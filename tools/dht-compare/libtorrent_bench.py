"""Isolated loopback API benchmark, with public discovery disabled."""
import os
import sys
import select
import socket
import time
import libtorrent as lt

count = int(sys.argv[1]) if len(sys.argv) > 1 else 8
trials = int(sys.argv[2]) if len(sys.argv) > 2 else 12
assert count in (8, 9, 32, 33) and 1 <= trials <= 16
readonly_writer = sys.argv[3:] == ["--readonly-writer"]
assert not sys.argv[3:] or readonly_writer
controlled = bool(os.environ.get("DHT_CONTROLLED"))
sessions = []
notifications = []

def alerts_until(index, predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        reader, _ = notifications[index]
        try:
            while reader.recv(4096):
                pass
        except BlockingIOError:
            pass
        for alert in sessions[index].pop_alerts():
            if predicate(alert):
                return alert
        select.select([reader], [], [], max(0, deadline - time.monotonic()))
    raise TimeoutError('libtorrent alert deadline')

try:
    for i in range(count + (2 if readonly_writer else 1)):
        session = lt.session({
            'listen_interfaces': '127.0.0.1:0',
            'outgoing_interfaces': '127.0.0.1',
            'enable_dht': True,
            'dht_bootstrap_nodes': '',
            'enable_lsd': False,
            'enable_upnp': False,
            'enable_natpmp': False,
            'dht_restrict_routing_ips': False,
            'dht_restrict_search_ips': False,
            'dht_enforce_node_id': False,
            'dht_block_ratelimit': 1000,
            'dht_read_only': i >= count,
            'alert_mask': (lt.alert.category_t.dht_notification
                           | lt.alert.category_t.status_notification
                           | lt.alert.category_t.error_notification
                           | lt.alert.category_t.stats_notification),
        })
        sessions.append(session)
        reader, writer = socket.socketpair()
        reader.setblocking(False)
        writer.setblocking(False)
        notifications.append((reader, writer))
        session.set_alert_fd(writer.fileno())
        alerts_until(i, lambda a: isinstance(a, lt.listen_succeeded_alert))
    addresses = [('127.0.0.1', s.listen_port()) for s in sessions]
    for i, session in enumerate(sessions):
        # Every implementation starts from local routing peers; no Internet routers.
        for peer in (0, (i + 1) % count):
            if peer != i:
                session.add_dht_node(addresses[peer])
    for i, session in enumerate(sessions):
        ready = False
        for _ in range(100):
            session.post_dht_stats()
            stats = alerts_until(i, lambda a: isinstance(a, lt.dht_stats_alert))
            if sum(bucket['num_nodes'] for bucket in stats.routing_table) > 0:
                ready = True
                break
            time.sleep(0.05)
        assert ready, 'private DHT routing table stayed empty'
    writer = count if readonly_writer else count - 1
    reader = writer + 1
    print('backend,version,nodes,trial,operation,success,elapsed_ms,replica_contacts', flush=True)
    for i in range(trials):
        time.sleep(1.1)
        value = i.to_bytes(4, 'big') + b'a' * 252
        start = time.perf_counter()
        target = sessions[writer].dht_put_immutable_item(value)
        put = alerts_until(writer, lambda a: isinstance(a, lt.dht_put_alert) and a.target == target)
        print(f'libtorrent,{lt.__version__},{count},{i},immutable_put,{str(put.num_success > 0).lower()},{(time.perf_counter()-start)*1000:.3f},{put.num_success}', flush=True)
        if controlled:
            assert put.num_success == 8, 'expected eight acknowledged stores'
            copies = 0
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.settimeout(5)
                for j, address in enumerate(addresses[:count]):
                    transaction = j.to_bytes(2, 'big')
                    request = {b'y': b'q', b't': transaction, b'q': b'get', b'ro': 1,
                               b'a': {b'id': b'v' * 20, b'target': bytes.fromhex(str(target))}}
                    probe.sendto(lt.bencode(request), address)
                    packet, source = probe.recvfrom(4096)
                    reply = lt.bdecode(packet)
                    assert source == address and reply[b't'] == transaction
                    assert reply[b'y'] == b'r', reply
                    found = reply[b'r'].get(b'v')
                    if found is not None:
                        assert found == value
                        copies += 1
            assert copies == 8, f'expected eight verified replicas, got {copies}'
            time.sleep(1.1)
        for operation in (('immutable_get', 'immutable_get_repeat') if controlled else ('immutable_get',)):
            start = time.perf_counter()
            sessions[reader].dht_get_immutable_item(target)
            got = alerts_until(reader, lambda a: isinstance(a, lt.dht_immutable_item_alert) and a.target == target)
            success = got.item == value
            print(f'libtorrent,{lt.__version__},{count},{i},{operation},{str(success).lower()},{(time.perf_counter()-start)*1000:.3f},', flush=True)
            assert success, 'read did not return the exact stored value'

finally:
    for session in sessions:
        session.set_alert_fd(-1)
        session.pause()
    sessions.clear()
    for reader, writer in notifications:
        reader.close()
        writer.close()
