// Private loopback experiment: one JS event loop per DHT node, eight replicas.
import DHT from 'hyperdht'
import sodium from 'sodium-universal'
import dgram from 'node:dgram'
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads'
import { performance } from 'node:perf_hooks'

async function freePort () {
  const socket = dgram.createSocket('udp4')
  await new Promise((resolve, reject) => { socket.once('error', reject); socket.bind(0, '127.0.0.1', resolve) })
  const { port } = socket.address()
  await new Promise(resolve => socket.close(resolve))
  return port
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
if (!isMainThread) {
  const port = await freePort()
  const node = workerData.root
    ? DHT.bootstrapper(port, '127.0.0.1', { host: '127.0.0.1' })
    : new DHT({ port, host: '127.0.0.1', bootstrap: workerData.bootstrap, ephemeral: workerData.reader, firewalled: false })
  await node.fullyBootstrapped()
  parentPort.postMessage({ ready: { id: node.id, host: '127.0.0.1', port } })
  parentPort.on('message', async ({ id, op, value, target, peers }) => {
    try {
      const options = peers ? { nodes: peers.map(p => ({ ...p, id: Buffer.from(p.id) })), onlyClosestNodes: true } : {}
      const start = performance.now()
      let result
      if (op === 'put') {
        const put = await node.immutablePut(Buffer.from(value), options)
        result = { copies: put.closestNodes.length }
      } else if (op === 'get') {
        const got = await node.immutableGet(Buffer.from(target), options)
        result = { value: got?.value ?? null }
      } else if (op === 'stop') {
        await node.destroy({ force: true })
      } else throw new Error(`unknown op: ${op}`)
      parentPort.postMessage({ id, result, elapsed: performance.now() - start })
    } catch (error) { parentPort.postMessage({ id, error: String(error) }) }
  })
} else {
  const count = Number(process.argv[2] ?? 9)
  const trials = Number(process.argv[3] ?? 12)
  if (![9, 33].includes(count) || !Number.isInteger(trials) || trials < 1 || trials > 16) throw new Error('expected nodes=9|33 trials=1..16')
  const nodes = []
  async function spawn (data) {
    const worker = new Worker(new URL(import.meta.url), { workerData: data })
    const pending = new Map()
    let serial = 0
    const node = { worker, pending }
    nodes.push(node)
    node.peer = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('bootstrap timeout')), 30000)
      worker.on('error', error => { clearTimeout(timer); reject(error); for (const p of pending.values()) p.reject(error) })
      worker.on('message', message => {
        if (message.ready) { clearTimeout(timer); resolve(message.ready); return }
        const p = pending.get(message.id)
        if (!p) return
        pending.delete(message.id)
        clearTimeout(p.timer)
        if (message.error) p.reject(new Error(message.error))
        else p.resolve(message)
      })
    })
    node.call = (op, args = {}) => new Promise((resolve, reject) => {
      const id = ++serial
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${op} timeout`)) }, 30000)
      pending.set(id, { resolve, reject, timer })
      worker.postMessage({ id, op, ...args })
    })
    return node
  }
  try {
    const root = await spawn({ root: true })
    const bootstrap = [`127.0.0.1:${root.peer.port}`]
    for (let i = 1; i <= count; i++) await spawn({ bootstrap, reader: i === count })
    const writer = nodes[count - 1]
    const reader = nodes[count]
    console.log('backend,version,nodes,trial,operation,success,elapsed_ms,replica_contacts')
    for (let i = 0; i < trials; i++) {
      await sleep(1100)
      const value = Buffer.alloc(256, 97)
      value.writeUInt32BE(i)
      const target = Buffer.alloc(32)
      sodium.crypto_generichash(target, value)
      const distance = peer => Buffer.from(peer.id).map((byte, j) => byte ^ target[j])
      const peers = nodes.slice(0, count - 1).map(n => n.peer).sort((a, b) => Buffer.compare(distance(a), distance(b))).slice(0, 8)
      const put = await writer.call('put', { value, peers })
      if (put.result.copies !== 8) throw new Error('expected eight put candidates')
      console.log(`hyperdht-dedicated,6.34.0,${count},${i},immutable_put,true,${put.elapsed.toFixed(3)},8`)
      let copies = 0
      for (const n of nodes.slice(0, count - 1)) {
        const got = await writer.call('get', { target, peers: [n.peer] })
        if (got.result.value !== null) {
          if (!value.equals(Buffer.from(got.result.value))) throw new Error('corrupt replica')
          copies++
        }
      }
      if (copies !== 8) throw new Error(`expected eight verified replicas, got ${copies}`)
      await sleep(1100)
      for (const operation of ['immutable_get', 'immutable_get_repeat']) {
        const got = await reader.call('get', { target })
        const success = got.result.value !== null && value.equals(Buffer.from(got.result.value))
        console.log(`hyperdht-dedicated,6.34.0,${count},${i},${operation},${success},${got.elapsed.toFixed(3)},`)
        if (!success) throw new Error('incorrect read')
      }
    }
  } finally {
    for (const n of nodes) {
      for (const p of n.pending.values()) clearTimeout(p.timer)
      await n.worker.terminate()
    }
  }
}
