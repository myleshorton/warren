// Isolated loopback API benchmark. Never uses public bootstrap nodes.
import DHT from 'hyperdht'
import dgram from 'node:dgram'
import { performance } from 'node:perf_hooks'

async function freePort () {
  const socket = dgram.createSocket('udp4')
  await new Promise((resolve, reject) => { socket.once('error', reject); socket.bind(0, '127.0.0.1', resolve) })
  const { port } = socket.address()
  await new Promise(resolve => socket.close(resolve))
  return port
}
async function bounded (promise, ms = 30000) {
  let timer
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms) })]) }
  finally { clearTimeout(timer) }
}
const count = Number(process.argv[2] ?? 8)
const trials = Number(process.argv[3] ?? 12)
if (![8, 32].includes(count) || trials < 1 || trials > 16) throw new Error('expected nodes=8|32 trials=1..16')
const nodes = []
try {
  const port = await freePort()
  const root = DHT.bootstrapper(port, '127.0.0.1', { host: '127.0.0.1' })
  nodes.push(root)
  await bounded(root.fullyBootstrapped())
  const bootstrap = [`127.0.0.1:${port}`]
  for (let i = 1; i < count + 1; i++) {
    const node = new DHT({ port: await freePort(), host: '127.0.0.1', bootstrap, ephemeral: i >= count, firewalled: false })
    nodes.push(node)
  }
  await bounded(Promise.all(nodes.map(node => node.fullyBootstrapped())))
  const writer = nodes[count - 1]
  const reader = nodes[count]
  console.log('backend,version,nodes,trial,operation,success,elapsed_ms,replica_contacts')
  for (let i = 0; i < trials; i++) {
    await new Promise(resolve => setTimeout(resolve, 1100))
    const value = Buffer.alloc(256, 97)
    value.writeUInt32BE(i)
    let start = performance.now()
    const put = await bounded(writer.immutablePut(value))
    const elapsed = performance.now() - start
    console.log(`hyperdht,6.34.0,${count},${i},immutable_put,${put.closestNodes.length > 0},${elapsed.toFixed(3)},${put.closestNodes.length}`)
    start = performance.now()
    const found = await bounded(reader.immutableGet(put.hash))
    const success = found !== null && value.equals(found.value)
    console.log(`hyperdht,6.34.0,${count},${i},immutable_get,${success},${(performance.now() - start).toFixed(3)},`)
    if (!success) throw new Error('read did not return the exact stored value')
  }
} finally {
  await Promise.allSettled(nodes.map(node => node.destroy({ force: true })))
}
