#!/usr/bin/env node
// Runs examples/node-server against the mock and a delivery signed by the server's own code.
import { spawn, spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'

const ROOT = resolve(new URL('..', import.meta.url).pathname)
const OUT = join(ROOT, '.verify')
mkdirSync(join(OUT, 'bb'), { recursive: true })
const file = join(OUT, `example-delivery-${Date.now()}.json`)
const gen = spawnSync('bash', [join(ROOT, 'scripts/bb-vector.sh'), 'fresh', file], { env: { ...process.env, BB_EXTRACT_DIR: join(OUT, 'bb') }, encoding: 'utf8' })
if (gen.status !== 0) throw new Error(gen.stderr)
const d = JSON.parse(readFileSync(file, 'utf8'))

const mock = spawn('node', [join(ROOT, 'scripts/mock-biometrics.mjs'), '4011'])
const app = spawn('node', [join(ROOT, 'examples/node-server/server.mjs')], {
  env: { ...process.env, PORT: '3199', CATALISA_API_KEY: 'pk_test.x', CATALISA_BIOMETRICS_URL: 'http://127.0.0.1:4011/v1', CATALISA_WEBHOOK_KEYS: JSON.stringify(d.keys) },
})
let appOut = ''
app.stdout.on('data', (x) => (appOut += x))
app.stderr.on('data', (x) => (appOut += x))
const base = 'http://127.0.0.1:3199'
const checks = []
try {
  for (let i = 0; i < 50; i++) {
    try {
      await fetch(base + '/')
      break
    } catch {
      await sleep(100)
    }
  }
  const page = await fetch(base + '/').then((r) => r.text())
  checks.push(['GET / serves the page', page.includes('openCapture')])
  const umd = await fetch(base + '/biometrics-web.umd.js').then((r) => r.text())
  checks.push(['serves the UMD bundle', umd.includes('CatalisaBiometrics')])
  const created = await fetch(base + '/api/biometrics/session', { method: 'POST' })
  const body = await created.json()
  checks.push(['POST /api/biometrics/session → 201 with only sessionId + captureUrl', created.status === 201 && Object.keys(body).sort().join() === 'captureUrl,sessionId'])
  const post = (h, b) => fetch(base + '/webhooks/biometrics', { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: b }).then((r) => r.status)
  checks.push(['webhook tampered → 400', (await post(d.headers, d.tamperedBody)) === 400])
  checks.push(['webhook stale → 400', (await post(d.stale.headers, d.stale.body)) === 400])
  checks.push(['webhook valid → 200', (await post(d.headers, d.body)) === 200])
  checks.push(['webhook replay (same event id) → 200, idempotent', (await post(d.headers, d.body)) === 200])
  const sessionId = JSON.parse(d.body).data.sessionId
  const result = await fetch(`${base}/api/biometrics/result?sessionId=${sessionId}`).then((r) => r.json())
  checks.push(['result endpoint exposes only "finished"', JSON.stringify(result) === '{"finished":true}'])
} finally {
  app.kill()
  mock.kill()
}
for (const [name, ok] of checks) console.log(`${ok ? 'OK ' : 'ERR'} examples/node-server — ${name}`)
const failed = checks.filter(([, ok]) => !ok).length
if (failed) console.log(appOut)
console.log(`\n${checks.length - failed}/${checks.length} example checks passed`)
process.exit(failed ? 1 : 0)
