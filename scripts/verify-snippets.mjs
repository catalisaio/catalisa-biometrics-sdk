#!/usr/bin/env node
// Runs EVERY server snippet and checks the outcome:
//  - create-session / get-session / handle-errors against the contract-faithful mock (scripts/mock-biometrics.mjs);
//  - verify-webhook: starts each language's server and posts three deliveries signed NOW by the
//    server's own code (scripts/bb-vector.sh fresh): valid → 200; tampered body → 400; 10 minutes old → 400.
// Languages missing on the host run in their official container image (docker run --rm), removed afterwards.
// Output: a table on stdout and .verify/results.json.
//
//   node scripts/verify-snippets.mjs             (everything)
//   ONLY=go,php node scripts/verify-snippets.mjs
import { spawn, spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'

const ROOT = resolve(new URL('..', import.meta.url).pathname)
const OUT = join(ROOT, '.verify')
mkdirSync(OUT, { recursive: true })
const MOCK_PORT = 4010
const BASE = `http://127.0.0.1:${MOCK_PORT}/v1`
const SUB_QUOTA = '00000000-0000-4000-8000-000000000402'
const SUB_SUSPENDED = '00000000-0000-4000-8000-000000000403'
const APPROVED_ID = '00000000-0000-4000-8000-00000000a000'
const ONLY = process.env.ONLY ? new Set(process.env.ONLY.split(',')) : null
const has = (bin) => spawnSync('sh', ['-c', `command -v ${bin}`]).status === 0

const IMAGES = {
  php: 'php:8.3-cli',
  go: 'golang:1.23-alpine',
  ruby: 'ruby:3.3-slim',
  csharp: 'mcr.microsoft.com/dotnet/sdk:10.0',
  java: 'eclipse-temurin:17-jdk',
}

// How to run each language. `file` is relative to the repo root.
function command(lang, file, env, { server = false, port } = {}) {
  const abs = join(ROOT, file)
  if (lang === 'curl') return { cmd: 'bash', args: [abs], env, runtime: 'host bash + curl' }
  if (lang === 'node') return { cmd: 'node', args: [abs], env, runtime: `host node ${process.version}` }
  if (lang === 'python') {
    return { cmd: 'python3', args: [abs], env: { ...env, PYTHONPATH: join(ROOT, 'packages/python/src'), PYTHONDONTWRITEBYTECODE: '1' }, runtime: 'host python3' }
  }
  if (lang === 'java' && has('java')) return { cmd: 'java', args: [abs], env, runtime: 'host java' }
  const image = IMAGES[lang]
  if (!image) throw new Error(`no runtime for ${lang}`)
  const inner = {
    php: server ? ['php', '-S', `0.0.0.0:${port}`, `/r/${file}`] : ['php', `/r/${file}`],
    go: ['go', 'run', `/r/${file}`],
    ruby: ['ruby', `/r/${file}`],
    csharp: ['dotnet', 'run', `/r/${file}`],
    java: ['java', `/r/${file}`],
  }[lang]
  const name = `cbio-verify-${lang}-${process.pid}-${Math.random().toString(36).slice(2, 7)}`
  const envArgs = Object.entries(env).filter(([k]) => /^(CATALISA_|SESSION_ID|PORT)/.test(k)).flatMap(([k, v]) => ['-e', `${k}=${v}`])
  const volumes = ['-v', `${ROOT}:/r:ro`]
  if (lang === 'go') volumes.push('-v', 'cbio-go-cache:/root/.cache/go-build')
  if (lang === 'csharp') {
    // No lingering build servers: they keep `dotnet run` (PID 1) alive after the program exits.
    for (const kv of ['DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_NOLOGO=1', 'MSBUILDDISABLENODEREUSE=1', 'DOTNET_CLI_USE_MSBUILD_SERVER=0', 'UseSharedCompilation=false']) envArgs.push('-e', kv)
  }
  return { cmd: 'docker', args: ['run', '--rm', '--init', '--name', name, '--network', 'host', ...volumes, ...envArgs, image, ...inner], env: {}, container: name, runtime: `docker ${image}` }
}

function run(spec, timeoutMs = 240_000) {
  return new Promise((done) => {
    const p = spawn(spec.cmd, spec.args, { env: { ...process.env, ...spec.env }, cwd: ROOT })
    let out = ''
    p.stdout.on('data', (d) => (out += d))
    p.stderr.on('data', (d) => (out += d))
    const t = setTimeout(() => {
      p.kill('SIGKILL')
      if (spec.container) spawnSync('docker', ['rm', '-f', spec.container])
    }, timeoutMs)
    p.on('close', (code) => {
      clearTimeout(t)
      done({ code, out })
    })
  })
}

async function waitPort(port, ms = 180_000) {
  const end = Date.now() + ms
  while (Date.now() < end) {
    try {
      await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1000) })
      return true
    } catch {
      await sleep(300)
    }
  }
  return false
}

function freshDelivery() {
  const f = join(OUT, `delivery-${Date.now()}.json`)
  const r = spawnSync('bash', [join(ROOT, 'scripts/bb-vector.sh'), 'fresh', f], { env: { ...process.env, BB_EXTRACT_DIR: join(OUT, 'bb') }, encoding: 'utf8' })
  if (r.status !== 0) throw new Error('bb-vector failed: ' + r.stderr)
  return JSON.parse(readFileSync(f, 'utf8'))
}

const results = []
const record = (topic, lang, ok, note, runtime) => {
  const status = ok ? 'executed' : 'FAILED'
  results.push({ topic, lang, status, note, runtime })
  console.log(`${ok ? 'OK ' : 'ERR'} ${topic.padEnd(16)} ${lang.padEnd(7)} ${status} — ${note}${runtime ? ` [${runtime}]` : ''}`)
}

const LANGS = ['curl', 'node', 'python', 'php', 'java', 'go', 'csharp', 'ruby']
const FILE = { curl: 'curl.sh', node: 'node.mjs', python: 'python.py', php: 'php.php', java: 'java.java', go: 'go.go', csharp: 'csharp.cs', ruby: 'ruby.rb' }

// ---------- prerequisites ----------
if (!existsSync(join(ROOT, 'packages/node/dist/index.js'))) {
  spawnSync('npm', ['run', 'build', '-w', '@catalisa/biometrics'], { cwd: ROOT, stdio: 'inherit' })
}
mkdirSync(join(OUT, 'bb'), { recursive: true })

const mockLog = join(OUT, 'mock.jsonl')
writeFileSync(mockLog, '')
const mock = spawn('node', [join(ROOT, 'scripts/mock-biometrics.mjs'), String(MOCK_PORT)], { env: { ...process.env, MOCK_LOG: mockLog } })
if (!(await waitPort(MOCK_PORT, 10_000))) throw new Error('mock did not start')

const API_KEY = 'pk_test.test_secret'
const baseEnv = { CATALISA_API_KEY: API_KEY, CATALISA_BIOMETRICS_URL: BASE }

try {
  for (const lang of LANGS) {
    if (ONLY && !ONLY.has(lang)) continue
    const file = (topic) => `snippets/${topic}/${FILE[lang]}`

    // create-session: prints sessionId and captureUrl; the mock saw X-API-Key
    {
      const before = readFileSync(mockLog, 'utf8').split('\n').filter(Boolean).length
      const spec = command(lang, file('create-session'), baseEnv)
      const r = await run(spec)
      const logs = readFileSync(mockLog, 'utf8').split('\n').filter(Boolean).slice(before).map((l) => JSON.parse(l))
      const sawKey = logs.some((l) => l.method === 'POST' && l.path === '/v1/sessions' && l.headers['x-api-key'] === API_KEY)
      const printed = lang === 'curl' ? /"captureUrl":"https:\/\/[^"]+\/capture\//.test(r.out) : /captureUrl: https:\/\/\S+\/capture\//.test(r.out)
      const ok = r.code === 0 && printed && sawKey
      record('create-session', lang, ok, ok ? '201 + captureUrl, X-API-Key sent' : r.out.slice(-600), spec.runtime)
    }
    // get-session: the mock's APPROVED session
    {
      const spec = command(lang, file('get-session'), { ...baseEnv, SESSION_ID: APPROVED_ID })
      const r = await run(spec)
      const ok = r.code === 0 && /APPROVED/.test(r.out)
      record('get-session', lang, ok, ok ? 'read status/decision APPROVED' : r.out.slice(-600), spec.runtime)
    }
    // handle-errors: 402 and 403
    {
      const spec = command(lang, file('handle-errors'), { ...baseEnv, CATALISA_SUBACCOUNT_ID: SUB_QUOTA })
      const a = await run(spec)
      const b = await run(command(lang, file('handle-errors'), { ...baseEnv, CATALISA_SUBACCOUNT_ID: SUB_SUSPENDED }))
      const ok = a.code === 0 && /blocked: QUOTA_EXCEEDED/.test(a.out) && b.code === 0 && /blocked: SUBACCOUNT_SUSPENDED/.test(b.out)
      record('handle-errors', lang, ok, ok ? '402 QUOTA_EXCEEDED and 403 SUBACCOUNT_SUSPENDED handled' : (a.out + '\n' + b.out).slice(-800), spec.runtime)
    }
    // verify-webhook
    {
      const d = freshDelivery()
      if (lang === 'curl') {
        // shell/openssl variant: body and key files
        const bodyFile = join(OUT, 'body.json')
        const pemFile = join(OUT, 'key.pem')
        writeFileSync(pemFile, Object.values(d.keys)[0])
        const check = async (headers, body) => {
          writeFileSync(bodyFile, body)
          return run({ cmd: 'bash', args: [join(ROOT, file('verify-webhook')), bodyFile, headers['x-webhook-id'], headers['x-webhook-timestamp'], headers['x-webhook-signature'], pemFile], env: {} })
        }
        const good = await check(d.headers, d.body)
        const bad = await check(d.headers, d.tamperedBody)
        const old = await check(d.stale.headers, d.stale.body)
        const ok = good.code === 0 && /Verified OK/.test(good.out) && bad.code !== 0 && old.code !== 0
        record('verify-webhook', 'curl', ok, ok ? 'openssl: valid → Verified OK; tampered and stale rejected' : good.out + bad.out + old.out, 'host bash + openssl')
        continue
      }
      const port = 3100 + LANGS.indexOf(lang)
      const spec = command(lang, file('verify-webhook'), { ...baseEnv, CATALISA_WEBHOOK_KEYS: JSON.stringify(d.keys), PORT: String(port) }, { server: true, port })
      const p = spawn(spec.cmd, spec.args, { env: { ...process.env, ...spec.env }, cwd: ROOT })
      let out = ''
      p.stdout.on('data', (x) => (out += x))
      p.stderr.on('data', (x) => (out += x))
      try {
        if (!(await waitPort(port))) {
          record('verify-webhook', lang, false, 'server did not start: ' + out.slice(-600), spec.runtime)
          continue
        }
        // the key pair is born with the delivery; it must still be within 300 s when the server is up
        if (Date.now() - Date.parse(d.headers['x-webhook-timestamp']) > 240_000) {
          record('verify-webhook', lang, false, 'delivery expired before the server came up (slow build)', spec.runtime)
          continue
        }
        const post = (headers, body) =>
          fetch(`http://127.0.0.1:${port}/webhooks/biometrics`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'user-agent': 'CatalisaWebhooks/1.0', ...headers },
            body,
          }).then((r) => r.status)
        const valid = await post(d.headers, d.body)
        const tampered = await post(d.headers, d.tamperedBody)
        const stale = await post(d.stale.headers, d.stale.body)
        const ok = valid === 200 && tampered === 400 && stale === 400
        record('verify-webhook', lang, ok, `valid ${valid}, tampered ${tampered}, 10 min old ${stale}` + (ok ? '' : ' | ' + out.slice(-600)), spec.runtime)
      } finally {
        p.kill('SIGTERM')
        if (spec.container) spawnSync('docker', ['rm', '-f', spec.container], { stdio: 'ignore' })
      }
    }
  }
} finally {
  mock.kill()
}

writeFileSync(join(OUT, 'results.json'), JSON.stringify(results, null, 2))
const failed = results.filter((r) => r.status === 'FAILED')
console.log(`\n${results.length - failed.length}/${results.length} server snippets executed successfully`)
process.exit(failed.length ? 1 : 0)
