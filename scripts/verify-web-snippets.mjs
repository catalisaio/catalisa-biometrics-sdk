#!/usr/bin/env node
// Runs the web-capture snippets in jsdom (a real DOM, scripts executed) and checks their behavior:
//  - link.html:      clicking fetches the session and navigates to the captureUrl;
//  - iframe.html:    mounts <iframe allow="camera">, ignores a spoofed origin, reacts to `done` from the iframe;
//  - modal-sdk.html: loads the built UMD bundle (instead of the CDN), opens the modal, receives `step`
//                    and closes on `done`, then navigates.
// The capture page itself (camera, MediaRecorder) is not exercised here; that is the server's page.
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { JSDOM, VirtualConsole } from 'jsdom'

const ROOT = resolve(new URL('..', import.meta.url).pathname)
const CAPTURE_URL = 'https://biometrics.bb.stg.catalisa.app/biometrics/capture/eyJhbGciOiJIUzI1NiJ9.e30.mock'
const CAPTURE_ORIGIN = new URL(CAPTURE_URL).origin
const UMD = readFileSync(join(ROOT, 'packages/web/dist/biometrics-web.umd.js'), 'utf8')
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms))

function load(file, { inlineUmd = false } = {}) {
  let html = readFileSync(join(ROOT, 'snippets/web-capture', file), 'utf8')
  if (inlineUmd) html = html.replace(/<script src="https:\/\/cdn\.jsdelivr\.net[^"]+"><\/script>/, `<script>${UMD}</script>`)
  const logs = []
  const navigations = []
  const vc = new VirtualConsole()
  vc.on('log', (...a) => logs.push(a.join(' ')))
  vc.on('jsdomError', (e) => {
    if (/navigation/i.test(e.message)) navigations.push(e.message)
    else logs.push('jsdomError: ' + e.message)
  })
  const fetchCalls = []
  const dom = new JSDOM(html, {
    url: 'https://shop.example/checkout',
    runScripts: 'dangerously',
    virtualConsole: vc,
    beforeParse(window) {
      window.fetch = async (url, init) => {
        fetchCalls.push({ url: String(url), method: init?.method })
        return { json: async () => ({ captureUrl: CAPTURE_URL }) }
      }
      window.alert = (m) => logs.push('alert: ' + m)
    },
  })
  return { dom, window: dom.window, logs, navigations, fetchCalls }
}

function post(window, iframe, event, extra = {}, origin = CAPTURE_ORIGIN, source = iframe.contentWindow) {
  window.dispatchEvent(new window.MessageEvent('message', { data: { source: 'catalisa-biometrics', event, ...extra }, origin, source }))
}

const results = []
function check(name, ok, note) {
  results.push({ file: name, ok, note })
  console.log(`${ok ? 'OK ' : 'ERR'} web-capture/${name.padEnd(15)} ${note}`)
}

// link.html
{
  const t = load('link.html')
  t.window.document.getElementById('verify').click()
  await tick()
  const ok = t.fetchCalls.length === 1 && t.fetchCalls[0].method === 'POST' && t.navigations.length === 1
  check('link.html', ok, `fetch ${t.fetchCalls.length}x POST, navigation attempted ${t.navigations.length}x`)
}

// iframe.html
{
  const t = load('iframe.html')
  await tick()
  const iframe = t.window.document.querySelector('#capture iframe')
  const mounted = iframe && iframe.getAttribute('allow') === 'camera' && iframe.src === CAPTURE_URL
  post(t.window, iframe, 'done', {}, 'https://evil.example')
  post(t.window, iframe, 'done', {}, CAPTURE_ORIGIN, t.window) // right origin, wrong window
  const ignoredSpoof = t.navigations.length === 0
  post(t.window, iframe, 'done')
  await tick()
  const ok = mounted && ignoredSpoof && t.navigations.length === 1
  check('iframe.html', ok, `iframe allow=camera ${Boolean(mounted)}, spoofed messages ignored ${ignoredSpoof}, done → navigation ${t.navigations.length}`)
}

// modal-sdk.html
{
  const t = load('modal-sdk.html', { inlineUmd: true })
  const hasGlobal = typeof t.window.CatalisaBiometrics?.openCapture === 'function'
  t.window.document.getElementById('verify').click()
  await tick()
  const dialog = t.window.document.querySelector('[role="dialog"]')
  const iframe = dialog?.querySelector('iframe')
  post(t.window, iframe, 'step:SMILE', { index: 0, total: 3, gesture: 'SMILE', durationMs: 5200 })
  post(t.window, iframe, 'error', { reason: 'camera', name: 'NotAllowedError' })
  post(t.window, iframe, 'done')
  await tick(1600) // default autoCloseMs in the modal = 1500
  const closed = !t.window.document.querySelector('.cbio-overlay')
  const ok =
    hasGlobal &&
    Boolean(iframe) &&
    iframe.getAttribute('allow') === 'camera' &&
    t.logs.some((l) => l.includes('gesture 1/3: SMILE')) &&
    t.logs.some((l) => l.startsWith('alert:')) &&
    closed &&
    t.navigations.length === 1
  check('modal-sdk.html', ok, `UMD global ${hasGlobal}, modal+iframe ${Boolean(iframe)}, step logged, camera alert, auto-closed ${closed}, navigation ${t.navigations.length}`)
  if (!ok) console.log(t.logs)
}

const failed = results.filter((r) => !r.ok).length
console.log(`\n${results.length - failed}/${results.length} web snippets executed in jsdom`)
process.exit(failed ? 1 : 0)
