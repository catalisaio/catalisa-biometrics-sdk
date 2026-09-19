import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { openCapture, parseCaptureMessage, type CaptureEvent } from '../src'

const CAPTURE_URL = 'https://biometrics.bb.stg.catalisa.app/biometrics/capture/eyJhbGciOi.token'
const ORIGIN = 'https://biometrics.bb.stg.catalisa.app'

function post(data: unknown, origin = ORIGIN, source: MessageEventSource | null = document.querySelector('iframe')!.contentWindow) {
  window.dispatchEvent(new MessageEvent('message', { data, origin, source }))
}
const msg = (event: string, extra: Record<string, unknown> = {}) => ({ source: 'catalisa-biometrics', event, ...extra })

beforeEach(() => {
  document.body.innerHTML = '<div id="slot"></div>'
})
afterEach(() => {
  vi.useRealTimers()
})

describe('parseCaptureMessage — real events from capture-page/page.ts', () => {
  it('step:<GESTURE> becomes step with gesture, index and duration', () => {
    expect(parseCaptureMessage(msg('step:SMILE', { index: 0, total: 3, gesture: 'SMILE', durationMs: 5200 }))).toMatchObject({
      type: 'step',
      gesture: 'SMILE',
      index: 0,
      total: 3,
      durationMs: 5200,
    })
  })
  it('error with reason/name, guide with loaded', () => {
    expect(parseCaptureMessage(msg('error', { reason: 'camera', name: 'NotAllowedError' }))).toMatchObject({ type: 'error', reason: 'camera', name: 'NotAllowedError' })
    expect(parseCaptureMessage(msg('guide', { loaded: false, reason: 'TypeError' }))).toMatchObject({ type: 'guide', loaded: false, reason: 'TypeError' })
  })
  it('ready, capturing, submitted, retry, done, expired', () => {
    for (const e of ['ready', 'capturing', 'submitted', 'retry', 'done', 'expired']) expect(parseCaptureMessage(msg(e))?.type).toBe(e)
  })
  it('a new event passes through as unknown; messages from another source are ignored', () => {
    expect(parseCaptureMessage(msg('something-new'))).toMatchObject({ type: 'unknown', event: 'something-new' })
    expect(parseCaptureMessage({ source: 'other', event: 'done' })).toBeNull()
    expect(parseCaptureMessage('done')).toBeNull()
  })
  it('understands every event name the server page emits (list extracted from page.ts into vectors.json)', () => {
    const vectors = JSON.parse(readFileSync(resolve(process.cwd(), '../../vectors/vectors.json'), 'utf8'))
    const names: string[] = vectors.captureEvents
    expect(names).toEqual(expect.arrayContaining(['capturing', 'done', 'error', 'ready', 'retry', 'submitted']))
    for (const n of names) {
      const parsed = parseCaptureMessage(msg(n.endsWith(':') ? `${n}BLINK` : n))
      expect(parsed?.type, n).not.toBe('unknown')
    }
  })
})

describe('openCapture — iframe', () => {
  it('mounts the iframe with allow="camera" in the container and delivers events from the right origin', () => {
    const events: CaptureEvent[] = []
    const h = openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#slot', onEvent: (e) => events.push(e) })
    const f = document.querySelector('#slot iframe') as HTMLIFrameElement
    expect(f).toBe(h.iframe)
    expect(f.getAttribute('allow')).toBe('camera')
    expect(f.src).toBe(CAPTURE_URL)
    expect(h.origin).toBe(ORIGIN)
    post(msg('ready'))
    post(msg('step:BLINK', { index: 1, total: 3, gesture: 'BLINK', durationMs: 4800 }))
    expect(events.map((e) => e.type)).toEqual(['ready', 'step'])
  })

  it('ignores another origin, another window and messages without source catalisa-biometrics', () => {
    const onEvent = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#slot', onEvent })
    post(msg('done'), 'https://evil.example')
    post(msg('done'), 'https://biometrics.bb.stg.catalisa.app.evil.example')
    post(msg('done'), ORIGIN, window) // same declared origin, but not our iframe
    post({ event: 'done' })
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('close() unmounts, stops listening and calls onClose("api") once', () => {
    const onEvent = vi.fn()
    const onClose = vi.fn()
    const h = openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#slot', onEvent, onClose })
    const src = h.iframe!.contentWindow
    h.close()
    h.close()
    expect(document.querySelector('iframe')).toBeNull()
    expect(h.closed).toBe(true)
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(onClose).toHaveBeenCalledWith('api')
    window.dispatchEvent(new MessageEvent('message', { data: msg('done'), origin: ORIGIN, source: src }))
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('does not auto-close in iframe mode by default', () => {
    vi.useFakeTimers()
    const onClose = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#slot', onClose })
    post(msg('done'))
    vi.advanceTimersByTime(10_000)
    expect(onClose).not.toHaveBeenCalled()
  })

  it('requires an existing container and https', () => {
    expect(() => openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#missing' })).toThrow(/container/)
    expect(() => openCapture({ captureUrl: 'http://biometrics.example/capture/x', mode: 'iframe', container: '#slot' })).toThrow(/https/)
    expect(() => openCapture({ captureUrl: 'javascript:alert(1)', mode: 'iframe', container: '#slot' })).toThrow()
    expect(() => openCapture({ captureUrl: 'http://localhost:3034/biometrics/capture/x', mode: 'iframe', container: '#slot' })).not.toThrow()
  })
})

describe('openCapture — modal', () => {
  it('opens an overlay with an accessible dialog; auto-closes 1.5 s after done', () => {
    vi.useFakeTimers()
    const onClose = vi.fn()
    const events: string[] = []
    openCapture({ captureUrl: CAPTURE_URL, onEvent: (e) => events.push(e.type), onClose })
    const dialog = document.querySelector('[role="dialog"]')!
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    expect(dialog.querySelector('iframe')!.getAttribute('allow')).toBe('camera')
    post(msg('submitted'))
    post(msg('done'))
    expect(events).toEqual(['submitted', 'done'])
    vi.advanceTimersByTime(1499)
    expect(onClose).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1)
    expect(onClose).toHaveBeenCalledWith('done')
    expect(document.querySelector('.cbio-overlay')).toBeNull()
  })

  it('the close button and Esc close with reason "user"', () => {
    const onClose = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, onClose })
    ;(document.querySelector('.cbio-close') as HTMLButtonElement).click()
    expect(onClose).toHaveBeenLastCalledWith('user')
    openCapture({ captureUrl: CAPTURE_URL, onClose })
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(onClose).toHaveBeenCalledTimes(2)
    expect(document.querySelector('.cbio-overlay')).toBeNull()
  })

  it('expired also closes; autoCloseMs:false keeps it open', () => {
    vi.useFakeTimers()
    const onClose = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, onClose, autoCloseMs: 0 })
    post(msg('expired'))
    vi.advanceTimersByTime(0)
    expect(onClose).toHaveBeenCalledWith('expired')
    const keep = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, onClose: keep, autoCloseMs: false })
    post(msg('done'))
    vi.advanceTimersByTime(60_000)
    expect(keep).not.toHaveBeenCalled()
  })
})

describe('openCapture — redirect', () => {
  it('navigates the tab to the captureUrl and mounts no iframe', () => {
    const assign = vi.fn()
    const original = window.location
    Object.defineProperty(window, 'location', { configurable: true, value: { ...original, assign } })
    try {
      const h = openCapture({ captureUrl: CAPTURE_URL, mode: 'redirect' })
      expect(assign).toHaveBeenCalledWith(CAPTURE_URL)
      expect(h.iframe).toBeNull()
      expect(document.querySelector('iframe')).toBeNull()
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original })
    }
  })
})
