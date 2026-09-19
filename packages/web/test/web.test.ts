import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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

describe('parseCaptureMessage — eventos reais de capture-page/page.ts', () => {
  it('step:<GESTO> vira step com gesto, índice e duração', () => {
    expect(parseCaptureMessage(msg('step:SMILE', { index: 0, total: 3, gesture: 'SMILE', durationMs: 5200 }))).toMatchObject({
      type: 'step',
      gesture: 'SMILE',
      index: 0,
      total: 3,
      durationMs: 5200,
    })
  })
  it('error com reason/name, guide com loaded', () => {
    expect(parseCaptureMessage(msg('error', { reason: 'camera', name: 'NotAllowedError' }))).toMatchObject({ type: 'error', reason: 'camera', name: 'NotAllowedError' })
    expect(parseCaptureMessage(msg('guide', { loaded: false, reason: 'TypeError' }))).toMatchObject({ type: 'guide', loaded: false, reason: 'TypeError' })
  })
  it('ready, capturing, submitted, retry, done, expired', () => {
    for (const e of ['ready', 'capturing', 'submitted', 'retry', 'done', 'expired']) expect(parseCaptureMessage(msg(e))?.type).toBe(e)
  })
  it('evento novo passa como unknown; mensagem de outra fonte é ignorada', () => {
    expect(parseCaptureMessage(msg('algo-novo'))).toMatchObject({ type: 'unknown', event: 'algo-novo' })
    expect(parseCaptureMessage({ source: 'outro', event: 'done' })).toBeNull()
    expect(parseCaptureMessage('done')).toBeNull()
  })
})

describe('openCapture — iframe', () => {
  it('monta o iframe com allow="camera" no container e entrega eventos da origem certa', () => {
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

  it('ignora outra origem, outra janela e mensagem sem source catalisa-biometrics', () => {
    const onEvent = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#slot', onEvent })
    post(msg('done'), 'https://evil.example')
    post(msg('done'), 'https://biometrics.bb.stg.catalisa.app.evil.example')
    post(msg('done'), ORIGIN, window) // mesma origem declarada, mas não é o nosso iframe
    post({ event: 'done' })
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('close() desmonta, para de ouvir e chama onClose("api") uma vez', () => {
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

  it('no iframe não fecha sozinho por padrão', () => {
    vi.useFakeTimers()
    const onClose = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#slot', onClose })
    post(msg('done'))
    vi.advanceTimersByTime(10_000)
    expect(onClose).not.toHaveBeenCalled()
  })

  it('exige container existente e https', () => {
    expect(() => openCapture({ captureUrl: CAPTURE_URL, mode: 'iframe', container: '#nao-existe' })).toThrow(/container/)
    expect(() => openCapture({ captureUrl: 'http://biometrics.example/capture/x', mode: 'iframe', container: '#slot' })).toThrow(/https/)
    expect(() => openCapture({ captureUrl: 'javascript:alert(1)', mode: 'iframe', container: '#slot' })).toThrow()
    expect(() => openCapture({ captureUrl: 'http://localhost:3034/biometrics/capture/x', mode: 'iframe', container: '#slot' })).not.toThrow()
  })
})

describe('openCapture — modal', () => {
  it('abre sobreposição com diálogo acessível; fecha sozinho 1,5 s após done', () => {
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

  it('botão fechar e Esc fecham com reason "user"', () => {
    const onClose = vi.fn()
    openCapture({ captureUrl: CAPTURE_URL, onClose })
    ;(document.querySelector('.cbio-close') as HTMLButtonElement).click()
    expect(onClose).toHaveBeenLastCalledWith('user')
    openCapture({ captureUrl: CAPTURE_URL, onClose })
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(onClose).toHaveBeenCalledTimes(2)
    expect(document.querySelector('.cbio-overlay')).toBeNull()
  })

  it('expired também fecha; autoCloseMs:false mantém aberto', () => {
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
  it('navega a aba para a captureUrl e não monta iframe', () => {
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
