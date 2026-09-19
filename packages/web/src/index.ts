/**
 * @catalisa/biometrics-web — opens the Catalisa Biometrics hosted capture page (link, iframe or
 * modal) and delivers the PROGRESS events the page sends through postMessage.
 *
 * The verification result NEVER reaches the front end: the page does not reveal it, on purpose
 * (so it cannot be used as a fraud oracle). The result arrives in the
 * `biometrics.session.completed` webhook or via `GET /sessions/:id`, on YOUR server.
 *
 * Real events emitted by `src/biometrics/capture-page/page.ts` (message
 * `{ source: 'catalisa-biometrics', event, ...extra }`):
 *   ready · capturing · step:<GESTURE> {index,total,gesture,durationMs} · submitted · retry ·
 *   done · expired · error {reason:'camera'|'engine', name?} · guide {loaded, reason?}
 * The page only posts events when it is inside an iframe, and only to the origins listed in the
 * provider's `allowedEmbedHosts` — without that, the iframe does not even load (frame-ancestors).
 */

export const VERSION = '0.1.0'
export const MESSAGE_SOURCE = 'catalisa-biometrics'

export type CaptureEvent =
  | { type: 'ready'; raw: RawMessage }
  | { type: 'capturing'; raw: RawMessage }
  | { type: 'step'; gesture: string; index: number; total: number; durationMs: number | null; raw: RawMessage }
  | { type: 'submitted'; raw: RawMessage }
  | { type: 'retry'; raw: RawMessage }
  | { type: 'done'; raw: RawMessage }
  | { type: 'expired'; raw: RawMessage }
  | { type: 'error'; reason: string; name?: string; raw: RawMessage }
  | { type: 'guide'; loaded: boolean; reason?: string; raw: RawMessage }
  /** An event this SDK version does not know yet. Passed through uninterpreted. */
  | { type: 'unknown'; event: string; raw: RawMessage }

export type CaptureEventType = CaptureEvent['type']

export interface RawMessage {
  source: typeof MESSAGE_SOURCE
  event: string
  [k: string]: unknown
}

export type CloseReason = 'user' | 'api' | 'done' | 'expired'

export interface OpenCaptureOptions {
  /** `handoff.captureUrl` of the session created on YOUR server. */
  captureUrl: string
  /** `modal` (default): fullscreen overlay. `iframe`: inside `container`. `redirect`: navigates the tab. */
  mode?: 'modal' | 'iframe' | 'redirect'
  /** Element (or selector) that receives the iframe in `iframe` mode. */
  container?: HTMLElement | string
  /** Every progress event. None of them carries the result. */
  onEvent?: (event: CaptureEvent) => void
  /** Called once when the capture is closed (by the user, by `close()`, or on completion). */
  onClose?: (reason: CloseReason) => void
  /**
   * Auto-close after `done`/`expired` (ms). Default: 1500 in the modal, `false` in the iframe.
   * `false` disables it.
   */
  autoCloseMs?: number | false
  /** Accessible label of the dialog/iframe. */
  title?: string
  /** Accessible label of the modal's close button. */
  closeLabel?: string
  /** Allows http:// (local development). Default: https only, except localhost. */
  allowInsecure?: boolean
}

export interface CaptureHandle {
  /** The mounted iframe (null in redirect mode). */
  readonly iframe: HTMLIFrameElement | null
  /** Origin expected on messages (the captureUrl's origin). */
  readonly origin: string
  /** Closes and unmounts. Idempotent. */
  close(): void
  /** `true` once closed. */
  readonly closed: boolean
}

/** Turns the page's raw message into a typed event. Exported for those who mount their own iframe. */
export function parseCaptureMessage(data: unknown): CaptureEvent | null {
  if (!data || typeof data !== 'object') return null
  const raw = data as RawMessage
  if (raw.source !== MESSAGE_SOURCE || typeof raw.event !== 'string') return null
  const name = raw.event
  if (name.startsWith('step:')) {
    return {
      type: 'step',
      gesture: typeof raw.gesture === 'string' ? raw.gesture : name.slice(5),
      index: typeof raw.index === 'number' ? raw.index : 0,
      total: typeof raw.total === 'number' ? raw.total : 0,
      durationMs: typeof raw.durationMs === 'number' ? raw.durationMs : null,
      raw,
    }
  }
  switch (name) {
    case 'ready':
    case 'capturing':
    case 'submitted':
    case 'retry':
    case 'done':
    case 'expired':
      return { type: name, raw }
    case 'error':
      return { type: 'error', reason: typeof raw.reason === 'string' ? raw.reason : 'unknown', ...(typeof raw.name === 'string' ? { name: raw.name } : {}), raw }
    case 'guide':
      return { type: 'guide', loaded: raw.loaded === true, ...(typeof raw.reason === 'string' ? { reason: raw.reason } : {}), raw }
    default:
      return { type: 'unknown', event: name, raw }
  }
}

function validUrl(captureUrl: string, allowInsecure: boolean): URL {
  let url: URL
  try {
    url = new URL(captureUrl)
  } catch {
    throw new Error('CatalisaBiometrics: invalid captureUrl')
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (allowInsecure || local))) {
    throw new Error('CatalisaBiometrics: captureUrl must use https')
  }
  return url
}

function resolveContainer(container: OpenCaptureOptions['container']): HTMLElement {
  const el = typeof container === 'string' ? document.querySelector<HTMLElement>(container) : container
  if (!el) throw new Error('CatalisaBiometrics: iframe mode needs an existing container')
  return el
}

function makeIframe(url: string, title: string): HTMLIFrameElement {
  const iframe = document.createElement('iframe')
  iframe.src = url
  iframe.title = title
  // The page asks for the camera; the iframe must delegate the permission. The microphone is not used.
  iframe.allow = 'camera'
  iframe.setAttribute('allow', 'camera')
  iframe.referrerPolicy = 'no-referrer'
  iframe.style.border = '0'
  iframe.style.width = '100%'
  iframe.style.height = '100%'
  return iframe
}

const STYLE_ID = 'catalisa-biometrics-style'
function ensureStyle(): void {
  if (document.getElementById(STYLE_ID)) return
  const style = document.createElement('style')
  style.id = STYLE_ID
  style.textContent =
    '.cbio-overlay{position:fixed;inset:0;z-index:2147483000;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center}' +
    '.cbio-dialog{position:relative;background:#fff;width:min(480px,100vw);height:min(760px,100dvh);border-radius:12px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,.35)}' +
    '@media (max-width:520px){.cbio-dialog{width:100vw;height:100dvh;border-radius:0}}' +
    '.cbio-close{position:absolute;top:8px;right:8px;z-index:1;border:0;border-radius:999px;width:36px;height:36px;font-size:20px;line-height:36px;cursor:pointer;background:rgba(0,0,0,.55);color:#fff}'
  document.head.appendChild(style)
}

/**
 * Opens the capture. In `redirect` mode it navigates the tab (the page can come back through the
 * session's `appearance.redirectUrl`) and there are no events. In `iframe` and `modal` modes it
 * listens to postMessage, validating the origin and the source window.
 */
export function openCapture(opts: OpenCaptureOptions): CaptureHandle {
  if (typeof window === 'undefined' || typeof document === 'undefined') throw new Error('CatalisaBiometrics: browser only')
  const url = validUrl(opts.captureUrl, opts.allowInsecure === true)
  const mode = opts.mode ?? 'modal'
  const origin = url.origin

  if (mode === 'redirect') {
    window.location.assign(url.toString())
    return { iframe: null, origin, close() {}, closed: false }
  }

  const title = opts.title ?? 'Face verification'
  const iframe = makeIframe(url.toString(), title)
  let root: HTMLElement
  let previousFocus: Element | null = null
  let onKey: ((e: KeyboardEvent) => void) | null = null

  if (mode === 'iframe') {
    root = iframe
    resolveContainer(opts.container).appendChild(iframe)
  } else {
    ensureStyle()
    previousFocus = document.activeElement
    const overlay = document.createElement('div')
    overlay.className = 'cbio-overlay'
    const dialog = document.createElement('div')
    dialog.className = 'cbio-dialog'
    dialog.setAttribute('role', 'dialog')
    dialog.setAttribute('aria-modal', 'true')
    dialog.setAttribute('aria-label', title)
    const closeButton = document.createElement('button')
    closeButton.type = 'button'
    closeButton.className = 'cbio-close'
    closeButton.setAttribute('aria-label', opts.closeLabel ?? 'Close')
    closeButton.textContent = '×'
    closeButton.addEventListener('click', () => close('user'))
    dialog.appendChild(closeButton)
    dialog.appendChild(iframe)
    overlay.appendChild(dialog)
    document.body.appendChild(overlay)
    onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close('user')
    }
    document.addEventListener('keydown', onKey)
    root = overlay
    closeButton.focus()
  }

  const autoClose = opts.autoCloseMs === undefined ? (mode === 'modal' ? 1500 : false) : opts.autoCloseMs
  let closed = false
  let timer: ReturnType<typeof setTimeout> | null = null

  function onMessage(e: MessageEvent): void {
    if (e.origin !== origin) return // only the captureUrl's origin
    if (e.source !== iframe.contentWindow) return // only OUR iframe
    const event = parseCaptureMessage(e.data)
    if (!event) return
    try {
      opts.onEvent?.(event)
    } finally {
      if ((event.type === 'done' || event.type === 'expired') && autoClose !== false && !timer) {
        const reason: CloseReason = event.type
        timer = setTimeout(() => close(reason), autoClose)
      }
    }
  }
  window.addEventListener('message', onMessage)

  function close(reason: CloseReason): void {
    if (closed) return
    closed = true
    if (timer) clearTimeout(timer)
    window.removeEventListener('message', onMessage)
    if (onKey) document.removeEventListener('keydown', onKey)
    root.remove()
    if (previousFocus instanceof HTMLElement) previousFocus.focus()
    opts.onClose?.(reason)
  }

  return {
    iframe,
    origin,
    close: () => close('api'),
    get closed() {
      return closed
    },
  }
}

export default { openCapture, parseCaptureMessage, VERSION, MESSAGE_SOURCE }
