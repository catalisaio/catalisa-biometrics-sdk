/**
 * @catalisa/biometrics-web — abre a página de captura hospedada do Catalisa Biometrics
 * (link, iframe ou modal) e entrega os eventos de ANDAMENTO que ela manda por postMessage.
 *
 * O resultado da verificação NUNCA chega ao front: a página não o revela, de propósito
 * (para não virar oráculo de fraude). O resultado vem no webhook
 * `biometrics.session.completed` ou em `GET /sessions/:id`, no SEU servidor.
 *
 * Eventos reais emitidos por `src/biometrics/capture-page/page.ts` (mensagem
 * `{ source: 'catalisa-biometrics', event, ...extra }`):
 *   ready · capturing · step:<GESTO> {index,total,gesture,durationMs} · submitted · retry ·
 *   done · expired · error {reason:'camera'|'engine', name?} · guide {loaded, reason?}
 * A página só manda eventos quando está num iframe e só para as origens listadas em
 * `allowedEmbedHosts` do fornecedor — sem isso, nem o iframe carrega (frame-ancestors).
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
  /** Evento que a página ainda não tinha quando este SDK saiu. Repassado sem interpretação. */
  | { type: 'unknown'; event: string; raw: RawMessage }

export type CaptureEventType = CaptureEvent['type']

export interface RawMessage {
  source: typeof MESSAGE_SOURCE
  event: string
  [k: string]: unknown
}

export type CloseReason = 'user' | 'api' | 'done' | 'expired'

export interface OpenCaptureOptions {
  /** `handoff.captureUrl` da sessão criada no SEU servidor. */
  captureUrl: string
  /** `modal` (padrão): sobreposição em tela cheia. `iframe`: dentro de `container`. `redirect`: navega a aba. */
  mode?: 'modal' | 'iframe' | 'redirect'
  /** Elemento (ou seletor) que recebe o iframe no modo `iframe`. */
  container?: HTMLElement | string
  /** Cada evento de andamento. Nenhum deles traz resultado. */
  onEvent?: (event: CaptureEvent) => void
  /** Chamado uma vez quando a captura é fechada (pelo usuário, por `close()`, ou ao terminar). */
  onClose?: (reason: CloseReason) => void
  /**
   * Fecha sozinho depois de `done`/`expired` (ms). Padrão: 1500 no modal, `false` no iframe.
   * `false` desliga.
   */
  autoCloseMs?: number | false
  /** Rótulo acessível do diálogo/iframe. */
  title?: string
  /** Texto do botão de fechar do modal. */
  closeLabel?: string
  /** Permite http:// (desenvolvimento local). Padrão: só https, exceto localhost. */
  allowInsecure?: boolean
}

export interface CaptureHandle {
  /** O iframe montado (null no modo redirect). */
  readonly iframe: HTMLIFrameElement | null
  /** Origem esperada nas mensagens (a da `captureUrl`). */
  readonly origin: string
  /** Fecha e desmonta. Idempotente. */
  close(): void
  /** `true` depois de fechado. */
  readonly closed: boolean
}

/** Converte a mensagem crua da página em evento tipado. Exportado para quem monta o próprio iframe. */
export function parseCaptureMessage(data: unknown): CaptureEvent | null {
  if (!data || typeof data !== 'object') return null
  const raw = data as RawMessage
  if (raw.source !== MESSAGE_SOURCE || typeof raw.event !== 'string') return null
  const ev = raw.event
  if (ev.startsWith('step:')) {
    return {
      type: 'step',
      gesture: typeof raw.gesture === 'string' ? raw.gesture : ev.slice(5),
      index: typeof raw.index === 'number' ? raw.index : 0,
      total: typeof raw.total === 'number' ? raw.total : 0,
      durationMs: typeof raw.durationMs === 'number' ? raw.durationMs : null,
      raw,
    }
  }
  switch (ev) {
    case 'ready':
    case 'capturing':
    case 'submitted':
    case 'retry':
    case 'done':
    case 'expired':
      return { type: ev, raw }
    case 'error':
      return { type: 'error', reason: typeof raw.reason === 'string' ? raw.reason : 'unknown', ...(typeof raw.name === 'string' ? { name: raw.name } : {}), raw }
    case 'guide':
      return { type: 'guide', loaded: raw.loaded === true, ...(typeof raw.reason === 'string' ? { reason: raw.reason } : {}), raw }
    default:
      return { type: 'unknown', event: ev, raw }
  }
}

function validUrl(captureUrl: string, allowInsecure: boolean): URL {
  let u: URL
  try {
    u = new URL(captureUrl)
  } catch {
    throw new Error('CatalisaBiometrics: captureUrl inválida')
  }
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1'
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (allowInsecure || local))) {
    throw new Error('CatalisaBiometrics: captureUrl precisa ser https')
  }
  return u
}

function resolveContainer(c: OpenCaptureOptions['container']): HTMLElement {
  const el = typeof c === 'string' ? document.querySelector<HTMLElement>(c) : c
  if (!el) throw new Error('CatalisaBiometrics: modo iframe precisa de um container existente')
  return el
}

function makeIframe(url: string, title: string): HTMLIFrameElement {
  const f = document.createElement('iframe')
  f.src = url
  f.title = title
  // A página pede a câmera; o iframe precisa delegar a permissão. Microfone não é usado.
  f.allow = 'camera'
  f.setAttribute('allow', 'camera')
  f.referrerPolicy = 'no-referrer'
  f.style.border = '0'
  f.style.width = '100%'
  f.style.height = '100%'
  return f
}

const STYLE_ID = 'catalisa-biometrics-style'
function ensureStyle(): void {
  if (document.getElementById(STYLE_ID)) return
  const s = document.createElement('style')
  s.id = STYLE_ID
  s.textContent =
    '.cbio-overlay{position:fixed;inset:0;z-index:2147483000;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center}' +
    '.cbio-dialog{position:relative;background:#fff;width:min(480px,100vw);height:min(760px,100dvh);border-radius:12px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,.35)}' +
    '@media (max-width:520px){.cbio-dialog{width:100vw;height:100dvh;border-radius:0}}' +
    '.cbio-close{position:absolute;top:8px;right:8px;z-index:1;border:0;border-radius:999px;width:36px;height:36px;font-size:20px;line-height:36px;cursor:pointer;background:rgba(0,0,0,.55);color:#fff}'
  document.head.appendChild(s)
}

/**
 * Abre a captura. Em `redirect`, navega a aba (a página pode voltar pelo `appearance.redirectUrl`
 * da sessão) e não há eventos. Em `iframe` e `modal`, ouve o postMessage validando a origem e a janela.
 */
export function openCapture(opts: OpenCaptureOptions): CaptureHandle {
  if (typeof window === 'undefined' || typeof document === 'undefined') throw new Error('CatalisaBiometrics: só roda no navegador')
  const url = validUrl(opts.captureUrl, opts.allowInsecure === true)
  const mode = opts.mode ?? 'modal'
  const origin = url.origin

  if (mode === 'redirect') {
    window.location.assign(url.toString())
    return { iframe: null, origin, close() {}, closed: false }
  }

  const title = opts.title ?? 'Verificação facial'
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
    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'cbio-close'
    btn.setAttribute('aria-label', opts.closeLabel ?? 'Fechar')
    btn.textContent = '×'
    btn.addEventListener('click', () => close('user'))
    dialog.appendChild(btn)
    dialog.appendChild(iframe)
    overlay.appendChild(dialog)
    document.body.appendChild(overlay)
    onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close('user')
    }
    document.addEventListener('keydown', onKey)
    root = overlay
    btn.focus()
  }

  const autoClose = opts.autoCloseMs === undefined ? (mode === 'modal' ? 1500 : false) : opts.autoCloseMs
  let closed = false
  let timer: ReturnType<typeof setTimeout> | null = null

  function onMessage(e: MessageEvent): void {
    if (e.origin !== origin) return // só a origem da captureUrl
    if (e.source !== iframe.contentWindow) return // só o NOSSO iframe
    const ev = parseCaptureMessage(e.data)
    if (!ev) return
    try {
      opts.onEvent?.(ev)
    } finally {
      if ((ev.type === 'done' || ev.type === 'expired') && autoClose !== false && !timer) {
        const reason: CloseReason = ev.type
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
