# @catalisa/biometrics-web

Opens the **Catalisa Biometrics** hosted capture page in the browser — as a modal, an embedded iframe or a full-page redirect — and delivers the page's progress events (sent over `postMessage`) as typed events.

- No dependencies, ~5 KB minified
- ESM, CommonJS and a UMD bundle for CDNs (global `CatalisaBiometrics`)

> **The result never reaches the front end.** The capture page does not reveal whether the person was approved — by design, so it cannot be used as an oracle to tune an attack. The decision arrives **on your server**, through the `biometrics.session.completed` webhook or `GET /sessions/:id` (see [`@catalisa/biometrics`](https://www.npmjs.com/package/@catalisa/biometrics)). The `done` event only means "the person finished"; never approve anything based on it.

## Install

```bash
npm install @catalisa/biometrics-web
```

or from a CDN:

```html
<script src="https://cdn.jsdelivr.net/npm/@catalisa/biometrics-web@0.1.0/dist/biometrics-web.umd.js"></script>
<!-- or https://unpkg.com/@catalisa/biometrics-web@0.1.0/dist/biometrics-web.umd.js -->
```

## Before embedding (iframe and modal)

1. **List your site's origin** in the provider's `allowedEmbedHosts` (`PATCH /providers/:id`). The capture page sends `Content-Security-Policy: frame-ancestors <allowedEmbedHosts>`; without your origin, the browser refuses to render it in an iframe, and the page only posts events to those origins.
2. The iframe needs `allow="camera"` — the SDK sets it.
3. Create the session **on your server** (the API key never goes to the browser) and hand only the `captureUrl` to the page.

The redirect mode needs none of this.

## Usage

```ts
import { openCapture } from '@catalisa/biometrics-web'

const { captureUrl } = await fetch('/api/biometrics/session', { method: 'POST' }).then((r) => r.json())

const capture = openCapture({
  captureUrl,
  mode: 'modal', // 'modal' | 'iframe' | 'redirect'
  onEvent(event) {
    if (event.type === 'step') console.log(`gesture ${event.index + 1}/${event.total}: ${event.gesture}`)
    if (event.type === 'error' && event.reason === 'camera') showCameraHelp()
  },
  onClose(reason) {
    if (reason === 'done') location.href = '/signup/under-review' // wait for the webhook on the server
  },
})

// capture.close() closes it programmatically
```

Embedded in your own layout:

```ts
openCapture({ captureUrl, mode: 'iframe', container: '#capture', onEvent })
```

With the CDN bundle: `CatalisaBiometrics.openCapture({ ... })`.

### Options

| Option | Default | |
|---|---|---|
| `captureUrl` | — | `handoff.captureUrl` from the session. Must be `https` (except `localhost`) |
| `mode` | `'modal'` | `'modal'`, `'iframe'` or `'redirect'` |
| `container` | — | Element or selector for `iframe` mode |
| `onEvent(event)` | — | Progress events (below) |
| `onClose(reason)` | — | `'user'` (close button or Esc), `'api'` (`close()`), `'done'`, `'expired'` |
| `autoCloseMs` | `1500` in the modal, `false` in the iframe | Auto-close after `done`/`expired`; `false` disables it |
| `title`, `closeLabel` | English defaults | Accessible labels |

### Events

These are exactly the events the hosted page emits (`src/biometrics/capture-page/page.ts`):

| `event.type` | Page message | When |
|---|---|---|
| `ready` | `ready` | Page loaded, session can be captured |
| `capturing` | `capturing` | Camera granted, recording started |
| `step` | `step:<GESTURE>` | Each challenge step, with `gesture`, `index`, `total`, `durationMs` |
| `submitted` | `submitted` | Video uploaded |
| `retry` | `retry` | New attempt; the page reloads itself |
| `done` | `done` | Session finished — read the result on your server |
| `expired` | `expired` | Session expired (or the link is no longer valid) |
| `error` | `error` | `reason: 'camera'` (with the browser's `name`, e.g. `NotAllowedError`) or `reason: 'engine'` |
| `guide` | `guide` | Live guide loaded (`loaded: true`) or unavailable (`loaded: false`) |
| `unknown` | anything else | Future events, passed through as `event.event` |

### Security

Messages are accepted only when **all** of these hold:

- `event.origin` equals the `captureUrl`'s origin;
- `event.source` is the SDK's own iframe window;
- `event.data.source === 'catalisa-biometrics'`.

If you build your own iframe, apply the same checks and use `parseCaptureMessage(event.data)` to get the typed event.

## Mobile apps

Inside a WebView the page is not in an iframe, so it posts no events. Set `appearance.redirectUrl` when creating the session and intercept that navigation to close the WebView — see the React Native, Flutter, Android and iOS snippets in the repository's `snippets/mobile-capture`.

## License

MIT
