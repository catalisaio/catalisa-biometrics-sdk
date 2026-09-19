// Capture in a modal with the web SDK from npm: npm install @catalisa/biometrics-web
// Prerequisite: this site's origin in the provider's allowedEmbedHosts (PATCH /providers/:id).
import { openCapture } from '@catalisa/biometrics-web'

export async function verifyIdentity() {
  // YOUR endpoint, which calls POST /sessions with the API key (the key never reaches the browser).
  const { captureUrl } = await fetch('/api/biometrics/session', { method: 'POST' }).then((r) => r.json())

  return openCapture({
    captureUrl,
    mode: 'modal', // or 'iframe' with container: '#capture', or 'redirect'
    onEvent(event) {
      if (event.type === 'step') console.log(`gesture ${event.index + 1}/${event.total}: ${event.gesture}`)
      if (event.type === 'error' && event.reason === 'camera') alert('Please allow camera access to continue.')
    },
    onClose(reason) {
      // 'done' = the person finished. The result comes in the webhook, not here.
      if (reason === 'done') window.location.href = '/signup/under-review'
    },
  })
}
