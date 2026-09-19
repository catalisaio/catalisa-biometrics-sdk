// React Native: capture in a WebView. npm i react-native-webview
// iOS: NSCameraUsageDescription in Info.plist. Android: <uses-permission android:name="android.permission.CAMERA"/>.
// Inside a WebView the page is not in an iframe, so there is no postMessage: the end of the flow is
// the navigation to appearance.redirectUrl, set when YOUR server creates the session.
import React, { useEffect, useState } from 'react'
import { PermissionsAndroid, Platform } from 'react-native'
import { WebView } from 'react-native-webview'

const REDIRECT_URL = 'https://yourapp.example/biometrics/done' // same value as appearance.redirectUrl

export function FaceCapture({ captureUrl, onFinish }: { captureUrl: string; onFinish: () => void }) {
  const [ready, setReady] = useState(Platform.OS !== 'android')

  useEffect(() => {
    if (Platform.OS === 'android') {
      PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.CAMERA).then((r) => setReady(r === PermissionsAndroid.RESULTS.GRANTED))
    }
  }, [])

  if (!ready) return null
  return (
    <WebView
      source={{ uri: captureUrl }}
      originWhitelist={['https://*']}
      javaScriptEnabled
      allowsInlineMediaPlayback // iOS: camera video inside the page, not fullscreen
      mediaPlaybackRequiresUserAction={false}
      mediaCapturePermissionGrantType="grant" // iOS 15+: grants the camera to the page without a second prompt
      onShouldStartLoadWithRequest={(request) => {
        if (request.url.startsWith(REDIRECT_URL)) {
          onFinish() // finished; the result comes in your server's webhook
          return false
        }
        return true
      }}
    />
  )
}
