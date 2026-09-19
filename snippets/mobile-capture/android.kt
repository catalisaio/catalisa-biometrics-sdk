// Android (Kotlin): WebView with camera access, or Custom Tabs (the browser handles the permission).
// AndroidManifest: <uses-permission android:name="android.permission.CAMERA"/>
// build.gradle: implementation("androidx.browser:browser:1.8.0")
import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.webkit.PermissionRequest
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.content.ContextCompat

const val REDIRECT_URL = "https://yourapp.example/biometrics/done" // the session's appearance.redirectUrl

class FaceCaptureActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private var pendingRequest: PermissionRequest? = null

    private val cameraPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        pendingRequest?.let { if (granted) it.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE)) else it.deny() }
        pendingRequest = null
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val captureUrl = intent.getStringExtra("captureUrl")!!
        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.mediaPlaybackRequiresUserGesture = false
            webChromeClient = object : WebChromeClient() {
                override fun onPermissionRequest(request: PermissionRequest) {
                    // Grant only the camera, and only to the capture page's origin.
                    if (request.origin.host != Uri.parse(captureUrl).host ||
                        !request.resources.contains(PermissionRequest.RESOURCE_VIDEO_CAPTURE)) return request.deny()
                    if (ContextCompat.checkSelfPermission(this@FaceCaptureActivity, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                        request.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE))
                    } else {
                        pendingRequest = request
                        cameraPermission.launch(Manifest.permission.CAMERA)
                    }
                }
            }
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    if (request.url.toString().startsWith(REDIRECT_URL)) {
                        finish() // finished; the result comes in your server's webhook
                        return true
                    }
                    return false
                }
            }
        }
        setContentView(webView)
        webView.loadUrl(captureUrl)
    }
}

// Alternative without a WebView: Custom Tabs. Chrome asks for the camera; come back via redirectUrl (App Link).
fun openInCustomTabs(activity: AppCompatActivity, captureUrl: String) {
    CustomTabsIntent.Builder().build().launchUrl(activity, Uri.parse(captureUrl))
}
