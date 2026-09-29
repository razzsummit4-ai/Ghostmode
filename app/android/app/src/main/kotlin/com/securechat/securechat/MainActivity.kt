package com.securechat.securechat

import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Hosts the Flutter UI and exposes the platform secure-window flag.
 *
 * Screenshot blocking is implemented with [WindowManager.LayoutParams.FLAG_SECURE]
 * rather than a post-hoc detection callback. With the flag set, Android refuses
 * to composite the window into a screenshot or into the recent-apps thumbnail,
 * so a copy of the conversation cannot be produced in the first place. There is
 * therefore no event to react to, and nothing to leak before we notice.
 */
class MainActivity : FlutterActivity() {

    private companion object {
        const val CHANNEL = "securechat/secure_window"
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "setSecure" -> {
                        val enabled = call.argument<Boolean>("enabled") ?: true
                        // Must run on the UI thread: window flags are not
                        // safe to mutate from the platform thread.
                        runOnUiThread {
                            if (enabled) {
                                window.setFlags(
                                    WindowManager.LayoutParams.FLAG_SECURE,
                                    WindowManager.LayoutParams.FLAG_SECURE,
                                )
                            } else {
                                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            }
                        }
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }
}

