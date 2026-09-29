# R8/ProGuard rules for the SecureChat release build.
#
# The default Flutter rules already cover the engine and Dart entrypoints. The
# rules below protect the specific things shrinking could otherwise break in a
# cryptography app.

# --- Flutter embedding -------------------------------------------------------
# The engine reaches these reflectively; renaming them breaks the runtime.
-keep class io.flutter.app.** { *; }
-keep class io.flutter.plugin.** { *; }
-keep class io.flutter.embedding.** { *; }
-keep class io.flutter.util.** { *; }
-keep class io.flutter.view.** { *; }
-keep class io.flutter.** { *; }
-dontwarn io.flutter.embedding.**

# --- Our platform channel ----------------------------------------------------
# MainActivity is looked up by name and the MethodChannel handler is invoked
# reflectively, so both must survive shrinking with their signatures intact.
-keep class com.securechat.securechat.MainActivity { *; }
-keep class com.securechat.securechat.** { *; }

# --- Plugin channels ---------------------------------------------------------
# Several plugins (secure storage, BLE) register MethodChannels whose handler
# types are only referenced from native code.
-keep class com.baseflow.** { *; }
-keep class com.it_nomads.** { *; }
-dontwarn com.baseflow.**
-dontwarn com.it_nomads.**

# --- Security provider -------------------------------------------------------
# flutter_secure_storage loads the Android Keystore KeyStore via JCA, which
# resolves these by string name at runtime.
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-keep class android.security.keystore.** { *; }
-dontwarn javax.crypto.**
-dontwarn java.security.**

# --- Diagnostics -------------------------------------------------------------
# Line numbers make a production stack trace actionable; the source file name
# adds nothing once the mapping file is uploaded.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
