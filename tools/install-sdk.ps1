# Installs the Android SDK pieces the SecureChat APK build needs.
# Run detached; writes progress to C:\devtool\logs\sdk-install.log
$ErrorActionPreference = 'Continue'
$env:JAVA_HOME = 'C:\devtool\jdk'
$env:ANDROID_SDK_ROOT = 'C:\devtool\android-sdk'
$env:ANDROID_HOME = 'C:\devtool\android-sdk'
$env:Path = "C:\devtool\jdk\bin;$env:Path"

$sdkmanager = 'C:\devtool\android-sdk\cmdline-tools\latest\bin\sdkmanager.bat'
New-Item -ItemType Directory -Force -Path 'C:\devtool\logs' | Out-Null

Write-Output "=== accepting licenses ==="
1..30 | ForEach-Object { 'y' } | & $sdkmanager --sdk_root='C:\devtool\android-sdk' --licenses 2>&1 | Out-String | Write-Output

Write-Output "=== installing packages ==="
# android-37.0 is required by permission_handler_android's compileSdk.
& $sdkmanager --sdk_root='C:\devtool\android-sdk' `
    'platform-tools' `
    'platforms;android-36' `
    'platforms;android-37.0' `
    'build-tools;36.0.0' 2>&1 | Out-String | Write-Output

Write-Output "=== done, exit=$LASTEXITCODE ==="
Get-ChildItem 'C:\devtool\android-sdk\platforms' -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name | Out-String | Write-Output
