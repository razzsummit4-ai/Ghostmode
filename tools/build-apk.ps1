# Builds the SecureChat release APK.
#
# Runs detached (Gradle's first run downloads a large dependency tree, far
# longer than a single command may wait). Progress lands in the log file.

$ErrorActionPreference = 'Continue'
$env:JAVA_HOME = 'C:\devtool\jdk'
$env:ANDROID_SDK_ROOT = 'C:\devtool\android-sdk'
$env:ANDROID_HOME = 'C:\devtool\android-sdk'
$env:Path = "C:\devtool\flutter\bin;C:\devtool\jdk\bin;$env:Path"

Set-Location 'C:\Users\sumit\OneDrive\Desktop\E2E\app'

# The project lives inside OneDrive, which holds file locks on Gradle's
# intermediates and intermittently fails the native-lib merge with
# AccessDeniedException. Build in a scratch directory on the local disk
# instead, and copy only the finished APKs back.
$buildRoot = 'C:\devtool\apkbuild'
if (Test-Path $buildRoot) { Remove-Item -Recurse -Force $buildRoot }
New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null

Write-Output "=== staging sources to $buildRoot ==="
robocopy 'C:\Users\sumit\OneDrive\Desktop\E2E\app' $buildRoot `
    /MIR /XD build .dart_tool .idea /NFL /NDL /NJH /NJS /NP | Out-Null
# pub get needs a real path, so recreate the cache marker Flutter expects.
if (-not (Test-Path "$buildRoot\.dart_tool")) {
    New-Item -ItemType Directory -Force -Path "$buildRoot\.dart_tool" | Out-Null
}

# The app has a PATH dependency on ../third_party/flutter_nearby_connections
# (the vendored Gradle 8 fix for the unmaintained Nearby Connections package).
# That relative path resolves against the app's own location, so it has to sit
# next to the staged copy or `pub get` fails with "path not found".
$stagedThirdParty = Join-Path (Split-Path $buildRoot -Parent) 'third_party'
if (Test-Path $stagedThirdParty) { Remove-Item -Recurse -Force $stagedThirdParty }
robocopy 'C:\Users\sumit\OneDrive\Desktop\E2E\third_party' $stagedThirdParty `
    /MIR /XD build .dart_tool /NFL /NDL /NJH /NJS /NP | Out-Null

Set-Location $buildRoot

Write-Output "=== pub get ==="
flutter pub get 2>&1 | Out-String | Write-Output

Write-Output "=== build apk (release) ==="
flutter build apk --release 2>&1 | Out-String | Write-Output

Write-Output "=== exit=$LASTEXITCODE ==="
$apks = Get-ChildItem "$buildRoot\build\app\outputs\flutter-apk" -Filter *.apk -ErrorAction SilentlyContinue
$apks | ForEach-Object { "$($_.Name) $([math]::Round($_.Length / 1MB, 2)) MB" } | Out-String | Write-Output
