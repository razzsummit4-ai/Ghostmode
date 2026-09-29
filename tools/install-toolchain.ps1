# Downloads + installs the toolchain needed to build the APK:
#   - Flutter SDK 3.47.5 (stable)
#   - Android SDK command-line tools + platform/build-tools/NDK
#   - Temurin JDK 17
#   - MongoDB (for backend integration testing)
# Run:  pwsh -File tools\install-toolchain.ps1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\devtool'
$dl = Join-Path $root 'downloads'
New-Item -ItemType Directory -Force -Path $dl | Out-Null

function Get-File($url, $dest) {
    if (Test-Path $dest) {
        $len = (Get-Item $dest).Length
        if ($len -gt 1MB) { Write-Host "[skip] already have $(Split-Path $dest -Leaf) ($([math]::Round($len/1MB)) MB)"; return $dest }
    }
    Write-Host "[get ] $url"
    $tmp = "$dest.part"
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
    curl.exe -L --fail --retry 5 --retry-delay 5 --connect-timeout 30 -o $tmp $url
    if ($LASTEXITCODE -ne 0) { throw "download failed: $url" }
    Move-Item -Force $tmp $dest
    Write-Host "[ok  ] $(Split-Path $dest -Leaf) ($([math]::Round((Get-Item $dest).Length/1MB)) MB)"
    return $dest
}

# ---------------- Flutter ----------------
$flutterZip = Join-Path $dl 'flutter_windows.zip'
Get-File 'https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_3.47.5-stable.zip' $flutterZip | Out-Null
if (-not (Test-Path (Join-Path $root 'flutter\bin\flutter.bat'))) {
    Write-Host '[unzip] Flutter SDK'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Expand-Archive -Force -Path $flutterZip -DestinationPath $root
}
Write-Host '[ok  ] flutter'

# ---------------- JDK 17 ----------------
$jdkZip = Join-Path $dl 'jdk17.zip'
Get-File 'https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse' $jdkZip | Out-Null
$jdkHome = Join-Path $root 'jdk'
if (-not (Test-Path $jdkHome)) {
    Write-Host '[unzip] JDK 17'
    $tmp = Join-Path $dl 'jdk_x'
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Expand-Archive -Force -Path $jdkZip -DestinationPath $tmp
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    Move-Item $inner.FullName $jdkHome
    Remove-Item -Recurse -Force $tmp
}
Write-Host '[ok  ] jdk'

# ---------------- Android SDK ----------------
$cmdZip = Join-Path $dl 'cmdline-tools.zip'
Get-File 'https://dl.google.com/android/repository/commandlinetools-win-13114758_latest.zip' $cmdZip | Out-Null
$sdk = Join-Path $root 'android-sdk'
if (-not (Test-Path (Join-Path $sdk 'cmdline-tools\latest\bin\sdkmanager.bat'))) {
    Write-Host '[unzip] Android cmdline-tools'
    $tmp = Join-Path $dl 'cmdline_x'
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Expand-Archive -Force -Path $cmdZip -DestinationPath $tmp
    New-Item -ItemType Directory -Force -Path (Join-Path $sdk 'cmdline-tools') | Out-Null
    Move-Item -Force (Join-Path $tmp 'cmdline-tools') (Join-Path $sdk 'cmdline-tools\latest')
    Remove-Item -Recurse -Force $tmp
}
Write-Host '[ok  ] android cmdline-tools'

$env:JAVA_HOME = $jdkHome
$env:ANDROID_HOME = $sdk
$env:ANDROID_SDK_ROOT = $sdk
$env:Path = "$jdkHome\bin;$sdk\cmdline-tools\latest\bin;$sdk\platform-tools;" + $env:Path

Write-Host '[sdk ] accepting licenses + installing packages (several minutes)'
& (Join-Path $sdk 'cmdline-tools\latest\bin\sdkmanager.bat') --sdk_root=$sdk --licenses 2>&1 | Out-Null
& (Join-Path $sdk 'cmdline-tools\latest\bin\sdkmanager.bat') --sdk_root=$sdk `
    'platform-tools' 'platforms;android-36' 'build-tools;36.0.0' 2>&1 | ForEach-Object { $_ }
Write-Host '[ok  ] android sdk packages'

# ---------------- MongoDB (for backend integration test) ----------------
$mongoZip = Join-Path $dl 'mongodb.zip'
Get-File 'https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-8.0.4.zip' $mongoZip | Out-Null
if (-not (Test-Path (Join-Path $root 'mongodb\bin\mongod.exe'))) {
    Write-Host '[unzip] MongoDB'
    $tmp = Join-Path $dl 'mongo_x'
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Expand-Archive -Force -Path $mongoZip -DestinationPath $tmp
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    Move-Item $inner.FullName (Join-Path $root 'mongodb')
    Remove-Item -Recurse -Force $tmp
}
Write-Host '[ok  ] mongodb'
Write-Host 'TOOLCHAIN_INSTALL_DONE'
