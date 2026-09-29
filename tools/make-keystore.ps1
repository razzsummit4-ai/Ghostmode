# Creates the SecureChat release signing keystore.
#
# Run ONCE on the machine that owns the release identity. The resulting
# .jks and its password must be kept: Android identifies an app by signing
# key, so a build signed with a different key cannot be installed as an update
# over an existing install. Losing it means users must uninstall first.
#
#   pwsh -File tools\make-keystore.ps1
#
# Credentials are written to android\keystore.properties, which is
# git-ignored. Never commit that file or the .jks to a public repository.

$ErrorActionPreference = 'Stop'
$env:JAVA_HOME = 'C:\devtool\jdk'
$env:Path = "C:\devtool\jdk\bin;$env:Path"

$project = 'C:\Users\sumit\OneDrive\Desktop\E2E\app'
$keystoreDir = Join-Path $project 'android'
$jks = Join-Path $keystoreDir 'securechat-release.jks'
$props = Join-Path $keystoreDir 'keystore.properties'

if (Test-Path $jks) {
    Write-Output "Keystore already exists: $jks"
    Write-Output 'Delete it first if you intend to rotate the signing key.'
    exit 0
}

# A generated password. The store password is intentionally separate from the
# key password, which is standard practice and limits the blast radius if the
# key file alone is disclosed.
$storePass = [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Maximum 256 }))
$keyPass = [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Maximum 256 }))
$alias = 'securechat'

Write-Output "=== generating release keystore ==="
& keytool -genkeypair `
    -alias $alias `
    -keyalg RSA `
    -keysize 4096 `
    -validity 10950 `
    -keystore $jks `
    -storepass $storePass `
    -keypass $keyPass `
    -dname 'CN=SecureChat, OU=Release, O=SecureChat, L=-, ST=-, C=IN'

if ($LASTEXITCODE -ne 0) {
    throw "keytool failed with exit code $LASTEXITCODE"
}

$propsBody = @"
# Release signing credentials. GIT-IGNORED - never commit.
# Regenerate with: tools\make-keystore.ps1
# Losing the .jks means existing installs cannot be updated in place.
storeFile=securechat-release.jks
storePassword=$storePass
keyAlias=$alias
keyPassword=$keyPass
"@
Set-Content -Path $props -Value $propsBody -Encoding utf8

Write-Output "=== done ==="
Write-Output "keystore: $jks"
Write-Output "properties: $props"
& keytool -list -v -keystore $jks -storepass $storePass 2>&1 |
    Select-String -Pattern 'Alias|Valid|Signature algorithm|Subject Public Key' |
    ForEach-Object { $_.Line }
