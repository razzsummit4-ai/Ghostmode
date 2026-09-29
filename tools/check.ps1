$env:Path = "C:\devtool\flutter\bin;" + $env:Path
Set-Location 'C:\Users\sumit\OneDrive\Desktop\E2E\app'
Write-Output "=== ANALYZE lib ==="
dart analyze lib 2>&1 | Select-String -Pattern ' error | warning |issues found|No issues' | ForEach-Object { $_.Line }
Write-Output "=== TESTS ==="
flutter test 2>&1 | Select-String -Pattern 'All tests passed|Some tests failed|Expected|Actual' | ForEach-Object { $_.Line }
