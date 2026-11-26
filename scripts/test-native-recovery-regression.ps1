# Runs only the disposable native fixture suites, never the installed service.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'NATIVE_RECOVERY_WINDOWS_REQUIRED' }
$dotnet = (Get-Command dotnet.exe -CommandType Application -ErrorAction Stop).Source
$project = Join-Path $PSScriptRoot '../native/windows-containment-helper/tests/ContainmentNativeTests.csproj'
$project = (Resolve-Path -LiteralPath $project).Path
& $dotnet build $project -c Release --disable-build-servers -p:UseSharedCompilation=false
if ($LASTEXITCODE -ne 0) { throw 'NATIVE_RECOVERY_TEST_BUILD_FAILED' }
$suites = @(
    'maintenance-boundary-tests',
    'orphan-import-authorization-tests',
    'coordinated-upgrade-tests',
    'native-update-transaction-tests',
    'update-eligibility-tests',
    'import-suite',
    'import-timeout-tests',
    'mcp-service-tests'
)
foreach ($suite in $suites) {
    & $dotnet run --project $project -c Release --no-build --no-restore -- $suite
    if ($LASTEXITCODE -ne 0) { throw "NATIVE_RECOVERY_TEST_FAILED $suite (exit $LASTEXITCODE)" }
    Write-Output "NATIVE_RECOVERY_SUITE_PASS=$suite"
}
Write-Output 'NATIVE_RECOVERY_REGRESSION_PASS=8/8'
