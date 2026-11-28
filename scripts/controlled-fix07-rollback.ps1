#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string] $RollbackSetup,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string] $ExpectedCurrentHelperSha256
)
$ErrorActionPreference = 'Stop'
# Only the exact qualified FIX-07 package is a rollback candidate.
$expectedSetup = '98cfb7579ab43da72beb31681f2ae9d919d0965d819f07eed078d05ed6d8dac5'
$expectedHelper = 'c0896bdb3f24b44c6ea06fe62455c9e144372d4b00d9e5303c3b269e6ce56b4d'
$helper = Join-Path $env:ProgramFiles 'lnwjud\resources\native-containment\lnwjud-containment.exe'
$setup = (Get-Item -LiteralPath $RollbackSetup -ErrorAction Stop).FullName
# Keep the verified rollback installer pinned against modification or replacement
# until the child finishes. The installed helper authenticates its own endpoint.
$pin = [IO.File]::Open($setup, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($sha.ComputeHash($pin)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($actual -cne $expectedSetup) { throw 'ROLLBACK_SETUP_HASH_MISMATCH' }
    if ((Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedCurrentHelperSha256.ToLowerInvariant()) {
        throw 'ROLLBACK_CURRENT_HELPER_HASH_MISMATCH'
    }
    if (-not $PSCmdlet.ShouldProcess($setup, 'Freeze native admission and run exact FIX-07 all-users rollback')) { return }
    $preflight = Start-Process -FilePath $helper -ArgumentList 'service-rollback-preflight' -PassThru -Wait -WindowStyle Hidden
    if ($preflight.ExitCode -ne 0) { throw "ROLLBACK_PREFLIGHT_REFUSED_$($preflight.ExitCode)" }
    # No installer is launched if the protected preflight fails. The existing
    # uninstaller repeats the check and the native fence survives a service crash.
    $installer = Start-Process -FilePath $setup -ArgumentList @('/S','/allusers') -PassThru -Wait -WindowStyle Hidden
    if ($installer.ExitCode -ne 0) { throw "ROLLBACK_INSTALLER_EXIT_$($installer.ExitCode)" }
    $service = Get-CimInstance Win32_Service -Filter "Name='LnwjudContainment'"
    if ($null -eq $service -or $service.State -ne 'Running' -or $service.StartName -ne 'LocalSystem' -or
        (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHelper) {
        throw 'ROLLBACK_POSTSTATE_UNVERIFIED'
    }
    Write-Output 'CONTROLLED_FIX07_ROLLBACK_VERIFIED'
}
finally { $pin.Dispose() }
# Never clear the fence, restart the service, edit the ledger or retry an
# interrupted transition automatically. Preserve evidence for administrator review.
