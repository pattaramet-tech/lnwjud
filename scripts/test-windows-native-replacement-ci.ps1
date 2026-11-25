# Destructive acceptance ONLY on a clean ephemeral GitHub-hosted Windows VM.
# Never run locally, on a self-hosted runner, or against an existing service.
param([Parameter(Mandatory)][ValidateSet('idle','modern','legacy')][string]$Mode)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_JOB -ne 'native-replacement-acceptance' -or
    $env:GITHUB_EVENT_NAME -ne 'workflow_dispatch' -or $env:GITHUB_RUN_ID -notmatch '^\d+$' -or
    $env:GITHUB_SHA -notmatch '^[a-f0-9]{40}$') { throw 'REPLACEMENT_DISPOSABLE_HOST_REQUIRED' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'REPLACEMENT_ADMIN_REQUIRED' }
$repo = Split-Path -Parent $PSScriptRoot
if ((& git -C $repo rev-parse HEAD).Trim() -ne $env:GITHUB_SHA -or $LASTEXITCODE -ne 0) { throw 'REPLACEMENT_SOURCE_SHA_MISMATCH' }
$store = Join-Path $env:ProgramData 'lnwjud-containment'
$installedRoot = Join-Path $env:ProgramFiles 'lnwjud'
$fixtureRoot = Join-Path $env:RUNNER_TEMP ('lnwjud-replacement-' + $Mode + '-' + $env:GITHUB_RUN_ID)
$newRoot = Join-Path $env:ProgramFiles ('lnwjud-replacement-' + $Mode + '-' + $env:GITHUB_RUN_ID)
if ((Get-CimInstance Win32_Service -Filter "Name='LnwjudContainment'") -or
    (Test-Path -LiteralPath $store) -or (Test-Path -LiteralPath $installedRoot) -or
    (Test-Path -LiteralPath $fixtureRoot) -or (Test-Path -LiteralPath $newRoot) -or
    (Test-Path 'HKLM:\SOFTWARE\lnwjud\UpdateAuthority') -or
    (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\com.lnwjud.desktop') -or
    (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\com.lnwjud.desktop')) {
    throw 'REPLACEMENT_RUNNER_NOT_CLEAN'
}
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$ledger = Join-Path $store 'attempts.json'
function Hash([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function Service {
    $s = Get-CimInstance Win32_Service -Filter "Name='LnwjudContainment'"
    if ($null -eq $s) { throw 'REPLACEMENT_SERVICE_MISSING' }
    return $s
}
function Assert-Service([string]$Image,[string]$State,[string]$StartMode) {
    $s = Service
    if ($s.PathName -ne ('"' + $Image + '" service') -or $s.State -ne $State -or
        $s.StartMode -ne $StartMode -or $s.StartName -ne 'LocalSystem' -or
        ($State -eq 'Running' -and $s.ProcessId -eq 0) -or ($State -eq 'Stopped' -and $s.ProcessId -ne 0)) {
        throw 'REPLACEMENT_SCM_ATTESTATION_FAILED'
    }
    return $s
}
function Invoke-Native([string]$Image,[string[]]$Arguments,[object]$Request = $null,[int]$Timeout = 180000) {
    $psi = [Diagnostics.ProcessStartInfo]::new($Image)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    foreach ($arg in $Arguments) { $psi.ArgumentList.Add($arg) }
    $p = [Diagnostics.Process]::Start($psi)
    if ($null -eq $p) { throw 'REPLACEMENT_PROCESS_START_FAILED' }
    try {
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        if ($null -ne $Request) {
            $body = [Text.Encoding]::UTF8.GetBytes(($Request | ConvertTo-Json -Depth 20 -Compress))
            $header = [BitConverter]::GetBytes([int]$body.Length)
            $p.StandardInput.BaseStream.Write($header,0,$header.Length)
            $p.StandardInput.BaseStream.Write($body,0,$body.Length)
        }
        $p.StandardInput.Close()
        if (-not $p.WaitForExit($Timeout)) { throw 'REPLACEMENT_PROCESS_TIMEOUT_STOP_NO_RETRY' }
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($out,$err),5000)) { throw 'REPLACEMENT_OUTPUT_TIMEOUT' }
        return [pscustomobject]@{ Exit = $p.ExitCode; Output = $out.Result.Trim(); Error = $err.Result.Trim() }
    } finally { $p.Dispose() }
}
function Require-Exit($Result,[int]$Code,[string]$Reason = '') {
    if ($Result.Exit -ne $Code -or ($Reason -and $Result.Output -ne $Reason)) {
        throw "REPLACEMENT_COMMAND_UNEXPECTED expected=$Code/$Reason actual=$($Result.Exit)/$($Result.Output)"
    }
}
function Rpc([string]$Image,[string]$Pin,[hashtable]$Request,[string]$ExpectedError = '') {
    $Request.protocol = 3
    $r = Invoke-Native $Image @('service-rpc',$Pin) $Request 130000
    # The old endpoint pin mismatch exits 125; native request denials return a
    # protocol envelope. The error name is checked, not just the exit code.
    $response = $r.Output | ConvertFrom-Json
    if ($response.protocol -ne 3) { throw 'REPLACEMENT_RPC_PROTOCOL_INVALID' }
    if ($ExpectedError) {
        if ($response.ok -or $response.error -ne $ExpectedError) { throw "REPLACEMENT_RPC_REFUSAL_EXPECTED_$ExpectedError" }
        return
    }
    Require-Exit $r 0
    if (-not $response.ok) { throw "REPLACEMENT_RPC_FAILED_$($response.error)" }
    return $response.result
}
function New-Identity {
    $id = 'repository-import-' + [guid]::NewGuid().ToString()
    return @{taskId=$id; reservationId=$id; attemptId=$id; generation=1; requestDigest=('a'*64);
        ownerClientId='replacement-ci'; ownerSessionId='replacement-ci-original'; workspaceId='replacement-ci-workspace'}
}
function Stage-Native([string]$Root,[string]$Helper,[string]$Pin) {
    if (Test-Path -LiteralPath $Root) { throw 'REPLACEMENT_STAGE_EXISTS' }
    $dir = Join-Path $Root 'resources\native-containment'
    New-Item -ItemType Directory -Path $dir | Out-Null
    # ACLs are established ONLY on newly created CI fixture paths.
    $owner = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
    foreach ($folder in @($Root,(Join-Path $Root 'resources'),$dir)) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true,$false)
        foreach ($pair in @(@($owner,'FullControl'),@($system,'FullControl'),@($users,'ReadAndExecute'))) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($pair[0],$pair[1],'ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $folder -AclObject $acl
    }
    $image = Join-Path $dir 'lnwjud-containment.exe'
    $pinFile = Join-Path $dir 'lnwjud-containment-pin.node'
    Copy-Item -LiteralPath $Helper -Destination $image
    Copy-Item -LiteralPath $Pin -Destination $pinFile
    if ((Hash $Helper) -ne (Hash $image) -or (Hash $Pin) -ne (Hash $pinFile)) { throw 'REPLACEMENT_COPY_MISMATCH' }
    $manifest = @{schemaVersion=2;buildId='lnwjud-containment-v2';platform='win32';architecture='x64';
        filename='lnwjud-containment.exe';sha256=(Hash $image);pinFilename='lnwjud-containment-pin.node';pinSha256=(Hash $pinFile)}
    $manifest | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $dir 'manifest.json') -Encoding utf8NoBOM
    foreach ($file in @($image,$pinFile,(Join-Path $dir 'manifest.json'))) {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetOwner($owner)
        $acl.SetAccessRuleProtection($true,$false)
        foreach ($pair in @(@($owner,'FullControl'),@($system,'FullControl'),@($users,'ReadAndExecute'))) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($pair[0],$pair[1],'Allow'))
        }
        Set-Acl -LiteralPath $file -AclObject $acl
    }
    return $image
}
function Invoke-Setup([string]$Image,[string[]]$Arguments,[int]$ExpectedExit) {
    $p = Start-Process -FilePath $Image -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    try {
        if (-not $p.WaitForExit(180000)) { throw 'REPLACEMENT_SETUP_TIMEOUT_STOP_NO_RETRY' }
        if ($p.ExitCode -ne $ExpectedExit) { throw "REPLACEMENT_SETUP_EXIT_$($p.ExitCode)_EXPECTED_$ExpectedExit" }
    } finally { $p.Dispose() }
}
$packaging = Join-Path $repo 'apps\desktop\dist\installers'
$setups = @(Get-ChildItem -LiteralPath $packaging -Filter 'lnwjud-Setup-*.exe' -File)
if ($setups.Count -ne 1) { throw 'REPLACEMENT_EXPECTED_ONE_SETUP' }
$setup = $setups[0].FullName
$sums = Get-Content -LiteralPath (Join-Path $packaging 'SHA256SUMS.txt')
if ($sums -notcontains ((Hash $setup) + '  ' + $setups[0].Name)) { throw 'REPLACEMENT_SETUP_HASH_MISMATCH' }
$unpacked = Join-Path $packaging 'win-unpacked\resources\native-containment'
$packedHelper = Join-Path $unpacked 'lnwjud-containment.exe'
$packedPin = Join-Path $unpacked 'lnwjud-containment-pin.node'
$manifest = Get-Content -LiteralPath (Join-Path $unpacked 'manifest.json') -Raw | ConvertFrom-Json
if ((Hash $packedHelper) -ne $manifest.sha256 -or (Hash $packedPin) -ne $manifest.pinSha256) { throw 'REPLACEMENT_PACKAGED_NATIVE_HASH_MISMATCH' }
if ($Mode -eq 'idle') {
    Invoke-Setup $setup @('/S','/allusers') 0
    $old = Join-Path $installedRoot 'resources\native-containment\lnwjud-containment.exe'
    $oldHash = Hash $old
    if ($oldHash -ne $manifest.sha256) { throw 'IDLE_INSTALLED_HELPER_MISMATCH' }
    $running = Assert-Service $old Running Auto
    $fresh = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    if ($fresh.schemaVersion -ne 2 -or @($fresh.attempts).Count -ne 0) { throw 'IDLE_FRESH_LEDGER_UNVERIFIED' }
    $identity = New-Identity
    $operation = @{kind='run_process';executable=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');
        args=@('-NoProfile','-NonInteractive','-Command','exit 0');cwd=$fixtureRoot;timeoutMs=10000;
        windowsVerbatimArguments=$false;environment=@{SystemRoot=$env:SystemRoot;WINDIR=$env:WINDIR};maximumOutputBytes=1024}
    $prepared = Rpc $old $oldHash @{command='prepare';identity=$identity;operation=$operation}
    if (-not $prepared.reservationHeld) { throw 'IDLE_PREPARE_FAILED' }
    $busyHash = Hash $ledger
    Rpc $old $oldHash @{command='maintenance_remove'} 'SERVICE_REMOVE_NATIVE_RESERVATION_UNVERIFIED'
    Require-Exit (Invoke-Native $old @('service-uninstall')) 125 'SERVICE_REMOVE_NATIVE_RESERVATION_UNVERIFIED'
    if ((Hash $ledger) -ne $busyHash -or (Assert-Service $old Running Auto).ProcessId -ne $running.ProcessId) {
        throw 'IDLE_BUSY_UNINSTALL_CHANGED_AUTHORITY'
    }
    $settled = Rpc $old $oldHash @{command='abort';identity=$identity;operation=$operation}
    if ($settled.phase -ne 2 -or $settled.reservationHeld) { throw 'IDLE_ABORT_FAILED' }
    $before = Hash $ledger
    $uninstaller = Join-Path $installedRoot 'uninstall.exe'
    Invoke-Setup $uninstaller @('/S','/allusers') 0
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (-not (Get-CimInstance Win32_Service -Filter "Name='LnwjudContainment'") -and
            -not (Test-Path -LiteralPath $old) -and -not (Test-Path -LiteralPath (Join-Path $installedRoot 'lnwjud.exe'))) { break }
        if ($watch.Elapsed.TotalSeconds -gt 90) { throw 'IDLE_UNINSTALL_NOT_COMPLETE' }
        Start-Sleep -Milliseconds 250
    } while ($true)
    if ((Hash $ledger) -ne $before) { throw 'IDLE_UNINSTALL_LEDGER_CHANGED' }
    [pscustomobject]@{mode=$Mode;source=$env:GITHUB_SHA;setupSha256=(Hash $setup);oldHelperSha256=$oldHash;
        ledgerBefore=$before;ledgerAfter=(Hash $ledger);busyRefusalVerified=$true;result='PASS'} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $fixtureRoot 'replacement-evidence.json') -Encoding utf8NoBOM
    Write-Host 'IDLE_HOSTED_ACCEPTANCE_PASS'
    return
}
$publish = Join-Path $fixtureRoot 'alternate-publish'
$project = Join-Path $repo 'native\windows-containment-helper\WindowsContainmentHelper.csproj'
if ($Mode -eq 'legacy') {
    # Pinned source predecessor, not a claimed historical release installer.
    $base = 'b331aa808d88bdb7db07a465db3de0be41ed981a'
    & git -C $repo diff --quiet $base HEAD -- native/windows-containment-helper/pin
    if ($LASTEXITCODE -ne 0) { throw 'REPLACEMENT_PREDECESSOR_PIN_SOURCE_DIFFERENT' }
    $baseTree = Join-Path $fixtureRoot 'predecessor'
    & git -C $repo worktree add --detach $baseTree $base
    if ($LASTEXITCODE -ne 0 -or (& git -C $baseTree rev-parse HEAD).Trim() -ne $base) { throw 'REPLACEMENT_PREDECESSOR_SOURCE_UNVERIFIED' }
    & dotnet publish (Join-Path $baseTree 'native\windows-containment-helper\WindowsContainmentHelper.csproj') -c Release -r win-x64 --self-contained true -o $publish --disable-build-servers -p:UseSharedCompilation=false
    if ($LASTEXITCODE -ne 0) { throw 'REPLACEMENT_PREDECESSOR_BUILD_FAILED' }
    $old = Stage-Native $installedRoot (Join-Path $publish 'lnwjud-containment.exe') $packedPin
    $candidate = Stage-Native $newRoot $packedHelper $packedPin
    Require-Exit (Invoke-Native $old @('service-install')) 0
} else {
    Invoke-Setup $setup @('/S','/allusers') 0
    $old = Join-Path $installedRoot 'resources\native-containment\lnwjud-containment.exe'
    if ((Hash $old) -ne $manifest.sha256) { throw 'REPLACEMENT_INSTALLED_HELPER_MISMATCH' }
    # Deliberately distinct same-source fixture binary, not a signed release.
    & dotnet publish $project -c Release -r win-x64 --self-contained true -o $publish --disable-build-servers -p:UseSharedCompilation=false -p:InformationalVersion=R7-acceptance-alternate
    if ($LASTEXITCODE -ne 0) { throw 'REPLACEMENT_ALTERNATE_BUILD_FAILED' }
    $candidate = Stage-Native $newRoot (Join-Path $publish 'lnwjud-containment.exe') $packedPin
}
$oldHash = Hash $old
$newHash = Hash $candidate
if ($oldHash -eq $newHash) { throw 'REPLACEMENT_FIXTURE_IMAGES_IDENTICAL' }
$running = Assert-Service $old Running Auto
Require-Exit (Invoke-Native $candidate @('service-replace-preflight',$oldHash,$newHash)) 125 'SERVICE_INSTALL_EXISTING_SERVICE_NOT_QUIESCED'
if ((Assert-Service $old Running Auto).ProcessId -ne $running.ProcessId) { throw 'REPLACEMENT_REFUSAL_RESTARTED_SERVICE' }
$workspace = Join-Path $fixtureRoot 'workspace'
$privateHome = Join-Path $fixtureRoot 'home'
$stage = Join-Path $fixtureRoot ('.lnwjud-import-stage-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $workspace,$privateHome | Out-Null
$identity = New-Identity
$operation = @{kind='run_process';executable=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');
    args=@('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 90');cwd=$fixtureRoot;timeoutMs=120000;
    windowsVerbatimArguments=$false;environment=@{SystemRoot=$env:SystemRoot;WINDIR=$env:WINDIR;TEMP=$fixtureRoot;TMP=$fixtureRoot};maximumOutputBytes=1024}
$ordinary = New-Identity
$ordinaryPrepared = Rpc $old $oldHash @{command='prepare';identity=$ordinary;operation=$operation}
if (-not $ordinaryPrepared.reservationHeld) { throw 'REPLACEMENT_ORDINARY_PREPARE_FAILED' }
$ordinaryAbort = Rpc $old $oldHash @{command='abort';identity=$ordinary;operation=$operation}
if ($ordinaryAbort.phase -ne 2 -or $ordinaryAbort.reservationHeld) { throw 'REPLACEMENT_ORDINARY_ABORT_FAILED' }
$prepared = Rpc $old $oldHash @{command='prepare';identity=$identity;operation=$operation}
if ($prepared.phase -ne 0 -or -not $prepared.reservationHeld) { throw 'REPLACEMENT_PREPARE_NOT_HELD' }
$started = Rpc $old $oldHash @{command='run';identity=$identity;operation=$operation}
if ($started.phase -ne 3 -or -not $started.reservationHeld) { throw 'REPLACEMENT_WORKER_NOT_RUNNING' }
$arguments = @{workspaceRoot=$workspace;destination='repo';stagePath=$stage;commit=('a'*40);privateHome=$privateHome}
$import = Rpc $old $oldHash @{command='control';identity=$identity;controlCommand='prepare_import';controlRequest=$arguments}
if (-not $import.verified -or $import.result.state -ne 'prepared' -or -not (Test-Path -LiteralPath $stage)) { throw 'REPLACEMENT_STAGE_NOT_PREPARED' }
# Protect a real destination collision and a distinct stage sentinel.
$destination = Join-Path $workspace 'repo'
New-Item -ItemType Directory -Path $destination | Out-Null
[IO.File]::WriteAllText((Join-Path $destination 'preserve.txt'),'destination')
[IO.File]::WriteAllText((Join-Path $stage 'preserve.txt'),'stage')
$destinationHash = Hash (Join-Path $destination 'preserve.txt')
$stageHash = Hash (Join-Path $stage 'preserve.txt')
$null = Rpc $old $oldHash @{command='cancel';identity=$identity}
$watch = [Diagnostics.Stopwatch]::StartNew()
do {
    $terminal = Rpc $old $oldHash @{command='inspect';identity=$identity}
    if ($terminal.phase -eq 4) { break }
    if ($watch.Elapsed.TotalSeconds -gt 30) { throw 'REPLACEMENT_TERMINAL_TIMEOUT' }
    Start-Sleep -Milliseconds 250
} while ($true)
if ($terminal.activeProcesses -ne 0 -or -not $terminal.reservationHeld) { throw 'REPLACEMENT_TERMINAL_HOLD_UNVERIFIED' }
$next = New-Identity
Rpc $old $oldHash @{command='prepare';identity=$next;operation=$operation} 'WRITER_RESERVATION_BUSY'
# Only this verified disposable fixture is quiesced. No generic force stop.
Set-Service -Name LnwjudContainment -StartupType Disabled
Stop-Service -Name LnwjudContainment
$watch.Restart()
do {
    $s = Service
    if ($s.State -eq 'Stopped' -and $s.ProcessId -eq 0) { break }
    if ($watch.Elapsed.TotalSeconds -gt 30) { throw 'REPLACEMENT_QUIESCENCE_TIMEOUT' }
    Start-Sleep -Milliseconds 250
} while ($true)
$null = Assert-Service $old Stopped Disabled
$doc = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
$expectedSchema = if ($Mode -eq 'legacy') { 2 } else { 3 }
$heldRecords = @($doc.attempts | Where-Object { $_.request.identity.attemptId -eq $identity.attemptId })
if ($doc.schemaVersion -ne $expectedSchema -or @($doc.attempts).Count -ne 2 -or $heldRecords.Count -ne 1 -or -not $heldRecords[0].request.holdForImport) { throw 'REPLACEMENT_LEDGER_SCHEMA_OR_HOLD_INVALID' }
$ledgerBefore = Hash $ledger
$importFiles = @(Get-ChildItem -LiteralPath (Join-Path $store 'imports') -File)
if ($importFiles.Count -ne 1) { throw 'REPLACEMENT_EXPECTED_ONE_IMPORT_RECORD' }
$transaction = $importFiles[0].FullName
$transactionBefore = Hash $transaction
function Assert-AuthorityUnchanged {
    if ((Hash $ledger) -ne $ledgerBefore -or (Hash $transaction) -ne $transactionBefore -or
        (Hash (Join-Path $destination 'preserve.txt')) -ne $destinationHash -or
        (Hash (Join-Path $stage 'preserve.txt')) -ne $stageHash) { throw 'REPLACEMENT_AUTHORITY_BYTES_CHANGED' }
}
if ($Mode -eq 'modern') {
    Require-Exit (Invoke-Native $old @('service-install-preflight')) 125 'SERVICE_INSTALL_NATIVE_SCHEMA_FORWARD_ONLY'
    Require-Exit (Invoke-Native $old @('service-uninstall')) 125 'SERVICE_REMOVE_NATIVE_SCHEMA_FORWARD_ONLY'
    Invoke-Setup $setup @('/S','/allusers') 125
    $uninstaller = Join-Path $installedRoot 'uninstall.exe'
    Invoke-Setup $uninstaller @('/S','/allusers',"_?=$installedRoot") 125
    if ((Hash $old) -ne $oldHash -or -not (Test-Path -LiteralPath (Join-Path $installedRoot 'lnwjud.exe'))) { throw 'REPLACEMENT_NSIS_REFUSAL_REMOVED_FILES' }
    Assert-AuthorityUnchanged
    $null = Assert-Service $old Stopped Disabled
}
Require-Exit (Invoke-Native $candidate @('service-replace-preflight',('0'*64),$newHash)) 125
$null = Assert-Service $old Stopped Disabled
Assert-AuthorityUnchanged
Require-Exit (Invoke-Native $candidate @('service-replace-preflight',$oldHash,$newHash)) 0 'SERVICE_REPLACEMENT_PREFLIGHT_VERIFIED'
$null = Assert-Service $old Stopped Disabled
Assert-AuthorityUnchanged
Require-Exit (Invoke-Native $candidate @('service-replace',$oldHash,$newHash)) 0 'SERVICE_REPLACEMENT_VERIFIED'
$replacement = Assert-Service $candidate Running Auto
Assert-AuthorityUnchanged
Rpc $old $oldHash @{command='inspect';identity=$identity} 'SERVICE_ENDPOINT_PACKAGE_MISMATCH'
$held = Rpc $candidate $newHash @{command='inspect';identity=$identity}
if ($held.phase -ne 4 -or -not $held.reservationHeld) { throw 'REPLACEMENT_HOLD_NOT_PRESERVED' }
Rpc $candidate $newHash @{command='prepare';identity=$next;operation=$operation} 'WRITER_RESERVATION_BUSY'
if ($Mode -eq 'legacy') {
    Rpc $candidate $newHash @{command='control';identity=$identity;controlCommand='abort_import';controlRequest=$arguments} 'SERVICE_IMPORT_LEGACY_EXPLICIT_RECOVERY_REQUIRED'
    $arguments.recoverLegacy = $true
    Rpc $candidate $newHash @{command='control';identity=$identity;controlCommand='abort_import';controlRequest=$arguments} 'SERVICE_IMPORT_LEGACY_NEW_BOOT_REQUIRED'
    $witnessHash = Hash $ledger
    Rpc $candidate $newHash @{command='control';identity=$identity;controlCommand='abort_import';controlRequest=$arguments} 'SERVICE_IMPORT_LEGACY_NEW_BOOT_REQUIRED'
    if ((Hash $ledger) -ne $witnessHash -or -not (Rpc $candidate $newHash @{command='inspect';identity=$identity}).reservationHeld) { throw 'REPLACEMENT_LEGACY_SAME_BOOT_RELEASED' }
    $witness = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    $witnessRecords = @($witness.attempts | Where-Object { $_.request.identity.attemptId -eq $identity.attemptId })
    if ($witness.schemaVersion -ne 3 -or $witnessRecords.Count -ne 1 -or -not $witnessRecords[0].request.legacyImportObservedBoot) { throw 'REPLACEMENT_LEGACY_WITNESS_MISSING' }
    Write-Host 'LEGACY_BOOT_WITNESS_RETAINED; ACTUAL_REBOOT_NOT_TESTED'
} else {
    $aborted = Rpc $candidate $newHash @{command='control';identity=$identity;controlCommand='abort_import';controlRequest=$arguments}
    if ($aborted.result.state -ne 'aborted' -or (Rpc $candidate $newHash @{command='inspect';identity=$identity}).reservationHeld) { throw 'REPLACEMENT_ABORT_RELEASE_UNVERIFIED' }
    if (-not (Rpc $candidate $newHash @{command='prepare';identity=$next;operation=$operation}).reservationHeld) { throw 'REPLACEMENT_NEXT_WRITER_NOT_ADMITTED' }
    $nextAbort = Rpc $candidate $newHash @{command='abort';identity=$next;operation=$operation}
    if ($nextAbort.phase -ne 2 -or $nextAbort.reservationHeld) { throw 'REPLACEMENT_NEXT_WRITER_NOT_RELEASED' }
}
if ((Hash (Join-Path $destination 'preserve.txt')) -ne $destinationHash -or (Hash (Join-Path $stage 'preserve.txt')) -ne $stageHash) { throw 'REPLACEMENT_FIXTURE_CONTENT_CHANGED' }
if ((Assert-Service $candidate Running Auto).ProcessId -ne $replacement.ProcessId) { throw 'REPLACEMENT_SERVICE_PID_CHANGED' }
# Do not restore or delete authority even on success. Hosted VM disposal owns teardown.
[pscustomobject]@{mode=$Mode;source=$env:GITHUB_SHA;setupSha256=(Hash $setup);oldHelperSha256=$oldHash;
    candidateHelperSha256=$newHash;initialSchema=$expectedSchema;ledgerBefore=$ledgerBefore;
    transactionBefore=$transactionBefore;ledgerAfter=(Hash $ledger);transactionAfter=(Hash $transaction);
    servicePid=$replacement.ProcessId;actualRebootTested=$false;historicalInstallerTested=$false;
    result='PASS'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $fixtureRoot 'replacement-evidence.json') -Encoding utf8NoBOM
Write-Host "REPLACEMENT_HOSTED_ACCEPTANCE_PASS mode=$Mode"
