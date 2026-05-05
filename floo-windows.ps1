#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    Write-Error 'floo-windows.ps1 only supports Windows.'
    exit 1
}

$Script:GitHubRepo = 'ntetv/floo'
$Script:ReleaseBaseUrl = "https://gh.5ieee.com/github.com/$Script:GitHubRepo/releases/latest/download"
$Script:ScriptPath = $PSCommandPath
$Script:ScriptDir = Split-Path -Parent $Script:ScriptPath
$Script:AppRoot = Join-Path $env:LOCALAPPDATA 'Floo'
$Script:ConfigDir = Join-Path $Script:AppRoot 'configs'
$Script:BinDir = Join-Path $Script:AppRoot 'bin'
$Script:LogDir = Join-Path $Script:AppRoot 'logs'
$Script:StateDir = Join-Path $Script:AppRoot 'state'
$Script:ManagedScriptPath = Join-Path $Script:BinDir 'floo-windows.ps1'
$Script:ManagedClientBin = Join-Path $Script:BinDir 'flooc.exe'

function Write-Note {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Fail {
    param([string]$Message)
    throw $Message
}

function Ensure-Directories {
    foreach ($path in @($Script:AppRoot, $Script:ConfigDir, $Script:BinDir, $Script:LogDir, $Script:StateDir)) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

function Write-Utf8File {
    param(
        [string]$Path,
        [string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Test-ValidId {
    param([string]$Id)
    return $Id -match '^[A-Za-z0-9_-]+$'
}

function Format-Target {
    param([string]$InputValue)
    if ($InputValue -match '^[0-9]+$') {
        return "127.0.0.1:$InputValue"
    }
    return $InputValue
}

function Parse-FlagValue {
    param(
        [string]$Argument,
        [string]$Prefix
    )

    $needle = "$Prefix="
    if ($Argument.StartsWith($needle)) {
        return $Argument.Substring($needle.Length)
    }

    return $null
}

function ConvertFrom-Base64Url {
    param([string]$Value)

    $normalized = $Value.Replace('-', '+').Replace('_', '/')
    switch ($normalized.Length % 4) {
        0 { }
        2 { $normalized += '==' }
        3 { $normalized += '=' }
        default { Fail 'Invalid base64url preset.' }
    }

    $bytes = [Convert]::FromBase64String($normalized)
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Get-ReleaseAssetName {
    if ([Environment]::Is64BitOperatingSystem) {
        return 'floo-x86_64-windows.zip'
    }

    Fail 'Current Windows architecture is not supported.'
}

function Download-ReleaseAsset {
    param(
        [string]$AssetName,
        [string]$OutputPath
    )

    $url = "$Script:ReleaseBaseUrl/$AssetName"
    Write-Note "Downloading from GitHub latest release: $AssetName"
    try {
        Invoke-WebRequest -Uri $url -OutFile $OutputPath -UseBasicParsing
    }
    catch {
        Fail "Failed to download $AssetName."
    }
}

function Install-ReleaseClientBinary {
    Ensure-Directories

    $assetName = Get-ReleaseAssetName
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        $archivePath = Join-Path $tempDir $assetName
        Download-ReleaseAsset -AssetName $assetName -OutputPath $archivePath

        $extractDir = Join-Path $tempDir 'extract'
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force

        $clientBinary = Get-ChildItem -LiteralPath $extractDir -Recurse -Filter 'flooc.exe' -File | Select-Object -First 1 -ExpandProperty FullName
        if ([string]::IsNullOrWhiteSpace($clientBinary)) {
            Fail 'flooc.exe not found in release archive.'
        }

        Copy-Item -LiteralPath $clientBinary -Destination $Script:ManagedClientBin -Force
    }
    finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force
        }
    }

    return $Script:ManagedClientBin
}

function Get-JsonString {
    param(
        [object]$JsonObject,
        [string]$Key
    )

    $property = $JsonObject.PSObject.Properties[$Key]
    if ($null -eq $property) {
        Fail "Missing preset field: $Key"
    }

    if ($null -eq $property.Value) {
        return ''
    }

    return [string]$property.Value
}

function Get-ConfigModeValue {
    param([string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return ''
    }

    foreach ($line in Get-Content -LiteralPath $FilePath) {
        if ($line -match '^mode\s*=\s*([12])\s*$') {
            return $Matches[1]
        }
    }

    return ''
}

function Get-ConfigKindValue {
    param([string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return 'client'
    }

    $hasBind = $false
    $hasPort = $false
    $hasServer = $false

    foreach ($line in Get-Content -LiteralPath $FilePath) {
        if ($line -match '^# floo_role\s*=\s*(server|client)\s*$') {
            return $Matches[1]
        }

        if ($line -match '^bind\s*=') {
            $hasBind = $true
        }
        if ($line -match '^port\s*=') {
            $hasPort = $true
        }
        if ($line -match '^server\s*=') {
            $hasServer = $true
        }
    }

    if ($hasBind -and $hasPort) {
        return 'server'
    }
    if ($hasServer) {
        return 'client'
    }

    return 'client'
}

function Escape-TomlString {
    param([string]$Value)

    return $Value.Replace('\', '\\').Replace('"', '\"')
}

function Get-InstanceLabel {
    param([string]$Id)
    return "com.ntetv.floo.client.$Id"
}

function Get-ConfigPath {
    param([string]$Id)
    return (Join-Path $Script:ConfigDir "$Id.toml")
}

function Get-StatePath {
    param([string]$Id)
    return (Join-Path $Script:StateDir "$Id.json")
}

function Get-StdoutLogPath {
    param([string]$Id)
    return (Join-Path $Script:LogDir "$(Get-InstanceLabel $Id).out.log")
}

function Get-StderrLogPath {
    param([string]$Id)
    return (Join-Path $Script:LogDir "$(Get-InstanceLabel $Id).err.log")
}

function Get-AutostartTaskName {
    param([string]$Id)
    return (Get-InstanceLabel $Id)
}

function New-InstanceState {
    param([string]$Id)

    return [pscustomobject]@{
        id = $Id
        kind = 'client'
        label = (Get-InstanceLabel $Id)
        configPath = (Get-ConfigPath $Id)
        stdoutLogPath = (Get-StdoutLogPath $Id)
        stderrLogPath = (Get-StderrLogPath $Id)
        statePath = (Get-StatePath $Id)
        binaryPath = $Script:ManagedClientBin
        pid = $null
        lastStartTime = $null
        lastStopTime = $null
        autostartTaskName = (Get-AutostartTaskName $Id)
        autostartEnabled = $false
        server = $null
        mapName = $null
        mode = $null
        proxyMode = $null
        clientTarget = $null
    }
}

function Set-StateField {
    param(
        [object]$State,
        [string]$Name,
        $Value
    )

    $property = $State.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $State | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
        return
    }

    $property.Value = $Value
}

function Load-InstanceState {
    param([string]$Id)

    $path = Get-StatePath $Id
    if (-not (Test-Path -LiteralPath $path)) {
        return (New-InstanceState $Id)
    }

    try {
        $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }
    catch {
        return (New-InstanceState $Id)
    }

    $defaults = New-InstanceState $Id
    foreach ($name in @('id', 'kind', 'label', 'configPath', 'stdoutLogPath', 'stderrLogPath', 'statePath', 'binaryPath', 'pid', 'lastStartTime', 'lastStopTime', 'autostartTaskName', 'autostartEnabled', 'server', 'mapName', 'mode', 'proxyMode', 'clientTarget')) {
        if ($null -eq $state.PSObject.Properties[$name]) {
            Set-StateField $state $name $defaults.$name
        }
    }

    return $state
}

function Save-InstanceState {
    param([string]$Id, [object]$State)

    Ensure-Directories
    $json = $State | ConvertTo-Json -Depth 4
    Write-Utf8File -Path (Get-StatePath $Id) -Content $json
}

function Get-InstanceIds {
    Ensure-Directories
    $files = Get-ChildItem -LiteralPath $Script:ConfigDir -Filter '*.toml' -File -ErrorAction SilentlyContinue | Sort-Object Name
    foreach ($file in $files) {
        $file.BaseName
    }
}

function Test-InstanceExists {
    param([string]$Id)
    return (Test-Path -LiteralPath (Get-ConfigPath $Id))
}

function Assert-ClientInstance {
    param([string]$Id)

    if (-not (Test-InstanceExists $Id)) {
        Fail "Unknown instance ID: $Id"
    }

    $kind = Get-ConfigKindValue (Get-ConfigPath $Id)
    if ($kind -ne 'client') {
        Fail "Windows lightweight manager only supports client instances: $Id"
    }
}

function Ensure-ManagedScript {
    Ensure-Directories
    if ($Script:ScriptPath -ne $Script:ManagedScriptPath) {
        Copy-Item -LiteralPath $Script:ScriptPath -Destination $Script:ManagedScriptPath -Force
    }
    return $Script:ManagedScriptPath
}

function Ensure-ClientBinary {
    Ensure-Directories

    if (-not (Test-Path -LiteralPath $Script:ManagedClientBin)) {
        return (Install-ReleaseClientBinary)
    }

    return $Script:ManagedClientBin
}

function Test-ScheduledTasksAvailable {
    return $null -ne (Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue)
}

function Test-AutostartEnabled {
    param([string]$Id)

    if (-not (Test-ScheduledTasksAvailable)) {
        return $false
    }

    return $null -ne (Get-ScheduledTask -TaskName (Get-AutostartTaskName $Id) -ErrorAction SilentlyContinue)
}

function Test-ProcessMatchesState {
    param(
        [System.Diagnostics.Process]$Process,
        [object]$State
    )

    $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction SilentlyContinue
    if ($null -eq $processInfo) {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$State.binaryPath) -and -not [string]::IsNullOrWhiteSpace([string]$processInfo.ExecutablePath)) {
        if ($processInfo.ExecutablePath.Trim().ToLowerInvariant() -ne ([string]$State.binaryPath).Trim().ToLowerInvariant()) {
            return $false
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$State.configPath) -and -not [string]::IsNullOrWhiteSpace([string]$processInfo.CommandLine)) {
        $escapedConfigPath = [Regex]::Escape([string]$State.configPath)
        if ($processInfo.CommandLine -notmatch $escapedConfigPath) {
            return $false
        }
    }

    return $true
}

function Get-InstanceProcess {
    param(
        [string]$Id,
        [object]$State
    )

    if ($null -eq $State.pid -or [string]::IsNullOrWhiteSpace([string]$State.pid)) {
        return $null
    }

    try {
        $process = Get-Process -Id ([int]$State.pid) -ErrorAction Stop
    }
    catch {
        Set-StateField $State 'pid' $null
        Save-InstanceState $Id $State
        return $null
    }

    if ($process.ProcessName -ne 'flooc') {
        Set-StateField $State 'pid' $null
        Save-InstanceState $Id $State
        return $null
    }

    if (-not (Test-ProcessMatchesState -Process $process -State $State)) {
        Set-StateField $State 'pid' $null
        Save-InstanceState $Id $State
        return $null
    }

    return $process
}

function Get-InstanceStateText {
    param([object]$State)

    if ($null -ne (Get-InstanceProcess -Id ([string]$State.id) -State $State)) {
        return 'running'
    }

    return 'stopped'
}

function Get-ActionTargetIds {
    param([string]$TargetId)

    if ([string]::IsNullOrWhiteSpace($TargetId)) {
        return @()
    }

    if ($TargetId -eq '--all') {
        return @(Get-InstanceIds)
    }

    return @($TargetId)
}

function Show-BinaryStatus {
    if (Test-Path -LiteralPath $Script:ManagedClientBin) {
        Write-Host "  flooc: installed ($Script:ManagedClientBin)"
    }
    else {
        Write-Host '  flooc: not installed'
    }
}

function Write-InstanceSummary {
    param(
        [string]$Id,
        [string]$StateText,
        [string]$Pid,
        [string]$Autostart
    )

    if (-not [string]::IsNullOrWhiteSpace($Pid)) {
        Write-Host "  [$Id] client state=$StateText pid=$Pid autostart=$Autostart"
        return
    }

    Write-Host "  [$Id] client state=$StateText autostart=$Autostart"
}

function Show-Status {
    Ensure-Directories

    Write-Host '========================================'
    Write-Host ' Managed binary'
    Show-BinaryStatus
    Write-Host ''
    Write-Host ' Instances'

    $instanceIds = @(Get-InstanceIds)
    if ($instanceIds.Count -eq 0) {
        Write-Host '  no instances'
        Write-Host '========================================'
        return
    }

    foreach ($id in $instanceIds) {
        $state = Load-InstanceState $id
        $stateText = Get-InstanceStateText -State $state
        $instancePid = if ($null -ne $state.pid) { [string]$state.pid } else { '' }
        $autostart = if (Test-AutostartEnabled $id) { 'on' } else { 'off' }
        Write-InstanceSummary -Id $id -StateText $stateText -Pid $instancePid -Autostart $autostart
    }

    Write-Host '========================================'
}

function Show-InstanceDetails {
    param([string]$Id)

    Assert-ClientInstance $Id
    $state = Load-InstanceState $Id
    $stateText = Get-InstanceStateText -State $state
    $modeValue = Get-ConfigModeValue (Get-ConfigPath $Id)
    $autostart = if (Test-AutostartEnabled $Id) { 'enabled' } else { 'disabled' }

    Write-Host "Instance ID: $Id"
    Write-Host 'Kind: client'
    if ([string]::IsNullOrWhiteSpace($modeValue)) {
        Write-Host 'Mode: <unset>'
    }
    else {
        Write-Host "Mode: $modeValue"
    }
    Write-Host "Label: $(Get-InstanceLabel $Id)"
    Write-Host "State: $stateText"
    if ($null -ne $state.pid) {
        Write-Host "PID: $($state.pid)"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$state.lastStartTime)) {
        Write-Host "Last start: $($state.lastStartTime)"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$state.lastStopTime)) {
        Write-Host "Last stop: $($state.lastStopTime)"
    }
    Write-Host "Autostart: $autostart"
    Write-Host "Config file: $(Get-ConfigPath $Id)"
    Write-Host "State file: $(Get-StatePath $Id)"
    Write-Host "Stdout log: $(Get-StdoutLogPath $Id)"
    Write-Host "Stderr log: $(Get-StderrLogPath $Id)"
    Write-Host "Scheduled task: $(Get-AutostartTaskName $Id)"
}

function List-Instances {
    Ensure-Directories
    $instanceIds = @(Get-InstanceIds)
    if ($instanceIds.Count -eq 0) {
        Write-Note 'No managed instances found.'
        return
    }

    foreach ($id in $instanceIds) {
        $state = Load-InstanceState $id
        $stateText = Get-InstanceStateText -State $state
        $instancePid = if ($null -ne $state.pid) { [string]$state.pid } else { '' }
        $autostart = if (Test-AutostartEnabled $id) { 'on' } else { 'off' }
        Write-InstanceSummary -Id $id -StateText $stateText -Pid $instancePid -Autostart $autostart
    }
}

function Start-Instance {
    param([string]$Id)

    Assert-ClientInstance $Id
    Ensure-Directories
    $null = Ensure-ManagedScript
    $binaryPath = Ensure-ClientBinary
    $configPath = Get-ConfigPath $Id
    $state = Load-InstanceState $Id

    if ($null -ne (Get-InstanceProcess -Id $Id -State $state)) {
        Write-Note "Instance already running: $Id"
        return
    }

    $stdoutPath = Get-StdoutLogPath $Id
    $stderrPath = Get-StderrLogPath $Id

    if (-not (Test-Path -LiteralPath $stdoutPath)) {
        New-Item -ItemType File -Path $stdoutPath -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $stderrPath)) {
        New-Item -ItemType File -Path $stderrPath -Force | Out-Null
    }

    $process = Start-Process -FilePath $binaryPath -ArgumentList @($configPath) -WorkingDirectory (Split-Path -Parent $binaryPath) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -WindowStyle Hidden -PassThru

    Set-StateField $state 'kind' 'client'
    Set-StateField $state 'label' (Get-InstanceLabel $Id)
    Set-StateField $state 'configPath' $configPath
    Set-StateField $state 'stdoutLogPath' $stdoutPath
    Set-StateField $state 'stderrLogPath' $stderrPath
    Set-StateField $state 'statePath' (Get-StatePath $Id)
    Set-StateField $state 'binaryPath' $binaryPath
    Set-StateField $state 'pid' $process.Id
    Set-StateField $state 'lastStartTime' ([DateTime]::UtcNow.ToString('o'))
    Set-StateField $state 'autostartTaskName' (Get-AutostartTaskName $Id)
    Set-StateField $state 'autostartEnabled' (Test-AutostartEnabled $Id)
    Save-InstanceState $Id $state

    Write-Success "Started instance: $Id"
}

function Stop-Instance {
    param([string]$Id)

    Assert-ClientInstance $Id
    $state = Load-InstanceState $Id
    $process = Get-InstanceProcess -Id $Id -State $state

    if ($null -eq $process) {
        Set-StateField $state 'pid' $null
        Set-StateField $state 'lastStopTime' ([DateTime]::UtcNow.ToString('o'))
        Save-InstanceState $Id $state
        Write-Note "Instance already stopped: $Id"
        return
    }

    Stop-Process -Id $process.Id -ErrorAction Stop
    Wait-Process -Id $process.Id -Timeout 5 -ErrorAction SilentlyContinue

    Set-StateField $state 'pid' $null
    Set-StateField $state 'lastStopTime' ([DateTime]::UtcNow.ToString('o'))
    Save-InstanceState $Id $state

    Write-Success "Stopped instance: $Id"
}

function Restart-Instance {
    param([string]$Id)

    Assert-ClientInstance $Id
    Stop-Instance $Id
    Start-Instance $Id
}

function Format-ProcessArgument {
    param([string]$Value)
    return ('"{0}"' -f $Value)
}

function Enable-AutostartInstance {
    param([string]$Id)

    Assert-ClientInstance $Id
    if (-not (Test-ScheduledTasksAvailable)) {
        Fail 'ScheduledTasks module is unavailable on this system.'
    }

    $managedScript = Ensure-ManagedScript
    $null = Ensure-ClientBinary
    $taskName = Get-AutostartTaskName $Id
    $userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $(Format-ProcessArgument $managedScript) start $(Format-ProcessArgument $Id)"

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Start Floo client instance $Id at logon." -Force | Out-Null

    $state = Load-InstanceState $Id
    Set-StateField $state 'autostartEnabled' $true
    Set-StateField $state 'autostartTaskName' $taskName
    Save-InstanceState $Id $state

    Write-Success "Enabled autostart: $Id"
}

function Disable-AutostartInstance {
    param([string]$Id)

    Assert-ClientInstance $Id
    if (Test-ScheduledTasksAvailable) {
        Unregister-ScheduledTask -TaskName (Get-AutostartTaskName $Id) -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    $state = Load-InstanceState $Id
    Set-StateField $state 'autostartEnabled' $false
    Save-InstanceState $Id $state

    Write-Success "Disabled autostart: $Id"
}

function Remove-InstanceFiles {
    param([string]$Id)

    foreach ($path in @(
        (Get-ConfigPath $Id),
        (Get-StatePath $Id),
        (Get-StdoutLogPath $Id),
        (Get-StderrLogPath $Id)
    )) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Delete-Instance {
    param([string]$Id)

    Assert-ClientInstance $Id
    Disable-AutostartInstance $Id
    try {
        Stop-Instance $Id
    }
    catch {
    }
    Remove-InstanceFiles $Id
    Write-Success "Deleted instance: $Id"
}

function Show-Logs {
    param([string]$Id)

    Ensure-Directories

    if ([string]::IsNullOrWhiteSpace($Id)) {
        $files = @(Get-ChildItem -LiteralPath $Script:LogDir -Filter '*.log' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -ExpandProperty FullName)
        if ($files.Count -eq 0) {
            Fail 'No Floo log files found.'
        }

        Get-Content -Path $files -Tail 50 -Wait
        return
    }

    Assert-ClientInstance $Id
    $stdoutPath = Get-StdoutLogPath $Id
    $stderrPath = Get-StderrLogPath $Id

    if (-not (Test-Path -LiteralPath $stdoutPath)) {
        New-Item -ItemType File -Path $stdoutPath -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $stderrPath)) {
        New-Item -ItemType File -Path $stderrPath -Force | Out-Null
    }

    Get-Content -Path @($stdoutPath, $stderrPath) -Tail 50 -Wait
}

function Import-Client {
    param([string[]]$Arguments)

    $preset = ''
    $clientTarget = ''

    foreach ($argument in $Arguments) {
        if ($argument.StartsWith('--preset=')) {
            $preset = Parse-FlagValue -Argument $argument -Prefix '--preset'
        }
        elseif ($argument.StartsWith('--client-target=')) {
            $clientTarget = Parse-FlagValue -Argument $argument -Prefix '--client-target'
        }
        else {
            Fail "Unsupported argument: $argument"
        }
    }

    if ([string]::IsNullOrWhiteSpace($preset) -or [string]::IsNullOrWhiteSpace($clientTarget)) {
        Fail 'Usage: import-client --preset=... --client-target=IP:PORT'
    }

    $presetJsonText = ConvertFrom-Base64Url $preset
    try {
        $presetObject = $presetJsonText | ConvertFrom-Json
    }
    catch {
        Fail 'Could not parse --preset payload.'
    }

    $serverAddr = Get-JsonString -JsonObject $presetObject -Key 'server'
    $cipher = Get-JsonString -JsonObject $presetObject -Key 'cipher'
    $pskValue = Get-JsonString -JsonObject $presetObject -Key 'psk'
    $tokenValue = Get-JsonString -JsonObject $presetObject -Key 'token'
    $proxyMode = Get-JsonString -JsonObject $presetObject -Key 'proxy_mode'
    $mapName = Get-JsonString -JsonObject $presetObject -Key 'map_name'
    $modeValue = Get-JsonString -JsonObject $presetObject -Key 'mode'
    $clientId = Get-JsonString -JsonObject $presetObject -Key 'client_id'

    if ([string]::IsNullOrWhiteSpace($serverAddr) -or [string]::IsNullOrWhiteSpace($mapName) -or [string]::IsNullOrWhiteSpace($clientId)) {
        Fail 'Preset is missing required fields.'
    }
    if ($modeValue -ne '1' -and $modeValue -ne '2') {
        Fail 'Preset mode must be 1 or 2.'
    }
    if ($proxyMode -ne '1' -and $proxyMode -ne '2') {
        Fail 'Preset proxy_mode must be 1 or 2.'
    }
    if (-not (Test-ValidId $clientId)) {
        Fail 'Preset client_id is invalid.'
    }
    if (Test-InstanceExists $clientId) {
        Fail "Instance ID already exists: $clientId"
    }

    Ensure-Directories
    $null = Ensure-ManagedScript
    $null = Ensure-ClientBinary

    $target = Format-Target $clientTarget
    $configPath = Get-ConfigPath $clientId
    $sectionName = if ($proxyMode -eq '1') { 'services' } else { 'reverse_services' }

    $configLines = @(
        '# floo_role = client'
        ('server = "{0}"' -f (Escape-TomlString $serverAddr))
        ('cipher = "{0}"' -f (Escape-TomlString $cipher))
        ('psk = "{0}"' -f (Escape-TomlString $pskValue))
        ('token = "{0}"' -f (Escape-TomlString $tokenValue))
        ''
        ('mode = {0}' -f $modeValue)
        ''
        ('[{0}]' -f $sectionName)
        ('{0} = "{1}"' -f $mapName, (Escape-TomlString $target))
        ''
    )

    Write-Utf8File -Path $configPath -Content ($configLines -join [Environment]::NewLine)

    $state = New-InstanceState $clientId
    Set-StateField $state 'server' $serverAddr
    Set-StateField $state 'mapName' $mapName
    Set-StateField $state 'mode' $modeValue
    Set-StateField $state 'proxyMode' $proxyMode
    Set-StateField $state 'clientTarget' $target
    Save-InstanceState $clientId $state

    Start-Instance $clientId
    Write-Success "Imported client instance: $clientId"
}

function Invoke-NamedInstanceCommand {
    param(
        [string]$Action,
        [string]$TargetId
    )

    if ([string]::IsNullOrWhiteSpace($TargetId)) {
        Fail "$Action requires an instance ID or --all."
    }

    $targetIds = @(Get-ActionTargetIds $TargetId)
    if ($TargetId -eq '--all' -and $targetIds.Count -eq 0) {
        Write-Note 'No managed instances found.'
        return
    }

    foreach ($id in $targetIds) {
        switch ($Action) {
            'start' { Start-Instance $id }
            'stop' { Stop-Instance $id }
            'restart' { Restart-Instance $id }
            'delete' { Delete-Instance $id }
        }
    }
}

function Invoke-AutostartCommand {
    param(
        [string]$Action,
        [string]$TargetId
    )

    if ([string]::IsNullOrWhiteSpace($TargetId)) {
        Fail "$Action-autostart requires an instance ID or --all."
    }

    $targetIds = @(Get-ActionTargetIds $TargetId)
    if ($TargetId -eq '--all' -and $targetIds.Count -eq 0) {
        Write-Note 'No managed instances found.'
        return
    }

    foreach ($id in $targetIds) {
        if ($Action -eq 'enable') {
            Enable-AutostartInstance $id
        }
        else {
            Disable-AutostartInstance $id
        }
    }
}

function Show-Help {
    @'
Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 import-client --preset=... --client-target=IP:PORT
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 start [id or --all]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 stop [id or --all]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 restart [id or --all]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 status [id]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 list
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 logs [id]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 enable-autostart [id or --all]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 disable-autostart [id or --all]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 delete [id or --all]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 help

Notes:
  - Managed config dir: %LOCALAPPDATA%\Floo\configs
  - Managed binary dir: %LOCALAPPDATA%\Floo\bin
  - Log dir: %LOCALAPPDATA%\Floo\logs
  - State dir: %LOCALAPPDATA%\Floo\state
  - This Windows lightweight manager only manages flooc client instances.
  - Presets generated on Linux/macOS can be imported directly.
  - enable-autostart creates a per-user logon scheduled task.
'@ | Write-Host
}

try {
    Ensure-Directories

    if ($args.Count -eq 0) {
        Show-Help
        exit 0
    }

    $command = $args[0]
    $targetId = if ($args.Count -ge 2) { $args[1] } else { $null }
    $remainingArgs = if ($args.Count -gt 1) { @($args | Select-Object -Skip 1) } else { @() }

    switch ($command) {
        'import-client' {
            Import-Client -Arguments $remainingArgs
        }
        'start' {
            Invoke-NamedInstanceCommand -Action 'start' -TargetId $targetId
        }
        'stop' {
            Invoke-NamedInstanceCommand -Action 'stop' -TargetId $targetId
        }
        'restart' {
            Invoke-NamedInstanceCommand -Action 'restart' -TargetId $targetId
        }
        'delete' {
            Invoke-NamedInstanceCommand -Action 'delete' -TargetId $targetId
        }
        'status' {
            if ($args.Count -ge 2) {
                Show-InstanceDetails $targetId
            }
            else {
                Show-Status
            }
        }
        'list' {
            List-Instances
        }
        'logs' {
            if ($args.Count -ge 2) {
                Show-Logs $targetId
            }
            else {
                Show-Logs ''
            }
        }
        'enable-autostart' {
            Invoke-AutostartCommand -Action 'enable' -TargetId $targetId
        }
        'disable-autostart' {
            Invoke-AutostartCommand -Action 'disable' -TargetId $targetId
        }
        'help' {
            Show-Help
        }
        '-h' {
            Show-Help
        }
        '--help' {
            Show-Help
        }
        default {
            Fail "Unsupported command: $command"
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
