#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    Write-Error 'floo-windows.ps1 仅支持在 Windows 上运行。'
    exit 1
}

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
        default { Fail '无效的 base64url 预设。' }
    }

    $bytes = [Convert]::FromBase64String($normalized)
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Get-JsonString {
    param(
        [object]$JsonObject,
        [string]$Key
    )

    $property = $JsonObject.PSObject.Properties[$Key]
    if ($null -eq $property) {
        Fail "预设缺少字段：$Key"
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
        Fail "未知实例 ID：$Id"
    }

    $kind = Get-ConfigKindValue (Get-ConfigPath $Id)
    if ($kind -ne 'client') {
        Fail "Windows 轻量版当前只支持客户端实例：$Id"
    }
}

function Get-ClientBinarySource {
    $candidates = @(
        (Join-Path $Script:ScriptDir 'flooc.exe'),
        (Join-Path $Script:ScriptDir 'zig-out\bin\flooc.exe'),
        (Join-Path $Script:ScriptDir 'zig-out\release\x86_64-windows\flooc.exe'),
        $Script:ManagedClientBin
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
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
    $source = Get-ClientBinarySource
    if ([string]::IsNullOrWhiteSpace($source)) {
        Fail '未找到 flooc.exe。请将 flooc.exe 放在 floo-windows.ps1 同目录，或从 Windows release zip 运行。'
    }

    if (-not (Test-Path -LiteralPath $Script:ManagedClientBin) -or $source -ne $Script:ManagedClientBin) {
        Copy-Item -LiteralPath $source -Destination $Script:ManagedClientBin -Force
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
        return '运行中'
    }

    return '已停止'
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
        Write-Host "  flooc：已安装 ($Script:ManagedClientBin)"
    }
    else {
        Write-Host '  flooc：尚未安装'
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
        Write-Host "  [$Id] 客户端 状态=$StateText 进程=$Pid 自启动=$Autostart"
        return
    }

    Write-Host "  [$Id] 客户端 状态=$StateText 自启动=$Autostart"
}

function Show-Status {
    Ensure-Directories

    Write-Host '========================================'
    Write-Host ' 受管二进制'
    Show-BinaryStatus
    Write-Host ''
    Write-Host ' 实例列表'

    $instanceIds = @(Get-InstanceIds)
    if ($instanceIds.Count -eq 0) {
        Write-Host '  暂无实例'
        Write-Host '========================================'
        return
    }

    foreach ($id in $instanceIds) {
        $state = Load-InstanceState $id
        $stateText = Get-InstanceStateText -State $state
        $pid = if ($null -ne $state.pid) { [string]$state.pid } else { '' }
        $autostart = if (Test-AutostartEnabled $id) { 'on' } else { 'off' }
        Write-InstanceSummary -Id $id -StateText $stateText -Pid $pid -Autostart $autostart
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

    Write-Host "实例 ID：$Id"
    Write-Host '类型：client'
    if ([string]::IsNullOrWhiteSpace($modeValue)) {
        Write-Host '模式：<未设置>'
    }
    else {
        Write-Host "模式：$modeValue"
    }
    Write-Host "标签：$(Get-InstanceLabel $Id)"
    Write-Host "状态：$stateText"
    if ($null -ne $state.pid) {
        Write-Host "进程 ID：$($state.pid)"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$state.lastStartTime)) {
        Write-Host "上次启动：$($state.lastStartTime)"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$state.lastStopTime)) {
        Write-Host "上次停止：$($state.lastStopTime)"
    }
    Write-Host "登录自启动：$autostart"
    Write-Host "配置文件：$(Get-ConfigPath $Id)"
    Write-Host "状态文件：$(Get-StatePath $Id)"
    Write-Host "标准输出日志：$(Get-StdoutLogPath $Id)"
    Write-Host "标准错误日志：$(Get-StderrLogPath $Id)"
    Write-Host "计划任务：$(Get-AutostartTaskName $Id)"
}

function List-Instances {
    Ensure-Directories
    $instanceIds = @(Get-InstanceIds)
    if ($instanceIds.Count -eq 0) {
        Write-Note '未找到任何受管实例。'
        return
    }

    foreach ($id in $instanceIds) {
        $state = Load-InstanceState $id
        $stateText = Get-InstanceStateText -State $state
        $pid = if ($null -ne $state.pid) { [string]$state.pid } else { '' }
        $autostart = if (Test-AutostartEnabled $id) { 'on' } else { 'off' }
        Write-InstanceSummary -Id $id -StateText $stateText -Pid $pid -Autostart $autostart
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
        Write-Note "实例已在运行：$Id"
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

    Write-Success "已启动实例：$Id"
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
        Write-Note "实例已经停止：$Id"
        return
    }

    Stop-Process -Id $process.Id -ErrorAction Stop
    Wait-Process -Id $process.Id -Timeout 5 -ErrorAction SilentlyContinue

    Set-StateField $state 'pid' $null
    Set-StateField $state 'lastStopTime' ([DateTime]::UtcNow.ToString('o'))
    Save-InstanceState $Id $state

    Write-Success "已停止实例：$Id"
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
        Fail '当前系统不可用 ScheduledTasks 模块，无法启用登录自启动。'
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

    Write-Success "已启用登录自启动：$Id"
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

    Write-Success "已禁用登录自启动：$Id"
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
    Write-Success "已删除实例：$Id"
}

function Show-Logs {
    param([string]$Id)

    Ensure-Directories

    if ([string]::IsNullOrWhiteSpace($Id)) {
        $files = @(Get-ChildItem -LiteralPath $Script:LogDir -Filter '*.log' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -ExpandProperty FullName)
        if ($files.Count -eq 0) {
            Fail '未找到 Floo 日志文件。'
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
            Fail "不支持的参数：$argument"
        }
    }

    if ([string]::IsNullOrWhiteSpace($preset) -or [string]::IsNullOrWhiteSpace($clientTarget)) {
        Fail '用法：import-client --preset=... --client-target=IP:PORT'
    }

    $presetJsonText = ConvertFrom-Base64Url $preset
    try {
        $presetObject = $presetJsonText | ConvertFrom-Json
    }
    catch {
        Fail '无法解析 --preset 内容。'
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
        Fail '预设缺少必要字段。'
    }
    if ($modeValue -ne '1' -and $modeValue -ne '2') {
        Fail '预设中的 mode 只能是 1 或 2。'
    }
    if ($proxyMode -ne '1' -and $proxyMode -ne '2') {
        Fail '预设中的 proxy_mode 只能是 1 或 2。'
    }
    if (-not (Test-ValidId $clientId)) {
        Fail '预设中的 client_id 不合法。'
    }
    if (Test-InstanceExists $clientId) {
        Fail "实例 ID 已存在：$clientId"
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
    Write-Success "客户端实例已导入并启动：$clientId"
}

function Invoke-NamedInstanceCommand {
    param(
        [string]$Action,
        [string]$TargetId
    )

    if ([string]::IsNullOrWhiteSpace($TargetId)) {
        Fail "$Action 需要提供实例 ID 或 --all。"
    }

    $targetIds = @(Get-ActionTargetIds $TargetId)
    if ($TargetId -eq '--all' -and $targetIds.Count -eq 0) {
        Write-Note '未找到任何受管实例。'
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
        Fail "$Action-autostart 需要提供实例 ID 或 --all。"
    }

    $targetIds = @(Get-ActionTargetIds $TargetId)
    if ($TargetId -eq '--all' -and $targetIds.Count -eq 0) {
        Write-Note '未找到任何受管实例。'
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
用法：
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 import-client --preset=... --client-target=IP:PORT
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 start <id|--all>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 stop <id|--all>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 restart <id|--all>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 status [id]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 list
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 logs [id]
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 enable-autostart <id|--all>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 disable-autostart <id|--all>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 delete <id|--all>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\floo-windows.ps1 help

说明：
  - 受管配置目录：%LOCALAPPDATA%\Floo\configs
  - 受管二进制目录：%LOCALAPPDATA%\Floo\bin
  - 日志目录：%LOCALAPPDATA%\Floo\logs
  - 状态目录：%LOCALAPPDATA%\Floo\state
  - Windows 轻量版当前仅管理 flooc 客户端实例。
  - Linux/macOS 生成的 --preset 可直接用于 import-client。
  - enable-autostart 会创建当前用户登录触发的计划任务。
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
            Fail "不支持的命令：$command"
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
