<#
.SYNOPSIS
    VBS Readiness - finds every VBScript dependency on this PC before Windows disables VBScript.

.DESCRIPTION
    Read-only scan. Nothing is changed, nothing is sent over the internet.
    1. Finds VBScript files (.vbs .vbe .wsf .wsc .hta) on the fixed drives (or the folders you give).
    2. Finds what launches VBScript: scheduled tasks, Run/RunOnce registry keys, Startup folders,
       Group Policy logon/startup scripts, services.
    3. Analyses each script: COM objects, risky features, conversion traps, security flags,
       risk score (0-100) and migration difficulty.
    4. Writes an HTML report and a CSV file (Desktop by default).

.PARAMETER Path
    Folders to scan instead of all fixed drives (for example a logon-script share \\server\NETLOGON).

.PARAMETER OutDir
    Where to write the report. Default: the folder of this script.

.PARAMETER SkipOutlook
    Do not run the Outlook module (new Outlook readiness: add-ins, VBA macros, PST files).

.PARAMETER SelfTest
    Creates a temporary fake environment (scripts, Outlook add-ins, macros, PST files), scans it,
    checks the results, then deletes everything it created.

.PARAMETER IncludeWindowsFolder
    Also scan C:\Windows (only Microsoft's own scripts are usually there).

.EXAMPLE
    .\VBSReadiness.ps1
    .\VBSReadiness.ps1 -Path '\\fileserver\NETLOGON','D:\Scripts'
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$OutDir,
    [switch]$IncludeWindowsFolder,
    [switch]$SkipOutlook,
    [switch]$SelfTest,
    [int]$MaxFileSizeKB = 2048
)

$ErrorActionPreference = 'Continue'
# Default report folder: the folder of this script (fallbacks: Desktop, then the current folder)
if (-not $OutDir) { $OutDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $OutDir) { $OutDir = [Environment]::GetFolderPath('Desktop') }
if (-not $OutDir) { $OutDir = (Get-Location).Path }
$ToolVersion = '0.3.1'
$ConvertUrl = 'https://apify.com/ali-lamtoueq/vbscript-to-powershell'
$Extensions = @('.vbs', '.vbe', '.wsf', '.wsc', '.hta')
$SkipNames = @('$Recycle.Bin', 'System Volume Information', 'node_modules', '.git', 'WinSxS', 'Config.Msi')
$WindowsDir = $env:SystemRoot.TrimEnd('\')

# ---------------------------------------------------------------- reference tables

# COM objects: risk + PowerShell replacement (short)
$ProgIds = @{
    'scripting.filesystemobject'     = @('low', 'files', 'Native cmdlets: Get-ChildItem, Test-Path, Get-Content, Set-Content, Copy-Item, Remove-Item.')
    'scripting.dictionary'           = @('low', 'data', 'Hashtable @{} or [ordered]@{}.')
    'wscript.shell'                  = @('medium', 'shell', 'Start-Process, Get/Set-ItemProperty (registry), $env:VAR, [Environment]::GetFolderPath().')
    'wscript.network'                = @('low', 'network', '$env:USERNAME / $env:COMPUTERNAME, New-PSDrive -Persist or New-SmbMapping, Add-Printer.')
    'shell.application'              = @('medium', 'shell', 'Expand-Archive / Compress-Archive, Start-Process -Verb; COM still works.')
    'adodb.connection'               = @('medium', 'database', 'System.Data.SqlClient / OleDb / Odbc, or Invoke-Sqlcmd.')
    'adodb.recordset'                = @('medium', 'database', 'DataTable / DataReader.')
    'adodb.command'                  = @('medium', 'database', 'SqlCommand with parameters.')
    'adodb.stream'                   = @('low', 'files', '[System.IO.File]::ReadAllBytes / WriteAllBytes.')
    'msxml2.xmlhttp'                 = @('low', 'http', 'Invoke-RestMethod / Invoke-WebRequest.')
    'msxml2.serverxmlhttp'           = @('low', 'http', 'Invoke-RestMethod / Invoke-WebRequest.')
    'microsoft.xmlhttp'              = @('low', 'http', 'Invoke-RestMethod / Invoke-WebRequest.')
    'winhttp.winhttprequest.5.1'     = @('low', 'http', 'Invoke-RestMethod / Invoke-WebRequest.')
    'msxml2.domdocument'             = @('low', 'xml', '[xml] and Select-Xml.')
    'microsoft.xmldom'               = @('low', 'xml', '[xml] and Select-Xml.')
    'vbscript.regexp'                = @('low', 'text', '-match / -replace, [regex].')
    'excel.application'              = @('medium', 'office', 'COM still works where Excel is installed, or the ImportExcel module.')
    'word.application'               = @('medium', 'office', 'COM still works where Word is installed.')
    'powerpoint.application'         = @('medium', 'office', 'COM still works where PowerPoint is installed.')
    'access.application'             = @('medium', 'office', 'COM where Access is installed, or OleDb (ACE provider).')
    'outlook.application'            = @('high', 'mail', 'Classic Outlook only: the new Outlook has no COM. Use Microsoft Graph (Send-MgUserMail).')
    'cdo.message'                    = @('medium', 'mail', 'Microsoft Graph or MailKit (Send-MailMessage is obsolete).')
    'internetexplorer.application'   = @('high', 'browser', 'IE is retired: Invoke-WebRequest, or Selenium/Playwright with Edge.')
    'msscriptcontrol.scriptcontrol'  = @('high', 'dynamic', 'No equivalent: rewrite the evaluated logic.')
    'scriptpw.password'              = @('high', 'ui', 'Removed from Windows: Read-Host -AsSecureString or Get-Credential.')
    'sapi.spvoice'                   = @('low', 'ui', 'System.Speech.Synthesis.SpeechSynthesizer.')
    'schedule.service'               = @('low', 'system', 'ScheduledTasks module: Register-ScheduledTask.')
    'microsoft.update.session'       = @('medium', 'system', 'COM still works, or the PSWindowsUpdate module.')
    'wbemscripting.swbemlocator'     = @('low', 'wmi', 'Get-CimInstance / Invoke-CimMethod.')
    'adsysteminfo'                   = @('medium', 'directory', 'ActiveDirectory module, [adsi] / [adsisearcher].')
}

# Features: id, regex, weight, risk, blocker, note
$Features = @(
    ,@('on_error_resume_next', '\bon\s+error\s+resume\s+next\b', 8, 'medium', $false, 'Silent error handling: PowerShell needs try/catch and -ErrorAction.')
    ,@('dynamic_code', '\b(execute|executeglobal|eval)\b\s*[("\w]', 25, 'high', $true, 'Execute/Eval builds code at runtime: manual rewrite needed.')
    ,@('getref', '\bgetref\s*\(', 10, 'high', $false, 'GetRef function pointers: rewrite with scriptblocks.')
    ,@('sendkeys', '\.sendkeys\b', 20, 'high', $true, 'SendKeys simulates keystrokes: fragile, no reliable equivalent.')
    ,@('gui_dialogs', '\b(msgbox|inputbox)\b', 4, 'medium', $false, 'MsgBox/InputBox: unattended runs must not wait for input.')
    ,@('registry', '\.reg(read|write|delete)\b', 4, 'medium', $false, 'Registry access: mind 32/64-bit views.')
    ,@('process_launch', '\.(run|exec)\s*[(\s"]', 4, 'medium', $false, 'Launches processes: check quoting and wait/exit codes.')
    ,@('classes', '(?m)^\s*class\s+\w+', 8, 'medium', $false, 'VBScript classes: map to PowerShell classes or PSCustomObject.')
    ,@('array_bounds', '\b(dim|redim)\s+[^\r\n]*?\b\w+\s*\(\s*\d+', 3, 'medium', $false, 'Dim a(n) has n+1 elements: off-by-one risk.')
    ,@('string_indexes', '\b(mid|left|right|instr|instrrev)\s*\(', 4, 'medium', $false, '1-based Mid/InStr vs 0-based Substring/IndexOf.')
    ,@('string_compare', '\bif\b[^\r\n]*[^<>]=\s*"', 3, 'medium', $false, 'VBScript "=" is case-sensitive, PowerShell -eq is not.')
    ,@('dates', '\b(cdate|dateadd|datediff|datepart|formatdatetime|dateserial|datevalue)\s*\(', 4, 'medium', $false, 'Locale-dependent date functions.')
    ,@('byref', '\bbyref\b', 3, 'medium', $false, 'ByRef parameters: use [ref] or return values.')
    ,@('html_application', '<hta:application|<\s*script[^>]+language\s*=\s*"?vbscript', 15, 'high', $true, 'HTA / embedded VBScript: the user interface must be rebuilt.')
    ,@('wsf_job', '<\s*job\b|<\s*package\b', 5, 'medium', $false, 'WSF file: may mix VBScript/JScript and include other files.')
    ,@('asp', '\b(response\.write|request\.(form|querystring)|server\.createobject)', 20, 'high', $true, 'Classic ASP logic: needs a manual web migration.')
)

$Security = @(
    ,@('hardcoded_credential', '\b(password|passwd|pwd|pass|secret|apikey|api_key|token)\s*=\s*"[^"]{3,}"', 'Hard-coded credential (value not shown).')
    ,@('credential_in_connection_string', ';\s*(pwd|password)\s*=', 'Password inside a connection string.')
    ,@('plain_http', '"http://(?!localhost|127\.0\.0\.1)', 'Plain HTTP URL.')
    ,@('download_execute', '(responsebody|savetofile)[\s\S]{0,400}\.(run|exec)\b', 'Downloads then runs a process: review carefully.')
)

$RiskWeight = @{ 'low' = 2; 'medium' = 6; 'high' = 18 }
$Rx = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

# ---------------------------------------------------------------- helpers

function Remove-VbsComments([string]$code) {
    $out = New-Object System.Text.StringBuilder
    foreach ($line in ($code -split "`r?`n")) {
        if ($line -match '^\s*rem(\s|$)') { [void]$out.AppendLine(''); continue }
        $inStr = $false
        $cut = $line.Length
        for ($i = 0; $i -lt $line.Length; $i++) {
            $c = $line[$i]
            if ($c -eq '"') { $inStr = -not $inStr }
            elseif ($c -eq "'" -and -not $inStr) { $cut = $i; break }
        }
        [void]$out.AppendLine($line.Substring(0, $cut))
    }
    return $out.ToString()
}

function Get-MatchCount([string]$pattern, [string]$text) {
    return [regex]::Matches($text, $pattern, $Rx).Count
}

function Find-ScriptFiles([string]$root) {
    $stack = New-Object System.Collections.Stack
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $dir = [string]$stack.Pop()
        $subs = @()
        try { $subs = [System.IO.Directory]::GetDirectories($dir) } catch { }
        foreach ($s in $subs) {
            $name = [System.IO.Path]::GetFileName($s)
            if ($SkipNames -contains $name) { continue }
            if (-not $IncludeWindowsFolder -and $s.TrimEnd('\') -ieq $WindowsDir) { continue }
            try {
                $attr = [System.IO.File]::GetAttributes($s)
                if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            } catch { continue }
            $stack.Push($s)
        }
        $files = @()
        try { $files = [System.IO.Directory]::GetFiles($dir) } catch { }
        foreach ($f in $files) {
            $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
            if ($Extensions -contains $ext -or $ext -eq '.pst') { $f }
        }
    }
}

function Get-ScriptPathsFromCommand([string]$command) {
    $found = @()
    $pattern = '((?:[A-Za-z]:\\|\\\\)[^"<>|*?\r\n]*?\.(?:vbs|vbe|wsf|wsc|hta))\b'
    foreach ($m in [regex]::Matches($command, $pattern, $Rx)) { $found += $m.Groups[1].Value }
    return $found
}

function Test-VbsCommand([string]$command) {
    return ($command -match '(?i)\b(wscript|cscript|mshta)(\.exe)?\b|\.(vbs|vbe|wsf|wsc|hta)\b|vbscript:')
}

function Get-Origin([string]$file) {
    # Libraries, SDKs and developer tools ship sample/test scripts that never run in production
    if ($file -match '(?i)\\(site-packages|node_modules|\.venv|\.uv-cache|Windows Kits|Microsoft Visual Studio|\.nuget)\\') { return 'Developer tool / library' }
    if ($file -match '(?i)^[A-Z]:\\Program Files') { return 'Installed software' }
    if ($file -ieq $WindowsDir -or $file.StartsWith($WindowsDir + '\', [StringComparison]::OrdinalIgnoreCase)) { return 'Windows' }
    return 'Custom'
}

function Invoke-ScriptAnalysis([string]$file) {
    $info = Get-Item -LiteralPath $file -ErrorAction SilentlyContinue
    $result = [ordered]@{
        Path = $file; Origin = (Get-Origin $file); Lines = 0; RiskScore = 0; Difficulty = 'unknown'
        ComObjects = ''; Features = ''; Blockers = ''; Security = ''; LaunchedBy = ''; Note = ''
    }
    if (-not $info) { $result.Note = 'Cannot read file.'; return $result }
    if ($info.Length -gt ($MaxFileSizeKB * 1KB)) { $result.Note = 'File too large, skipped.'; return $result }
    try { $code = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::Default) }
    catch { $result.Note = 'Access denied.'; return $result }

    if ($code -match '#@~\^') {
        $result.Difficulty = 'hard'; $result.RiskScore = 60
        $result.Blockers = 'Encoded VBScript (.vbe): decode and review first.'
        $result.Note = 'Encoded script'
        return $result
    }

    $lines = ($code -split "`r?`n")
    $result.Lines = $lines.Count
    $clean = Remove-VbsComments $code
    $codeLines = @($clean -split "`r?`n" | Where-Object { $_.Trim() -ne '' }).Count
    $score = 0
    $blockers = New-Object System.Collections.ArrayList
    $coms = New-Object System.Collections.ArrayList

    # COM objects
    $seen = @{}
    foreach ($m in [regex]::Matches($clean, '(?:createobject|getobject)\s*\(\s*(?:"[^"]*"\s*,\s*)?"([\w.]+)"', $Rx)) {
        $raw = $m.Groups[1].Value.ToLowerInvariant()
        $key = $raw
        if (-not $ProgIds.ContainsKey($key)) { $key = $raw -replace '\.\d+(\.\d+)?$', '' }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if ($ProgIds.ContainsKey($key)) {
            $risk = $ProgIds[$key][0]
            [void]$coms.Add("$($m.Groups[1].Value) [$risk]")
            if ($risk -eq 'high') { [void]$blockers.Add("$($m.Groups[1].Value): $($ProgIds[$key][2])") }
        } else {
            $risk = 'medium'
            [void]$coms.Add("$($m.Groups[1].Value) [third-party]")
        }
        $score += $RiskWeight[$risk]
    }
    if ((Get-MatchCount 'getobject\s*\(\s*"winmgmts:' $clean) -gt 0) { [void]$coms.Add('winmgmts: (WMI) [low]'); $score += 2 }
    if ((Get-MatchCount 'getobject\s*\(\s*"ldap://' $clean) -gt 0) { [void]$coms.Add('LDAP:// [medium]'); $score += 6 }

    # Features
    $feats = New-Object System.Collections.ArrayList
    foreach ($f in $Features) {
        $target = $clean
        if ($f[0] -eq 'html_application' -or $f[0] -eq 'wsf_job') { $target = $code }
        $n = Get-MatchCount $f[1] $target
        if ($n -gt 0) {
            [void]$feats.Add("$($f[0]) x$n")
            $score += $f[2]
            if ($f[4]) { [void]$blockers.Add($f[5]) }
        }
    }

    # Security
    $sec = New-Object System.Collections.ArrayList
    foreach ($s in $Security) {
        if ((Get-MatchCount $s[1] $clean) -gt 0) { [void]$sec.Add($s[2]) }
    }

    $score += [Math]::Min(20, [Math]::Floor($codeLines / 50) * 2)
    $score = [Math]::Min(100, $score)
    $difficulty = 'easy'
    if ($score -ge 20) { $difficulty = 'medium' }
    if ($blockers.Count -gt 0 -or $score -ge 50) { $difficulty = 'hard' }

    $result.RiskScore = $score
    $result.Difficulty = $difficulty
    $result.ComObjects = ($coms -join '; ')
    $result.Features = ($feats -join '; ')
    $result.Blockers = ($blockers -join ' | ')
    $result.Security = ($sec -join ' | ')
    return $result
}

# ---------------------------------------------------------------- Outlook module (new Outlook readiness)
# The new Outlook for Windows does not run COM/VSTO add-ins or VBA macros. This module lists what will
# stop working: add-ins, VBA macro projects, PST files, Outlook templates, and which Outlook is installed.

$script:TestUserRoot = $null
$AddinRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins',
    'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\Outlook\Addins',
    'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Office\Outlook\Addins'
)
# Add-ins of every user whose registry hive is loaded (includes the current user)
foreach ($hive in (Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
    if ($hive.PSChildName -match '^S-1-5-21-[\d-]+$') {
        $AddinRoots += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Office\Outlook\Addins"
    }
}

# Microsoft's own add-ins: their features exist in the new Outlook or are no longer needed
$MicrosoftAddins = @('TeamsAddin.FastConnect', 'OscAddin.Connect', 'UmOutlookAddin.FormRegionAddin', 'ColleagueImport.ColleagueImportAddin',
    'OneNote.OutlookAddin', 'Microsoft.VbaAddinForOutlook.1', 'AccessAddin.DC', 'Search.OutlookToastNotifier', 'OutlookChangeNotifier.Connect',
    'Microsoft.Outlook.SocialConnector.Connector', 'Microsoft.Outlook.SocialConnector.Connector.1', 'Microsoft.OutlookAutomatedClient')

function Get-UserProfileFolders {
    if ($script:TestUserRoot) { return @(Get-ChildItem -LiteralPath $script:TestUserRoot -Directory -ErrorAction SilentlyContinue) }
    $usersRoot = Split-Path -Parent $env:PUBLIC
    return @(Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { @('Public', 'Default', 'Default User', 'All Users') -notcontains $_.Name })
}

function Get-OutlookInventory([string[]]$knownPst) {
    $inv = [ordered]@{ Classic = 'not installed'; New = 'not installed'; Addins = @(); Macros = @(); Pst = @(); Templates = 0 }

    # Which Outlook is installed
    $app = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE' -ErrorAction SilentlyContinue
    if ($app -and $app.'(default)' -and (Test-Path -LiteralPath $app.'(default)' -ErrorAction SilentlyContinue)) {
        $ver = (Get-Item -LiteralPath $app.'(default)').VersionInfo.ProductVersion
        $inv.Classic = "installed (version $ver)"
    }
    $pkg = $null
    try { $pkg = Get-AppxPackage -AllUsers -Name 'Microsoft.OutlookForWindows' -ErrorAction Stop | Select-Object -First 1 } catch { }
    if (-not $pkg) { try { $pkg = Get-AppxPackage -Name 'Microsoft.OutlookForWindows' -ErrorAction Stop | Select-Object -First 1 } catch { } }
    if ($pkg) { $inv.New = "installed (version $($pkg.Version))" }

    # COM / VSTO add-ins
    $byId = @{}
    foreach ($root in $AddinRoots) {
        foreach ($key in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            $id = $key.PSChildName
            if ($byId.ContainsKey($id)) { continue }
            $lb = $null
            if ($p -and $null -ne $p.LoadBehavior) { $lb = [int]$p.LoadBehavior }
            $active = ($lb -eq 3 -or $lb -eq 9 -or $lb -eq 16)
            $name = $id
            if ($p -and $p.FriendlyName) { $name = [string]$p.FriendlyName }
            $isMs = ($MicrosoftAddins -contains $id)
            $risk = 'high'
            $advice = 'Not supported in the new Outlook. Ask the vendor for a web add-in (Office Add-in) version, or replace the workflow.'
            if ($isMs) { $risk = 'low'; $advice = 'Microsoft add-in: the feature is built into the new Outlook or no longer needed.' }
            $byId[$id] = [pscustomobject]@{ ProgId = $id; Name = $name; Active = $active; LoadBehavior = $lb; Publisher = $(if ($isMs) { 'Microsoft' } else { 'Third-party / custom' }); Risk = $risk; Advice = $advice; Registry = $root }
        }
    }
    $inv.Addins = @($byId.Values | Sort-Object @{ Expression = { if ($_.Risk -eq 'high') { 0 } else { 1 } } }, Name)

    # VBA macro projects, PST files and templates in every user profile
    $pstList = New-Object System.Collections.ArrayList
    foreach ($k in $knownPst) { [void]$pstList.Add($k) }
    foreach ($prof in (Get-UserProfileFolders)) {
        $otm = Join-Path $prof.FullName 'AppData\Roaming\Microsoft\Outlook\VbaProject.OTM'
        if (Test-Path -LiteralPath $otm -ErrorAction SilentlyContinue) {
            $fi = Get-Item -LiteralPath $otm
            $inv.Macros += [pscustomobject]@{ User = $prof.Name; Path = $otm; SizeKB = [Math]::Round($fi.Length / 1KB, 1); Modified = $fi.LastWriteTime.ToString('yyyy-MM-dd') }
        }
        foreach ($sub in @('Documents\Outlook Files', 'AppData\Local\Microsoft\Outlook', 'Documents')) {
            $dir = Join-Path $prof.FullName $sub
            if (-not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter '*.pst' -File -ErrorAction SilentlyContinue)) {
                if (-not ($pstList -contains $f.FullName)) { [void]$pstList.Add($f.FullName) }
            }
        }
        $tpl = Join-Path $prof.FullName 'AppData\Roaming\Microsoft\Templates'
        if (Test-Path -LiteralPath $tpl -ErrorAction SilentlyContinue) { $inv.Templates += @(Get-ChildItem -LiteralPath $tpl -Filter '*.oft' -File -ErrorAction SilentlyContinue).Count }
    }
    foreach ($p in $pstList) {
        $fi = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
        if ($fi) { $inv.Pst += [pscustomobject]@{ Path = $fi.FullName; SizeMB = [Math]::Round($fi.Length / 1MB, 1); Modified = $fi.LastWriteTime.ToString('yyyy-MM-dd') } }
    }
    return [pscustomobject]$inv
}

# ---------------------------------------------------------------- self-test (fake Outlook environment, removed afterwards)
$SelfTestRoot = $null
$SelfTestReg = 'HKCU:\Software\VBSReadiness-SelfTest'
if ($SelfTest) {
    Write-Host 'SELF-TEST: creating a temporary fake Outlook environment...' -ForegroundColor Yellow
    $SelfTestRoot = Join-Path $env:TEMP ('VBSReadiness-SelfTest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $u = Join-Path $SelfTestRoot 'Users\TestUser'
    foreach ($d in @('AppData\Roaming\Microsoft\Outlook', 'AppData\Roaming\Microsoft\Templates', 'Documents\Outlook Files', 'Scripts')) {
        New-Item -ItemType Directory -Path (Join-Path $u $d) -Force | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $u 'AppData\Roaming\Microsoft\Outlook\VbaProject.OTM') -Value ('x' * 4096)
    Set-Content -LiteralPath (Join-Path $u 'AppData\Roaming\Microsoft\Templates\Invoice.oft') -Value 'TEST'
    Set-Content -LiteralPath (Join-Path $u 'Documents\Outlook Files\archive-2019.pst') -Value 'TEST'
    Set-Content -LiteralPath (Join-Path $u 'Documents\Outlook Files\old-mails.pst') -Value 'TEST'
    Set-Content -LiteralPath (Join-Path $u 'Scripts\send-report.vbs') -Value @(
        'On Error Resume Next', 'Set ol = CreateObject("Outlook.Application")', 'Set mail = ol.CreateItem(0)',
        'mail.To = "boss@example.com"', 'mail.Send', 'Execute "x = 1"')
    $addinBase = "$SelfTestReg\Outlook\Addins"
    New-Item -Path "$addinBase\Contoso.CrmConnector" -Force | Out-Null
    New-ItemProperty -Path "$addinBase\Contoso.CrmConnector" -Name 'FriendlyName' -Value 'Contoso CRM Connector' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$addinBase\Contoso.CrmConnector" -Name 'LoadBehavior' -Value 3 -PropertyType DWord -Force | Out-Null
    New-Item -Path "$addinBase\TeamsAddin.FastConnect" -Force | Out-Null
    New-ItemProperty -Path "$addinBase\TeamsAddin.FastConnect" -Name 'FriendlyName' -Value 'Microsoft Teams Meeting Add-in' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$addinBase\TeamsAddin.FastConnect" -Name 'LoadBehavior' -Value 3 -PropertyType DWord -Force | Out-Null
    $Path = @($SelfTestRoot)
    $script:TestUserRoot = Join-Path $SelfTestRoot 'Users'
    $AddinRoots = @($addinBase)
}

try {

# ---------------------------------------------------------------- 1. launchers

Write-Host "VBS Readiness $ToolVersion - read-only scan, nothing is changed or sent." -ForegroundColor Cyan
$launchers = New-Object System.Collections.ArrayList

function Add-Launcher([string]$kind, [string]$name, [string]$command) {
    [void]$launchers.Add([pscustomobject]@{ Kind = $kind; Name = $name; Command = $command; Scripts = (Get-ScriptPathsFromCommand $command) })
}

Write-Host '[1/4] Scheduled tasks...'
try {
    foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
        foreach ($a in $t.Actions) {
            $cmd = ("$($a.Execute) $($a.Arguments)").Trim()
            if ($cmd -and (Test-VbsCommand $cmd)) { Add-Launcher 'Scheduled task' ($t.TaskPath + $t.TaskName) $cmd }
        }
    }
} catch { Write-Host '      (scheduled tasks unavailable on this system)' -ForegroundColor DarkYellow }

Write-Host '[2/4] Registry Run keys, Startup folders, Group Policy scripts, services...'
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
    $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $val = [string]$p.Value
        if (Test-VbsCommand $val) { Add-Launcher 'Registry Run key' "$k\$($p.Name)" $val }
    }
}

$shell = $null
try { $shell = New-Object -ComObject WScript.Shell } catch { }
$startupFolders = @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))
# Startup folders of every user profile (the script may run under another administrator account)
$usersRoot = Split-Path -Parent $env:PUBLIC
foreach ($prof in (Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue)) {
    $startupFolders += (Join-Path $prof.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
}
$startupFolders = @($startupFolders | Where-Object { $_ } | Select-Object -Unique)
foreach ($folder in $startupFolders) {
    if (-not $folder -or -not (Test-Path -LiteralPath $folder -ErrorAction SilentlyContinue)) { continue }
    foreach ($item in (Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue)) {
        $cmd = $item.FullName
        if ($item.Extension -ieq '.lnk' -and $shell) {
            try { $lnk = $shell.CreateShortcut($item.FullName); $cmd = ("$($lnk.TargetPath) $($lnk.Arguments)").Trim() } catch { }
        }
        if (Test-VbsCommand $cmd) { Add-Launcher 'Startup folder' $item.FullName $cmd }
    }
}

foreach ($gp in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts')) {
    foreach ($key in (Get-ChildItem -Path $gp -Recurse -ErrorAction SilentlyContinue)) {
        $s = (Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue).Script
        if ($s -and (Test-VbsCommand $s)) { Add-Launcher 'Group Policy script' $key.Name $s }
    }
}

try {
    foreach ($svc in (Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        if ($svc.PathName -and (Test-VbsCommand $svc.PathName)) { Add-Launcher 'Service' $svc.Name $svc.PathName }
    }
} catch { }

# VBScript Feature on Demand status (Windows 11 24H2+, needs administrator rights)
$fodStatus = 'unknown (run as administrator to check)'
try {
    $cap = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like 'VBSCRIPT*' } | Select-Object -First 1
    if ($cap) { $fodStatus = "$($cap.State) ($($cap.Name))" } else { $fodStatus = 'not an optional feature on this Windows version (built in)' }
} catch { }

# ---------------------------------------------------------------- 2. files

Write-Host '[3/4] Searching for VBScript files (this can take a few minutes)...'
$roots = @()
if ($Path) { $roots = $Path }
else {
    $roots = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName })
}
$files = New-Object System.Collections.ArrayList
$pstFound = New-Object System.Collections.ArrayList
foreach ($r in $roots) {
    Write-Host "      $r"
    foreach ($f in (Find-ScriptFiles $r)) {
        if ($f.ToLowerInvariant().EndsWith('.pst')) { [void]$pstFound.Add($f) } else { [void]$files.Add($f) }
    }
}
# Scripts referenced by launchers but stored elsewhere (network shares...)
foreach ($l in $launchers) {
    foreach ($s in $l.Scripts) {
        if (-not ($files -contains $s) -and (Test-Path -LiteralPath $s -ErrorAction SilentlyContinue)) { [void]$files.Add($s) }
    }
}

Write-Host "[4/4] Analysing $($files.Count) script(s)..."
$results = New-Object System.Collections.ArrayList
$i = 0
foreach ($f in $files) {
    $i++
    if ($files.Count -gt 0) { Write-Progress -Activity 'Analysing VBScript files' -Status $f -PercentComplete (100 * $i / $files.Count) }
    $r = Invoke-ScriptAnalysis $f
    $by = @($launchers | Where-Object { $_.Scripts -contains $f } | ForEach-Object { "$($_.Kind): $($_.Name)" })
    $r.LaunchedBy = ($by -join ' | ')
    [void]$results.Add([pscustomobject]$r)
}
Write-Progress -Activity 'Analysing VBScript files' -Completed

$missing = New-Object System.Collections.ArrayList
foreach ($l in $launchers) {
    if ($l.Scripts.Count -eq 0) { [void]$missing.Add($l); continue }
    foreach ($s in $l.Scripts) { if (-not ($files -contains $s)) { [void]$missing.Add($l); break } }
}

$outlook = $null
if (-not $SkipOutlook) {
    Write-Host 'Outlook module: add-ins, VBA macros, PST files...'
    $outlook = Get-OutlookInventory @($pstFound)
}

# ---------------------------------------------------------------- 3. report

if (-not (Test-Path -LiteralPath $OutDir -ErrorAction SilentlyContinue)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$csvPath = Join-Path $OutDir "VBSReadiness-$env:COMPUTERNAME-$stamp.csv"
$htmlPath = Join-Path $OutDir "VBSReadiness-$env:COMPUTERNAME-$stamp.html"
$results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
if ($outlook -and @($outlook.Addins).Count -gt 0) {
    $outlook.Addins | Export-Csv -LiteralPath (Join-Path $OutDir "VBSReadiness-$env:COMPUTERNAME-$stamp-outlook-addins.csv") -NoTypeInformation -Encoding UTF8
}

function ConvertTo-HtmlText([string]$s) { return [System.Net.WebUtility]::HtmlEncode($s) }

$custom = @($results | Where-Object { $_.Origin -eq 'Custom' })
$active = @($results | Where-Object { $_.LaunchedBy -ne '' })
$hard = @($results | Where-Object { $_.Difficulty -eq 'hard' })
$sec = @($results | Where-Object { $_.Security -ne '' })

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append(@"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>VBS Readiness - $(ConvertTo-HtmlText $env:COMPUTERNAME)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2328;background:#f6f8fa}
h1{margin:0 0 4px}h2{margin-top:28px}.muted{color:#656d76}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.card{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:12px 16px;min-width:150px}
.card b{display:block;font-size:26px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}th,td{border:1px solid #d0d7de;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#eef1f4}.easy{color:#1a7f37;font-weight:600}.medium{color:#9a6700;font-weight:600}.hard{color:#cf222e;font-weight:600}
code{font-size:12px;word-break:break-all}.box{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:12px 16px}
</style></head><body>
<h1>VBS Readiness report</h1>
<div class="muted">Computer: <b>$(ConvertTo-HtmlText $env:COMPUTERNAME)</b> &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; VBS Readiness $ToolVersion &middot; read-only scan</div>
<div class="box" style="margin-top:12px">Microsoft is phasing out VBScript: enabled by default as a Feature on Demand until about 2026-2027, then <b>disabled by default</b>, then removed from future Windows releases.
VBScript optional feature on this PC: <b>$(ConvertTo-HtmlText $fodStatus)</b></div>
<div class="cards">
<div class="card"><b>$($results.Count)</b>VBScript files found</div>
<div class="card"><b>$($custom.Count)</b>custom scripts (not Windows / installed software)</div>
<div class="card"><b>$($launchers.Count)</b>automatic launchers</div>
<div class="card"><b>$($active.Count)</b>scripts launched automatically</div>
<div class="card"><b class="hard">$($hard.Count)</b>hard to migrate</div>
<div class="card"><b class="hard">$($sec.Count)</b>with security flags</div>
</div>
"@)

[void]$sb.Append('<h2>What launches VBScript automatically</h2>')
if ($launchers.Count -eq 0) { [void]$sb.Append('<p class="muted">Nothing found: no scheduled task, Run key, Startup item, Group Policy script or service uses VBScript on this PC.</p>') }
else {
    [void]$sb.Append('<table><tr><th>Type</th><th>Name</th><th>Command</th></tr>')
    foreach ($l in $launchers) { [void]$sb.Append("<tr><td>$(ConvertTo-HtmlText $l.Kind)</td><td>$(ConvertTo-HtmlText $l.Name)</td><td><code>$(ConvertTo-HtmlText $l.Command)</code></td></tr>") }
    [void]$sb.Append('</table>')
    if ($missing.Count -gt 0) { [void]$sb.Append("<p class='muted'>$($missing.Count) launcher(s) point to scripts that could not be read here (network share or missing file). Re-run with -Path pointing to that location.</p>") }
}

[void]$sb.Append('<h2>VBScript files</h2>')
if ($results.Count -eq 0) { [void]$sb.Append('<p class="muted">No VBScript file found in the scanned locations.</p>') }
else {
    [void]$sb.Append('<table><tr><th>File</th><th>Origin</th><th>Launched by</th><th>Lines</th><th>Difficulty</th><th>Risk</th><th>COM objects</th><th>Blockers</th><th>Security</th></tr>')
    $order = @{ 'hard' = 0; 'medium' = 1; 'easy' = 2; 'unknown' = 3 }
    $sorted = $results | Sort-Object @{ Expression = { if ($_.Origin -eq 'Custom') { 0 } else { 1 } } }, @{ Expression = { $order[$_.Difficulty] } }, @{ Expression = { $_.RiskScore }; Descending = $true }
    foreach ($r in $sorted) {
        $note = ''
        if ($r.Note) { $note = "<br><span class='muted'>$(ConvertTo-HtmlText $r.Note)</span>" }
        [void]$sb.Append("<tr><td><code>$(ConvertTo-HtmlText $r.Path)</code>$note</td><td>$(ConvertTo-HtmlText $r.Origin)</td><td>$(ConvertTo-HtmlText $r.LaunchedBy)</td><td>$($r.Lines)</td><td class='$($r.Difficulty)'>$($r.Difficulty)</td><td>$($r.RiskScore)</td><td>$(ConvertTo-HtmlText $r.ComObjects)</td><td>$(ConvertTo-HtmlText $r.Blockers)</td><td>$(ConvertTo-HtmlText $r.Security)</td></tr>")
    }
    [void]$sb.Append('</table>')
}

[void]$sb.Append('<h2>New Outlook readiness</h2>')
if (-not $outlook) { [void]$sb.Append('<p class="muted">Outlook module skipped (-SkipOutlook).</p>') }
else {
    $thirdParty = @($outlook.Addins | Where-Object { $_.Risk -eq 'high' })
    [void]$sb.Append("<div class='box'>The new Outlook for Windows does not run COM/VSTO add-ins or VBA macros. Classic Outlook: <b>$(ConvertTo-HtmlText $outlook.Classic)</b> &middot; New Outlook: <b>$(ConvertTo-HtmlText $outlook.New)</b></div>")
    [void]$sb.Append("<div class='cards'><div class='card'><b class='hard'>$($thirdParty.Count)</b>third-party / custom add-ins</div><div class='card'><b>$(@($outlook.Addins).Count)</b>add-ins in total</div><div class='card'><b class='hard'>$(@($outlook.Macros).Count)</b>users with VBA macros</div><div class='card'><b>$(@($outlook.Pst).Count)</b>PST files</div><div class='card'><b>$($outlook.Templates)</b>Outlook templates (.oft)</div></div>")
    if (@($outlook.Addins).Count -gt 0) {
        [void]$sb.Append('<table><tr><th>Add-in</th><th>ProgID</th><th>Publisher</th><th>Active</th><th>Impact</th></tr>')
        foreach ($a in $outlook.Addins) { [void]$sb.Append("<tr><td>$(ConvertTo-HtmlText $a.Name)</td><td><code>$(ConvertTo-HtmlText $a.ProgId)</code></td><td>$(ConvertTo-HtmlText $a.Publisher)</td><td>$(if ($a.Active) { 'yes' } else { 'no' })</td><td class='$(if ($a.Risk -eq 'high') { 'hard' } else { 'easy' })'>$(ConvertTo-HtmlText $a.Advice)</td></tr>") }
        [void]$sb.Append('</table>')
    }
    if (@($outlook.Macros).Count -gt 0) {
        [void]$sb.Append('<h3>VBA macros (VbaProject.OTM)</h3><table><tr><th>User</th><th>File</th><th>Size (KB)</th><th>Last modified</th></tr>')
        foreach ($m in $outlook.Macros) { [void]$sb.Append("<tr><td>$(ConvertTo-HtmlText $m.User)</td><td><code>$(ConvertTo-HtmlText $m.Path)</code></td><td>$($m.SizeKB)</td><td>$($m.Modified)</td></tr>") }
        [void]$sb.Append('</table><p class="muted">VBA macros do not run in the new Outlook: rewrite them as Power Automate flows, Office Add-ins or PowerShell + Microsoft Graph. Rules using "Run a script" depend on these macros.</p>')
    }
    if (@($outlook.Pst).Count -gt 0) {
        [void]$sb.Append('<h3>PST files</h3><table><tr><th>File</th><th>Size (MB)</th><th>Last modified</th></tr>')
        foreach ($p in $outlook.Pst) { [void]$sb.Append("<tr><td><code>$(ConvertTo-HtmlText $p.Path)</code></td><td>$($p.SizeMB)</td><td>$($p.Modified)</td></tr>") }
        [void]$sb.Append('</table><p class="muted">Check how each PST is used: importing archives into the mailbox or an online archive avoids depending on local PST support.</p>')
    }
    [void]$sb.Append('<p class="muted">Not covered automatically: client-only rules (they need classic Outlook to be read). Export them from classic Outlook (File &gt; Manage Rules &amp; Alerts) and check rules that run a script, play a sound or move mail to a PST.</p>')
}

[void]$sb.Append(@"
<h2>Next steps</h2>
<ol>
<li>Start with <b>custom scripts that are launched automatically</b>: they break silently when VBScript is disabled.</li>
<li>Scripts under Program Files belong to installed software: check that the vendor has an update. Scripts inside developer tools and libraries (SDK samples, Python packages...) are usually samples or tests and can be ignored.</li>
<li>Convert the others to PowerShell. Online converter with a review checklist: <a href="$ConvertUrl">$ConvertUrl</a></li>
<li>Remove hard-coded passwords before converting or sharing any script.</li>
</ol>
<p class="muted">CSV export: $(ConvertTo-HtmlText $csvPath)</p>
</body></html>
"@)

[System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

Write-Host ''
Write-Host "Done: $($results.Count) VBScript file(s), $($launchers.Count) launcher(s), $($hard.Count) hard to migrate." -ForegroundColor Green
Write-Host "Report: $htmlPath"
Write-Host "CSV:    $csvPath"
try { Start-Process $htmlPath } catch { }

if ($SelfTest) {
    $checks = @(
        @('script found and rated hard', (@($results | Where-Object { $_.Path -like '*send-report.vbs' -and $_.Difficulty -eq 'hard' }).Count -eq 1)),
        @('Outlook COM object flagged as blocker', (@($results | Where-Object { $_.Blockers -like '*Outlook.Application*' }).Count -ge 1)),
        @('2 add-ins found', (@($outlook.Addins).Count -eq 2)),
        @('third-party add-in active and high risk', (@($outlook.Addins | Where-Object { $_.ProgId -eq 'Contoso.CrmConnector' -and $_.Active -and $_.Risk -eq 'high' }).Count -eq 1)),
        @('Microsoft add-in classified low risk', (@($outlook.Addins | Where-Object { $_.ProgId -eq 'TeamsAddin.FastConnect' -and $_.Risk -eq 'low' }).Count -eq 1)),
        @('VBA macro project found', (@($outlook.Macros).Count -eq 1)),
        @('2 PST files found (no duplicates)', (@($outlook.Pst).Count -eq 2)),
        @('1 Outlook template found', ($outlook.Templates -eq 1)),
        @('HTML report written', (Test-Path -LiteralPath $htmlPath -ErrorAction SilentlyContinue))
    )
    $failed = 0
    Write-Host ''
    foreach ($c in $checks) {
        if ($c[1]) { Write-Host "  PASS  $($c[0])" -ForegroundColor Green } else { Write-Host "  FAIL  $($c[0])" -ForegroundColor Red; $failed++ }
    }
    if ($failed -eq 0) { Write-Host 'SELF-TEST PASSED' -ForegroundColor Green } else { Write-Host "SELF-TEST FAILED ($failed check(s))" -ForegroundColor Red }
}

} finally {
    if ($SelfTest) {
        if ($SelfTestRoot -and (Test-Path -LiteralPath $SelfTestRoot -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $SelfTestRoot -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $SelfTestReg -ErrorAction SilentlyContinue) { Remove-Item -LiteralPath $SelfTestReg -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Host 'SELF-TEST: temporary files and registry keys removed.' -ForegroundColor Yellow
    }
}
