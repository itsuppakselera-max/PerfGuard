#requires -Version 3.0
<#
    PerfGuard - Diagnose & relieve 100% CPU / RAM on Windows.

    Modes:
      status   Snapshot: who is eating CPU and RAM right now.
      watch    Monitor and LOG spikes (no action taken). Answers "what caused the 100%".
      auto     Monitor and automatically apply relief when thresholds are crossed.
      relieve  Apply relief once, right now.
      restore  Undo everything (resume suspended, restore priorities, clear EcoQoS).
      report   Summarise the spike log: your top repeat offenders.
      install  Register a scheduled task so 'auto' runs at logon.
      uninstall  Remove that scheduled task.

    Nothing is ever killed. Every action is reversible via -Mode restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('status','watch','auto','guard','ceiling','optimize','memclear','relieve','restore','report','export','tune','profile','install','uninstall','help')]
    [string]$Mode = 'status',
    [int]$CpuThreshold = 0,
    [int]$RamThreshold = 0,
    [int]$Seconds = 0,
    [int]$Ceiling = 0,
    [int]$Target = 0,
    [int]$PurgeAt = 0,
    [int]$PurgeTo = 0,
    [switch]$Aggressive,
    [switch]$Apply,
    [switch]$Gentle,
    [switch]$Purge,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir    = Join-Path $Root 'logs'
$SpikeLog  = Join-Path $LogDir 'spikes.csv'
$HangLog   = Join-Path $LogDir 'hangs.csv'
$StateFile = Join-Path $Root 'state.json'
$CfgFile   = Join-Path $Root 'config.json'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

# ---------------------------------------------------------------- native interop
if (-not ('PerfGuardNative' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class PerfGuardNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PowerThrottlingState
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EmptyWorkingSet(IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetProcessInformation(
        IntPtr hProcess, int infoClass, IntPtr info, uint size);

    [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr hProcess);
    [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr hProcess);

    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

    // ProcessPowerThrottling = 4 ; EXECUTION_SPEED = 0x1
    public static bool SetEco(IntPtr h, bool on)
    {
        PowerThrottlingState s = new PowerThrottlingState();
        s.Version     = 1;
        s.ControlMask = 0x1;
        s.StateMask   = on ? 0x1u : 0x0u;
        int size = Marshal.SizeOf(s);
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(s, buf, false);
            return SetProcessInformation(h, 4, buf, (uint)size);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
'@ -Language CSharp
}

# ---------------------------------------------------------------- machine capabilities
# Nothing below is assumed. Every capability is probed on the machine we are
# actually running on, because this tool gets carried to unknown PCs.
function Get-Capabilities {
    $os    = Get-CimInstance Win32_OperatingSystem
    $build = 0
    try { $build = [int]($os.BuildNumber) } catch {}

    $cs    = Get-CimInstance Win32_ComputerSystem
    $cores = [int]$cs.NumberOfLogicalProcessors
    if ($cores -lt 1) { $cores = 1 }
    $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

    $admin = $false
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    # EcoQoS is Windows 10 2004 (build 19041) and later. Rather than trust the
    # build number alone, actually call the API against our own process: OEM
    # images and Server SKUs do not always behave like the build implies.
    $eco = $false
    if ($build -ge 19041) {
        try {
            $h = (Get-Process -Id $PID).Handle
            if ([PerfGuardNative]::SetEco($h, $true)) {
                $eco = $true
                [void][PerfGuardNative]::SetEco($h, $false)   # undo the probe
            }
        } catch { $eco = $false }
    }

    [pscustomobject]@{
        OSName    = ($os.Caption -replace '^Microsoft ', '').Trim()
        Build     = $build
        PSVersion = $PSVersionTable.PSVersion.ToString()
        Cores     = $cores
        RamGB     = $ramGB
        IsAdmin   = $admin
        HasEcoQoS = $eco
        # Without EcoQoS we still have priority, and we can pin a hog to a
        # subset of cores. On a 2-core box that is too blunt to be useful.
        HasAffinity = ($cores -ge 4)
    }
}

# ---------------------------------------------------------------- app knowledge base
# Process names by role. Used to profile an unfamiliar machine. Anything not
# listed here is left alone - unknown means untouched.
$KB = @{
    # Never throttled, suspended or trimmed under any circumstance.
    System = @(
        'System','Idle','Registry','csrss','wininit','winlogon','services','lsass','smss',
        'dwm','fontdrvhost','audiodg','sihost','ctfmon','explorer','ShellExperienceHost',
        'StartMenuExperienceHost','TextInputHost','ApplicationFrameHost','LogonUI',
        'TrustedInstaller','WmiPrvSE','svchost','taskhostw','RuntimeBroker','dllhost',
        'Memory Compression','MemCompression','wininit','spoolsv','lsm','conhost',
        'powershell','pwsh','WindowsTerminal','cmd','claude','node','wsl','wslhost',
        'wudfhost','dasHost','SearchProtocolHost','SearchFilterHost'
    )
    # Security software. Throttling AV is a bad idea and often blocked anyway.
    Security = @(
        'MsMpEng','MpDefenderCoreService','NisSrv','SecurityHealthService',
        'SecurityHealthSystray','MpCmdRun','avp','avgui','avastui','ekrn','egui',
        'mcshield','MBAMService','mbamtray','SentinelAgent','CylanceSvc','CSFalconService',
        'ccSvcHst','SAVAdminService','TmListen','ntrtscan','PccNTMon'
    )
    # Browsers and Electron shells: the usual CPU burners. Safe to throttle when
    # not focused. NOT safe to trim - they fault every page straight back in.
    Heavy = @(
        'chrome','msedge','msedgewebview2','firefox','brave','opera','opera_gx','vivaldi',
        'iexplore','Code','Code - Insiders','devenv','idea64','pycharm64','studio64',
        'webstorm64','rider64','sublime_text','atom','notepad++'
    )
    # Chat, sync and media. Throttle when unfocused, trim when dormant.
    Background = @(
        'Teams','ms-teams','Slack','Discord','WhatsApp','WhatsApp.Root','Telegram',
        'Signal','Skype','Zoom','Spotify','iTunes','Music.UI','OneDrive','Dropbox',
        'GoogleDriveFS','googledrivesync','Creative Cloud','CCXProcess','CCLibrary',
        'AdobeIPCBroker','AdobeNotificationClient','Microsoft.Notes','YourPhone',
        'PhoneExperienceHost','Cortana','SearchApp','GameBar','GameBarFTServer'
    )
    # Driver-adjacent helpers for touchpad, audio and graphics. These are NEVER
    # touched. Suspending SynTPEnh kills touchpad scrolling and gestures;
    # suspending the audio or Intel graphics helper breaks sound and display
    # hotkeys. They cost almost no CPU anyway, so there is nothing to win here.
    Driver = @(
        'SynTPEnh','SynTPHelper','SynTPLpr','ETDCtrl','ETDIntelligentPointer','ETDService',
        'ApointC','Apoint','TouchpadService','ElanTouchpad',
        'SmartAudio3','RtkAudUService64','RtkNGUI64','RAVCpl64','NahimicService',
        'NahimicSvc32','NahimicSvc64','WavesSvc64','DTSAudioService',
        'igfxCUIService','igfxEM','igfxHK','igfxTray','IntelCpHDCPSvc','IntelCpHeciSvc',
        'nvcontainer','NVDisplay.Container','atieclxx','amdow','AMDRSServ','RadeonSoftware'
    )
    # OEM tray software, launchers and updaters. Safe to suspend: nothing breaks
    # if the RGB config panel or the vendor updater stops thinking for a while.
    # Anything whose job is a driver, a VPN or a security agent is NOT here.
    Vendor = @(
        'SteelSeriesGGEZ','SteelSeriesEngine','iCUE','LGHUB','LogiOptions','LogiOptionsMgr',
        'Razer Synapse','RzSynapse','GlideX','ArmouryCrate','ROGLiveService',
        'MSI Center','DragonCenter','LenovoVantage','LenovoVantageService',
        'HPSupportSolutionsFramework','HPPrintScanDoctorService','DellSupportAssist',
        'SupportAssistAgent','AcerJumpStart','ASUSSoftwareManager',
        'NVIDIA Web Helper','CCleaner','ccleaner64','GoogleUpdate','MicrosoftEdgeUpdate',
        'AdobeARM','AdobeUpdateService','jusched','SetPoint'
    )
}

# ---------------------------------------------------------------- profiling
function New-Profile {
    param([switch]$Loud)

    $caps  = $script:Caps
    $seen  = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $seen[$p.ProcessName] = $true }

    $eco = New-Object System.Collections.Generic.List[string]
    $trm = New-Object System.Collections.Generic.List[string]
    $sus = New-Object System.Collections.Generic.List[string]

    foreach ($n in ($KB.Heavy + $KB.Background + $KB.Vendor)) {
        if (-not $seen.ContainsKey($n)) { continue }        # only what is really here
        if ($KB.System -contains $n -or $KB.Security -contains $n -or $KB.Driver -contains $n) { continue }
        if (-not $eco.Contains($n)) { $eco.Add($n) }
        if ($KB.Heavy -notcontains $n) {
            if (-not $trm.Contains($n)) { $trm.Add($n) }     # never trim active apps
        }
        if ($KB.Vendor -contains $n) {
            if (-not $sus.Contains($n)) { $sus.Add($n) }     # tray junk only
        }
    }

    # Thresholds scaled to the hardware in front of us. A 2-core/8GB laptop hits
    # trouble far earlier than an 8-core/32GB desktop.
    $cpuT = 80
    $ramT = 80
    if ($caps.Cores -le 2) { $cpuT = 75 }
    if ($caps.RamGB -le 4) { $ramT = 73 } elseif ($caps.RamGB -le 8) { $ramT = 77 }
    $sample = 4
    if ($caps.Cores -le 2) { $sample = 6 }   # sample less often on weak CPUs

    $cfg = [ordered]@{
        _generated     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        _machine       = "$($caps.OSName) build $($caps.Build), $($caps.Cores) cores, $($caps.RamGB) GB"
        CpuThreshold   = $cpuT
        RamThreshold   = $ramT
        SampleSeconds  = $sample
        IdleCpuPercent = 1.0
        EcoMinCpu      = 2.0
        GuardCpuThreshold = [math]::Max(40, $cpuT - 15)
        GuardRamThreshold = [math]::Max(60, $ramT - 10)
        BoostForeground   = $true
        CeilingCpu        = 80
        CeilingRam        = 80
        CeilingTargetLow  = 75
        CeilingAggressive = $true
        MemPurgeAtRam       = 80
        MemPurgeTargetLow   = 75
        MemPurgeCooldownSec = 120
        MemPurgeOps         = @('workingsets','systemws','modified','standby0')
        NeverTouch     = @($KB.System + $KB.Security + $KB.Driver | Sort-Object -Unique)
        EcoTargets     = @($eco)
        TrimTargets    = @($trm)
        SuspendTargets = @($sus)
    }
    ConvertTo-Json -InputObject $cfg -Depth 4 | Set-Content -Path $CfgFile -Encoding utf8

    if ($Loud) {
        Write-Host ("  Profiled this machine -> config.json") -ForegroundColor Green
        Write-Host ("    {0}" -f $cfg._machine) -ForegroundColor Gray
        Write-Host ("    thresholds  CPU {0}%   RAM {1}%" -f $cpuT, $ramT) -ForegroundColor Gray
        Write-Host ("    throttle    {0}" -f $(if ($eco.Count) { $eco -join ', ' } else { '(none found)' })) -ForegroundColor Gray
        Write-Host ("    trim        {0}" -f $(if ($trm.Count) { $trm -join ', ' } else { '(none found)' })) -ForegroundColor Gray
        Write-Host ("    suspend     {0}" -f $(if ($sus.Count) { $sus -join ', ' } else { '(none found)' })) -ForegroundColor Gray
        Write-Host '                (suspend only ever happens if you pass -Aggressive)' -ForegroundColor DarkGray
        $skipped = @($KB.Driver | Where-Object { $seen.ContainsKey($_) })
        if ($skipped.Count -gt 0) {
            Write-Host ("    protected   {0}" -f ($skipped -join ', ')) -ForegroundColor DarkGray
            Write-Host '                (touchpad / audio / graphics helpers - never touched)' -ForegroundColor DarkGray
        }
    }
    return $cfg
}

function Get-Config {
    if (Test-Path $CfgFile) {
        try {
            $raw = Get-Content $CfgFile -Raw | ConvertFrom-Json
            $c = @{}
            foreach ($k in @('CpuThreshold','RamThreshold','SampleSeconds','IdleCpuPercent',
                             'EcoMinCpu','NeverTouch','EcoTargets','TrimTargets','SuspendTargets',
                             'GuardCpuThreshold','GuardRamThreshold','BoostForeground',
                             'CeilingCpu','CeilingRam','CeilingTargetLow','CeilingAggressive',
                             'MemPurgeAtRam','MemPurgeTargetLow','MemPurgeCooldownSec','MemPurgeOps')) {
                if ($null -ne $raw.$k) { $c[$k] = $raw.$k }
            }
            # Older config files predate the guard keys: fill them in rather than
            # forcing a full reprofile that would discard the operator's edits.
            if ($null -eq $c['GuardCpuThreshold']) { $c['GuardCpuThreshold'] = [math]::Max(40, $c['CpuThreshold'] - 15) }
            if ($null -eq $c['GuardRamThreshold']) { $c['GuardRamThreshold'] = [math]::Max(60, $c['RamThreshold'] - 10) }
            if ($null -eq $c['BoostForeground'])   { $c['BoostForeground']   = $true }
            if ($null -eq $c['CeilingCpu'])        { $c['CeilingCpu']        = 80 }
            if ($null -eq $c['CeilingRam'])        { $c['CeilingRam']        = 80 }
            if ($null -eq $c['CeilingTargetLow'])  { $c['CeilingTargetLow']  = 75 }
            if ($null -eq $c['MemPurgeAtRam'])       { $c['MemPurgeAtRam']       = 80 }
            if ($null -eq $c['MemPurgeTargetLow'])   { $c['MemPurgeTargetLow']   = 75 }
            if ($null -eq $c['MemPurgeCooldownSec']) { $c['MemPurgeCooldownSec'] = 120 }
            if ($null -eq $c['MemPurgeOps'])         { $c['MemPurgeOps'] = @('workingsets','systemws','modified','standby0') }
            if ($null -eq $c['CeilingAggressive']) { $c['CeilingAggressive'] = $true }
            if ($c.Count -ge 20) { return $c }
            Write-Warning 'config.json is incomplete - reprofiling this machine.'
        } catch {
            Write-Warning "config.json unreadable ($($_.Exception.Message)) - reprofiling."
        }
    }
    $gen = New-Profile
    $c = @{}
    foreach ($k in @('CpuThreshold','RamThreshold','SampleSeconds','IdleCpuPercent',
                     'EcoMinCpu','NeverTouch','EcoTargets','TrimTargets','SuspendTargets',
                     'GuardCpuThreshold','GuardRamThreshold','BoostForeground',
                     'CeilingCpu','CeilingRam','CeilingTargetLow','CeilingAggressive',
                     'MemPurgeAtRam','MemPurgeTargetLow','MemPurgeCooldownSec','MemPurgeOps')) {
        $c[$k] = $gen[$k]
    }
    return $c
}

$script:HungSeen = @{}
$script:BoostedPids = @()
$script:BoostedName = $null
$script:Caps = Get-Capabilities
$Cfg   = Get-Config

# config.json sits next to this script, so anything running as the user can edit
# it. NeverTouch is therefore treated as ADDITIVE ONLY: the built-in protection
# list is merged back in unconditionally. A tampered or careless config can widen
# what is protected, never expose lsass, the AV agent or a driver helper.
$Cfg.NeverTouch = @($KB.System + $KB.Security + $KB.Driver + @($Cfg.NeverTouch) |
                    Where-Object { $_ } | Sort-Object -Unique)
if ($Gentle)        { $Cfg.CeilingAggressive = $false }
if ($Ceiling -gt 0) { $Cfg.CeilingCpu = $Ceiling; $Cfg.CeilingRam = $Ceiling }
if ($Target  -gt 0) { $Cfg.CeilingTargetLow = $Target }
if ($PurgeAt -gt 0) { $Cfg.MemPurgeAtRam = $PurgeAt }
if ($PurgeTo -gt 0) { $Cfg.MemPurgeTargetLow = $PurgeTo }
if ([int]$Cfg.MemPurgeTargetLow -ge [int]$Cfg.MemPurgeAtRam) { $Cfg.MemPurgeTargetLow = [int]$Cfg.MemPurgeAtRam - 5 }
if ([int]$Cfg.CeilingTargetLow -ge [int]$Cfg.CeilingCpu) { $Cfg.CeilingTargetLow = [int]$Cfg.CeilingCpu - 5 }
if ($CpuThreshold -gt 0) { $Cfg.CpuThreshold = $CpuThreshold }
if ($RamThreshold -gt 0) { $Cfg.RamThreshold = $RamThreshold }

$Cores   = $script:Caps.Cores
$SelfPid = $PID

# ---------------------------------------------------------------- sampling
function Get-Snapshot {
    # Work out the Task-Manager normalisation factor first: the per-process loop
    # below needs it.
    $script:CpuRatio = 1.0
    try {
        $pi0 = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction Stop
        if ($null -ne $pi0) {
            $u0 = [double]$pi0.PercentProcessorUtility
            $t0 = [double]$pi0.PercentProcessorTime
            if ($u0 -ge 0 -and $t0 -gt 0) {
                $r0 = $u0 / $t0
                if ($r0 -gt 0 -and $r0 -le 4) { $script:CpuRatio = $r0 }
            }
        }
    } catch {}

    # One cheap CIM query gives both CPU% and private working set for every process.
    $rows = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.IDProcess -ne 0 -and $_.Name -ne '_Total' -and $_.Name -ne 'Idle' }

    $procs = foreach ($r in $rows) {
        [pscustomobject]@{
            Pid    = [int]$r.IDProcess
            Name   = ($r.Name -replace '#\d+$','')
            Cpu    = [math]::Round((($r.PercentProcessorTime / $Cores) * $script:CpuRatio), 1)
            RamMB  = [math]::Round($r.WorkingSetPrivate / 1MB, 0)
        }
    }

    $os      = Get-CimInstance Win32_OperatingSystem
    $ramPct  = [math]::Round(100 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100), 0)

    # Task Manager (Windows 8+) reports "% Processor Utility", not "% Processor
    # Time". Utility normalises against the base clock, so a CPU that is fully
    # busy while clocked below base reads under 100. Using % Processor Time made
    # every number here read higher than what the user sees in Task Manager.
    $cpuTot   = $null
    $cpuRatio = 1.0
    try {
        $pi = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction Stop
        if ($null -ne $pi) {
            $util = [double]$pi.PercentProcessorUtility
            $time = [double]$pi.PercentProcessorTime
            if ($util -ge 0) {
                $cpuTot = $util
                # Per-process counters are still % Processor Time, so scale them
                # by the same factor to keep the parts consistent with the whole.
                if ($time -gt 0) { $cpuRatio = $util / $time }
            }
            elseif ($time -ge 0) { $cpuTot = $time }
        }
    } catch {}
    if ($null -eq $cpuTot) {
        # Pre-Win8 / counter class missing: fall back to the classic counter.
        try { $cpuTot = [double](Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop).PercentProcessorTime } catch { $cpuTot = 0 }
    }
    if ($cpuRatio -le 0 -or $cpuRatio -gt 4) { $cpuRatio = 1.0 }
    # Task Manager clamps at 100; turbo can push raw utility above it.
    if ($cpuTot -gt 100) { $cpuTot = 100 }
    if ($cpuTot -lt 0)   { $cpuTot = 0 }

    $diskPct = 0; $diskQ = 0; $pages = 0
    try {
        $d = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction Stop
        $diskPct = [int]$d.PercentDiskTime
        $diskQ   = [int]$d.CurrentDiskQueueLength
    } catch {}
    try {
        $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
        $pages = [int]$m.PagesPerSec
    } catch {}

    [pscustomobject]@{
        Cpu       = [int]$cpuTot
        RamPct    = [int]$ramPct
        FreeMB    = [int]($os.FreePhysicalMemory / 1KB)
        TotalMB   = [int]($os.TotalVisibleMemorySize / 1KB)
        DiskPct   = $diskPct
        DiskQueue = $diskQ
        PagesSec  = $pages
        Processes = @($procs)
    }
}

function Get-ForegroundApp {
    try {
        $hwnd = [PerfGuardNative]::GetForegroundWindow()
        if ($hwnd -eq [IntPtr]::Zero) { return $null }
        $fg = [uint32]0
        [void][PerfGuardNative]::GetWindowThreadProcessId($hwnd, [ref]$fg)
        if ($fg -eq 0) { return $null }
        return (Get-Process -Id $fg -ErrorAction Stop).ProcessName
    } catch { return $null }
}

# ---------------------------------------------------------------- state (for restore)
function Read-State {
    if (-not (Test-Path $StateFile)) { return @() }
    try {
        $raw = Get-Content $StateFile -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $parsed = ConvertFrom-Json $raw
        if ($null -eq $parsed) { return @() }
        # Emit the records straight into the pipeline. The previous version
        # returned ,$out.ToArray(): the leading comma adds a wrapper array that
        # @(Read-State) does NOT flatten, so a state file holding two or more
        # records arrived as ONE element whose .Pid was an array - and the
        # caller's "malformed entry" guard then silently discarded the lot.
        # Restore was therefore a no-op in exactly the case it exists for: a
        # crashed run that left several processes suspended.
        return @($parsed)
    } catch { return @() }
}
function Write-State($entries) {
    if ($null -eq $entries -or $entries.Count -eq 0) {
        if (Test-Path $StateFile) { Remove-Item $StateFile -Force }
        return
    }
    # -InputObject, not the pipeline: piping a collection makes ConvertTo-Json
    # emit {"value":[...],"Count":n} instead of a plain array, which Read-State
    # cannot parse - restore would then silently do nothing.
    ConvertTo-Json -InputObject @($entries) -Depth 4 | Set-Content -Path $StateFile -Encoding utf8
}

# Start time is what makes a PID unambiguous. Windows recycles PIDs within
# minutes, so a record left behind by a crashed run can point at a completely
# different process by the time restore runs. StartTime is unreadable on a few
# system processes; '' there is fine, it just falls back to the name check.
function Get-ProcStart($p) {
    try { return $p.StartTime.ToString('o') } catch { return '' }
}

# True only when the PID still belongs to the SAME process we touched. Without
# this, restore would resume or re-prioritise an innocent bystander that merely
# inherited the number.
function Test-RecordAlive($rec) {
    if ($null -eq $rec) { return $false }
    $id = 0
    try { $id = [int]$rec.Pid } catch { return $false }
    try {
        $p = Get-Process -Id $id -ErrorAction Stop
        if ($rec.Name -and ($p.ProcessName -ine [string]$rec.Name)) { return $false }
        # State files written before this check carry no Start. Accept them on
        # the name match rather than discarding a restore that is probably valid.
        if (-not $rec.Start) { return $true }
        return ([string]$rec.Start -eq (Get-ProcStart $p))
    } catch { return $false }
}

$script:Touched = @{}   # pid -> record, in-memory mirror of the state file
$script:LoadedState = @(Read-State)
$script:StaleDropped = 0
foreach ($e in $script:LoadedState) {
    if ($null -eq $e) { continue }
    $sp = $e.Pid
    if ($null -eq $sp -or ($sp -is [array])) { continue }   # malformed entry: skip, never crash
    # A surviving PID proves nothing on its own - verify identity before letting
    # restore act on it.
    if (-not (Test-RecordAlive $e)) { $script:StaleDropped++; continue }
    try { $script:Touched[[int]$sp] = $e } catch { }
}

function Save-Touched { Write-State (@($script:Touched.Values)) }

function Get-SafeHandle([int]$id) {
    try { return (Get-Process -Id $id -ErrorAction Stop).Handle } catch { return [IntPtr]::Zero }
}

function Test-Protected([string]$name, [int]$id) {
    if ($id -eq $SelfPid -or $id -le 4) { return $true }
    foreach ($n in $Cfg.NeverTouch) { if ($name -ieq $n) { return $true } }
    return $false
}

function New-Record([int]$Id, [string]$Name) {
    $prio  = 'Normal'
    $start = ''
    try {
        $p     = Get-Process -Id $Id -ErrorAction Stop
        $prio  = $p.PriorityClass.ToString()
        $start = Get-ProcStart $p
    } catch {}
    return [pscustomobject]@{ Pid=$Id; Name=$Name; Start=$start; OrigPriority=$prio; Eco=$false; Suspended=$false
                              PrioChanged=$false; AffChanged=$false; OrigAffinity=0; Lvl=0 }
}

# ---------------------------------------------------------------- relief primitives
function Invoke-Eco {
    param([int]$Id, [string]$Name)
    if ($script:Touched.ContainsKey($Id) -and $script:Touched[$Id].Eco) { return $false }
    $h = Get-SafeHandle $Id
    if ($h -eq [IntPtr]::Zero) { return $false }
    if ($DryRun) { Write-Host ("    [dry] throttle {0} ({1})" -f $Name, $Id) -ForegroundColor DarkGray; return $true }

    $rec = $script:Touched[$Id]
    if (-not $rec) { $rec = New-Record $Id $Name }

    $ok = $false
    if ($script:Caps.HasEcoQoS) {
        try { if ([PerfGuardNative]::SetEco($h, $true)) { $ok = $true } } catch {}
    }
    elseif ($script:Caps.HasAffinity -and -not $rec.AffChanged) {
        # No EcoQoS on this Windows build. Pin the hog to half the logical CPUs
        # so it cannot monopolise the machine. Skipped on 2-core boxes, where
        # halving would cripple the app instead of merely slowing it.
        try {
            $proc = Get-Process -Id $Id -ErrorAction Stop
            $rec.OrigAffinity = [int64]$proc.ProcessorAffinity
            $half = [math]::Max(1, [math]::Floor($script:Caps.Cores / 2))
            $mask = [int64](([math]::Pow(2, $half)) - 1)
            $proc.ProcessorAffinity = [IntPtr]$mask
            $rec.AffChanged = $true
            $ok = $true
        } catch {}
    }

    $cur = $rec.OrigPriority
    if ($cur -eq 'Normal' -or $cur -eq 'AboveNormal' -or $cur -eq 'High' -or $cur -eq 'RealTime') {
        try {
            (Get-Process -Id $Id -ErrorAction Stop).PriorityClass = 'BelowNormal'
            $rec.PrioChanged = $true
            $ok = $true
        } catch {}
    }
    if ($ok) { $rec.Eco = $true; $script:Touched[$Id] = $rec }
    return $ok
}

function Invoke-Trim {
    param([int]$Id, [string]$Name)
    $h = Get-SafeHandle $Id
    if ($h -eq [IntPtr]::Zero) { return 0 }
    $before = 0
    try { $before = (Get-Process -Id $Id -ErrorAction Stop).WorkingSet64 } catch { return 0 }
    if ($DryRun) {
        Write-Host ("    [dry] trim {0} ({1}) holding {2} MB" -f $Name, $Id, [math]::Round($before/1MB,0)) -ForegroundColor DarkGray
        return 0
    }
    try { [void][PerfGuardNative]::EmptyWorkingSet($h) } catch { return 0 }
    Start-Sleep -Milliseconds 40
    $after = $before
    try { $after = (Get-Process -Id $Id -ErrorAction Stop).WorkingSet64 } catch {}
    $freed = [math]::Round(($before - $after) / 1MB, 0)
    if ($freed -lt 0) { $freed = 0 }
    return $freed
}

function Invoke-Suspend {
    param([int]$Id, [string]$Name)
    if ($script:Touched.ContainsKey($Id) -and $script:Touched[$Id].Suspended) { return $false }
    $h = Get-SafeHandle $Id
    if ($h -eq [IntPtr]::Zero) { return $false }
    if ($DryRun) { Write-Host ("    [dry] suspend {0} ({1})" -f $Name, $Id) -ForegroundColor DarkGray; return $true }
    $rc = -1
    try { $rc = [PerfGuardNative]::NtSuspendProcess($h) } catch { return $false }
    if ($rc -ne 0) { return $false }
    $rec = $script:Touched[$Id]
    if (-not $rec) { $rec = New-Record $Id $Name }
    $rec.Suspended = $true
    $script:Touched[$Id] = $rec
    return $true
}

function Invoke-Resume {
    param([int]$Id)
    $rec = $script:Touched[$Id]
    if (-not $rec -or -not $rec.Suspended) { return $false }
    $h = Get-SafeHandle $Id
    if ($h -ne [IntPtr]::Zero) {
        try { [void][PerfGuardNative]::NtResumeProcess($h) } catch {}
    }
    $rec.Suspended = $false
    $script:Touched[$Id] = $rec
    return $true
}

function Restore-All {
    param([switch]$Quiet)
    $n = 0
    foreach ($id in @($script:Touched.Keys)) {
        $rec = $script:Touched[$id]
        $h = Get-SafeHandle ([int]$id)
        if ($h -ne [IntPtr]::Zero) {
            if ($rec.Suspended) { try { [void][PerfGuardNative]::NtResumeProcess($h) } catch {} }
            if ($rec.Eco) {
                try { [void][PerfGuardNative]::SetEco($h, $false) } catch {}
                if ($rec.AffChanged -and $rec.OrigAffinity -gt 0) {
                    try { (Get-Process -Id ([int]$id) -ErrorAction Stop).ProcessorAffinity = [IntPtr][int64]$rec.OrigAffinity } catch {}
                }
                if ($rec.PrioChanged) {
                    try {
                        $p = Get-Process -Id ([int]$id) -ErrorAction Stop
                        if ($rec.OrigPriority) { $p.PriorityClass = $rec.OrigPriority } else { $p.PriorityClass = 'Normal' }
                    } catch {}
                }
            }
            $n++
        }
        $script:Touched.Remove($id)
    }
    if ($Aggressive) {
        $swept = 0
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            if (Test-Protected $p.ProcessName $p.Id) { continue }
            if (-not ($Cfg.EcoTargets -contains $p.ProcessName)) { continue }
            try {
                if ($p.PriorityClass -eq 'BelowNormal') { $p.PriorityClass = 'Normal'; $swept++ }
                if ($p.Handle -ne [IntPtr]::Zero) { [void][PerfGuardNative]::SetEco($p.Handle, $false) }
            } catch {}
        }
        if ($swept -gt 0 -and -not $Quiet) {
            Write-Host "  Swept $swept orphaned process(es) back to Normal priority." -ForegroundColor Green
        }
        $n += $swept
    }

    Save-Touched
    if (-not $Quiet) {
        if ($script:StaleDropped -gt 0) {
            Write-Host ("  {0} catatan lama diabaikan - PID-nya sudah dipakai proses lain." -f $script:StaleDropped) -ForegroundColor DarkGray
        }
        if ($n -gt 0) { Write-Host "  Restored $n process(es) to normal." -ForegroundColor Green }
        else { Write-Host "  Nothing was throttled or suspended - nothing to restore." -ForegroundColor DarkGray }
    }
    return $n
}

# ---------------------------------------------------------------- the relief pass
function Invoke-Relief {
    param($Snap, [string]$Foreground, [switch]$Loud)

    $acted = New-Object System.Collections.Generic.List[string]
    $freedTotal = 0
    $script:Skipped = New-Object System.Collections.Generic.List[string]

    # Always first: give back anything the user just switched to.
    foreach ($id in @($script:Touched.Keys)) {
        $rec = $script:Touched[$id]
        if ($rec.Suspended -and $Foreground -and $rec.Name -ieq $Foreground) {
            if (Invoke-Resume ([int]$id)) { $acted.Add("resumed $($rec.Name) ($id) - back in focus") }
        }
    }

    $busy = $Snap.Processes | Where-Object {
        (-not (Test-Protected $_.Name $_.Pid)) -and
        ((-not $Foreground) -or ($_.Name -ine $Foreground))
    }

    if ($Foreground) {
        $fgCpu = ($Snap.Processes | Where-Object { $_.Name -ieq $Foreground } | Measure-Object Cpu -Sum).Sum
        if ($fgCpu -ge $Cfg.EcoMinCpu) {
            $script:Skipped.Add("$Foreground is using $([math]::Round($fgCpu,1))% CPU but it is your focused app - never throttled")
        }
    }
    $offTarget = $Snap.Processes | Where-Object {
        $_.Cpu -ge $Cfg.EcoMinCpu -and (-not (Test-Protected $_.Name $_.Pid)) -and
        (-not ($Cfg.EcoTargets -contains $_.Name)) -and ((-not $Foreground) -or ($_.Name -ine $Foreground))
    } | Group-Object Name | Sort-Object { ($_.Group | Measure-Object Cpu -Sum).Sum } -Descending | Select-Object -First 3
    foreach ($g in $offTarget) {
        $c = [math]::Round((($g.Group | Measure-Object Cpu -Sum).Sum), 1)
        $script:Skipped.Add("$($g.Name) is using $c% CPU but is not in EcoTargets - add it to config.json to throttle it")
    }

    # 1) CPU relief - EcoQoS + BelowNormal on background CPU burners.
    if ($Snap.Cpu -ge $Cfg.CpuThreshold) {
        $hogs = $busy | Where-Object { $_.Cpu -ge $Cfg.EcoMinCpu -and ($Cfg.EcoTargets -contains $_.Name) } |
                Sort-Object Cpu -Descending | Select-Object -First 12
        foreach ($p in $hogs) {
            if (Invoke-Eco $p.Pid $p.Name) { $acted.Add("throttled $($p.Name) ($($p.Pid)) at $($p.Cpu)% CPU") }
        }
    }

    # 2) RAM relief - trim ONLY processes that are genuinely idle right now.
    #    Trimming a busy process just makes it fault the pages straight back in.
    if ($Snap.RamPct -ge $Cfg.RamThreshold) {
        $freeBefore = [int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)
        $idleFat = $busy | Where-Object {
            $_.Cpu -le $Cfg.IdleCpuPercent -and $_.RamMB -ge 60 -and ($Cfg.TrimTargets -contains $_.Name)
        } | Sort-Object RamMB -Descending | Select-Object -First 20
        $trimmed = 0
        foreach ($p in $idleFat) {
            if ((Invoke-Trim $p.Pid $p.Name) -ge 5) { $trimmed++ }
        }
        if ($trimmed -gt 0 -and -not $DryRun) {
            Start-Sleep -Milliseconds 400
            $freeAfter  = [int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)
            # The honest number: change in ACTUALLY available memory. The sum of
            # working sets released is meaningless - most of it lands on the
            # standby list and is faulted straight back in.
            $freedTotal = $freeAfter - $freeBefore
            $acted.Add("trimmed $trimmed dormant process(es)")
        }
    }

    # 3) Aggressive - suspend opted-in background apps outright.
    if ($Aggressive -and ($Snap.Cpu -ge $Cfg.CpuThreshold -or $Snap.RamPct -ge $Cfg.RamThreshold)) {
        $targets = $busy | Where-Object { $Cfg.SuspendTargets -contains $_.Name } |
                   Sort-Object Cpu -Descending | Select-Object -First 10
        foreach ($p in $targets) {
            if (Invoke-Suspend $p.Pid $p.Name) { $acted.Add("SUSPENDED $($p.Name) ($($p.Pid))") }
        }
    }

    Save-Touched
    if ($Loud) {
        if ($acted.Count -eq 0) {
            if ($DryRun) {
                Write-Host "  (dry run - the actions listed above are what would happen)" -ForegroundColor DarkGray
            } else {
                $why = 'no process qualified'
                if ($Snap.Cpu -lt $Cfg.CpuThreshold -and $Snap.RamPct -lt $Cfg.RamThreshold) {
                    $why = "CPU $($Snap.Cpu)% and RAM $($Snap.RamPct)% are both under your thresholds ($($Cfg.CpuThreshold)% / $($Cfg.RamThreshold)%)"
                }
                Write-Host "  No action taken - $why." -ForegroundColor DarkGray
            }
            foreach ($sk in $script:Skipped) { Write-Host "    note: $sk" -ForegroundColor DarkGray }
        }
        else { foreach ($a in $acted) { Write-Host "  - $a" -ForegroundColor Yellow } }
        if ($freedTotal -gt 0) {
            Write-Host "  Available RAM actually went up by $freedTotal MB." -ForegroundColor Green
        } elseif ($freedTotal -lt 0) {
            Write-Host "  Available RAM went DOWN by $([math]::Abs($freedTotal)) MB - those apps were not dormant" -ForegroundColor Red
            Write-Host "  after all and pulled their pages back in. Remove them from TrimTargets." -ForegroundColor Red
        }
    }
    return $acted
}

# ---------------------------------------------------------------- display helpers
function Show-Bar([int]$pct, [int]$width = 28) {
    $fill = [math]::Round($pct / 100 * $width)
    if ($fill -gt $width) { $fill = $width }
    if ($fill -lt 0) { $fill = 0 }
    $colour = 'Green'
    if ($pct -ge 70) { $colour = 'Yellow' }
    if ($pct -ge 88) { $colour = 'Red' }
    Write-Host ('[' + ('#' * $fill) + ('.' * ($width - $fill)) + ']') -NoNewline -ForegroundColor $colour
}

function Show-Header {
    $c = $script:Caps
    Write-Host ''
    Write-Host '  PerfGuard' -NoNewline -ForegroundColor Cyan
    Write-Host ("  -  {0} (build {1})  |  {2} cores  |  {3} GB RAM  |  PS {4}" -f `
        $c.OSName, $c.Build, $c.Cores, $c.RamGB, $c.PSVersion) -ForegroundColor DarkGray
    $mode = 'EcoQoS + priority'
    $col  = 'DarkGray'
    if (-not $c.HasEcoQoS) {
        if ($c.HasAffinity) { $mode = 'priority + affinity (no EcoQoS on this build)' }
        else { $mode = 'priority only (no EcoQoS, too few cores for affinity)' }
        $col = 'Yellow'
    }
    $adm = 'standard user'
    if ($c.IsAdmin) { $adm = 'administrator' }
    Write-Host ("     throttling: {0}  |  running as {1}" -f $mode, $adm) -ForegroundColor $col
    if (-not $c.IsAdmin) {
        Write-Host '     note: without admin, processes owned by other users or elevated apps cannot be touched.' -ForegroundColor DarkGray
    }
    Write-Host '  ---------------------------------------------------------------' -ForegroundColor DarkGray
}

function Show-Snapshot($Snap, [string]$Foreground) {
    Write-Host '  CPU  ' -NoNewline
    Show-Bar $Snap.Cpu
    Write-Host ("  {0,3}%" -f $Snap.Cpu) -ForegroundColor White
    Write-Host '  RAM  ' -NoNewline
    Show-Bar $Snap.RamPct
    Write-Host ("  {0,3}%   {1} MB free of {2} MB" -f $Snap.RamPct, $Snap.FreeMB, $Snap.TotalMB) -ForegroundColor White
    if ($Foreground) { Write-Host ("  Focus: {0}" -f $Foreground) -ForegroundColor DarkGray }
    Write-Host ''

    $byApp = $Snap.Processes | Group-Object Name | ForEach-Object {
        [pscustomobject]@{
            App   = $_.Name
            N     = $_.Count
            'CPU%' = [math]::Round((($_.Group | Measure-Object Cpu -Sum).Sum), 1)
            'RAM MB' = [math]::Round((($_.Group | Measure-Object RamMB -Sum).Sum), 0)
        }
    }
    Write-Host '  Top CPU' -ForegroundColor Cyan
    $byApp | Sort-Object 'CPU%' -Descending | Select-Object -First 6 | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
    Write-Host '  Top RAM' -ForegroundColor Cyan
    $byApp | Sort-Object 'RAM MB' -Descending | Select-Object -First 6 | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
}

function Write-Spike($Snap, [string]$Foreground) {
    $top = $Snap.Processes | Sort-Object Cpu -Descending | Select-Object -First 3
    $ram = $Snap.Processes | Group-Object Name | ForEach-Object {
        [pscustomobject]@{ N=$_.Name; M=(($_.Group | Measure-Object RamMB -Sum).Sum) }
    } | Sort-Object M -Descending | Select-Object -First 1

    $row = [pscustomobject]@{
        Time      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        CpuPct    = $Snap.Cpu
        RamPct    = $Snap.RamPct
        FreeMB    = $Snap.FreeMB
        DiskPct   = $Snap.DiskPct
        DiskQueue = $Snap.DiskQueue
        PagesSec  = $Snap.PagesSec
        Focus     = $Foreground
        Top1      = if ($top[0]) { $top[0].Name } else { '' }
        Top1Cpu   = if ($top[0]) { $top[0].Cpu }  else { 0 }
        Top2      = if ($top.Count -gt 1) { $top[1].Name } else { '' }
        Top2Cpu   = if ($top.Count -gt 1) { $top[1].Cpu }  else { 0 }
        Top3      = if ($top.Count -gt 2) { $top[2].Name } else { '' }
        Top3Cpu   = if ($top.Count -gt 2) { $top[2].Cpu }  else { 0 }
        TopRamApp = if ($ram) { $ram.N } else { '' }
        TopRamMB  = if ($ram) { $ram.M } else { 0 }
    }
    if (Test-Path $SpikeLog) { $row | Export-Csv -Path $SpikeLog -NoTypeInformation -Append -Encoding utf8 }
    else                     { $row | Export-Csv -Path $SpikeLog -NoTypeInformation -Encoding utf8 }
}

# ---------------------------------------------------------------- monitor loop
function Start-Loop {
    param([switch]$Act, [switch]$GuardMode)

    $label = 'WATCH (logging only)'
    if ($Act) { $label = 'AUTO (logging + relief)' }
    if ($GuardMode) { $label = 'GUARD (anti-lag, preventif)' }
    Show-Header
    Write-Host ("  Mode: {0}   thresholds CPU {1}%  RAM {2}%" -f $label, $Cfg.CpuThreshold, $Cfg.RamThreshold) -ForegroundColor Cyan
    if ($GuardMode) {
        Write-Host ("  Ambang preventif: CPU {0}%  RAM {1}%   (bertindak sebelum lag terjadi)" -f `
            $Cfg.GuardCpuThreshold, $Cfg.GuardRamThreshold) -ForegroundColor Cyan
        if ($Cfg.BoostForeground) { Write-Host '  Aplikasi yang sedang dipakai diprioritaskan otomatis.' -ForegroundColor Cyan }
    }
    if ($Act -and $Aggressive) { Write-Host '  Aggressive: background apps in SuspendTargets will be suspended.' -ForegroundColor Yellow }
    if ($DryRun) { Write-Host '  Dry run: nothing will actually be changed.' -ForegroundColor Yellow }
    Write-Host ("  Log: {0}" -f $SpikeLog) -ForegroundColor DarkGray
    Write-Host '  Press Ctrl+C to stop (everything is restored on exit).' -ForegroundColor DarkGray
    Write-Host ''

    $deadline = $null
    if ($Seconds -gt 0) { $deadline = (Get-Date).AddSeconds($Seconds) }
    $spikes = 0
    $ticks  = 0
    $purges = 0; $purgeFreed = 0
    $script:WarnedNoAdmin = $false

    try {
        while ($true) {
            if ($deadline -and (Get-Date) -gt $deadline) { break }
            $snap = Get-Snapshot
            $fg   = Get-ForegroundApp
            $ticks++

            $hot = ($snap.Cpu -ge $Cfg.CpuThreshold) -or ($snap.RamPct -ge $Cfg.RamThreshold)
            $stamp = (Get-Date).ToString('HH:mm:ss')

            # Freeze detection. Checked every 3rd tick: Responding blocks up to
            # 5s per window, so polling it every tick would itself cause stutter.
            $hung = @()
            if (($ticks % 3) -eq 1) {
                $hung = Get-HungApps
                foreach ($h in $hung) {
                    $hrow = [pscustomobject]@{
                        Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        App = $h.Name; Pid = $h.Pid; Title = $h.Title
                        CpuPct = $snap.Cpu; RamPct = $snap.RamPct
                        FreeMB = $snap.FreeMB; DiskPct = $snap.DiskPct
                    }
                    if (Test-Path $HangLog) { $hrow | Export-Csv -Path $HangLog -NoTypeInformation -Append -Encoding utf8 }
                    else                    { $hrow | Export-Csv -Path $HangLog -NoTypeInformation -Encoding utf8 }
                    $script:HungSeen["$($h.Name)"] = 1 + $(if ($script:HungSeen.ContainsKey("$($h.Name)")) { $script:HungSeen["$($h.Name)"] } else { 0 })
                    Write-Host ("  {0}  NOT RESPONDING: {1} ({2}) {3}" -f $stamp, $h.Name, $h.Pid, $h.Title) -ForegroundColor Magenta
                }
            }

            if ($GuardMode) {
                $g = Invoke-Guard $snap $fg
                foreach ($a in $g) { Write-Host ("  {0}  guard: {1}" -f $stamp, $a) -ForegroundColor DarkCyan }
            }

            # Auto and Guard act on the machine, so they get the memory purge
            # trigger too. Watch never touches anything, so it is excluded.
            if ($Act -or $GuardMode) {
                $pr = Invoke-AutoMemPurge $snap '            '
                if ($pr) { $purges++; $purgeFreed += $pr.Freed }
            }

            if ($hot) {
                $spikes++
                Write-Spike $snap $fg
                $top = $snap.Processes | Sort-Object Cpu -Descending | Select-Object -First 3
                $names = ($top | ForEach-Object { "{0} {1}%" -f $_.Name, $_.Cpu }) -join ', '
                $extra = ''
                if ($snap.DiskPct -ge 80) { $extra += "  DISK $($snap.DiskPct)%" }
                if ($snap.PagesSec -ge 1000) { $extra += "  PAGING $($snap.PagesSec)/s" }
                Write-Host ("  {0}  CPU {1,3}%  RAM {2,3}%{3}  <- {4}" -f $stamp, $snap.Cpu, $snap.RamPct, $extra, $names) -ForegroundColor Red
                if ($Act -and -not $GuardMode) { Invoke-Relief $snap $fg -Loud | Out-Null }
            }
            else {
                Write-Host ("  {0}  CPU {1,3}%  RAM {2,3}%" -f $stamp, $snap.Cpu, $snap.RamPct) -ForegroundColor DarkGray
                if ($Act -and -not $GuardMode) {
                    # still resume anything the user switched back to
                    foreach ($id in @($script:Touched.Keys)) {
                        $rec = $script:Touched[$id]
                        if ($rec.Suspended -and $fg -and $rec.Name -ieq $fg) {
                            if (Invoke-Resume ([int]$id)) { Write-Host "  - resumed $($rec.Name) ($id)" -ForegroundColor Green }
                        }
                    }
                    Save-Touched
                }
            }
            Start-Sleep -Seconds $Cfg.SampleSeconds
        }
    }
    finally {
        Write-Host ''
        Write-Host ("  Stopped. {0} samples, {1} spike(s) logged." -f $ticks, $spikes) -ForegroundColor Cyan
        if ($purges -gt 0) {
            Write-Host ("  Pembersihan memori: {0}x, total RAM bebas bertambah {1} MB" -f $purges, $purgeFreed) -ForegroundColor Cyan
        }
        if ($script:HungSeen.Count -gt 0) {
            Write-Host '  Aplikasi yang sempat berhenti merespons:' -ForegroundColor Magenta
            foreach ($k in ($script:HungSeen.Keys | Sort-Object { -$script:HungSeen[$_] })) {
                Write-Host ("    {0} - {1} kali" -f $k, $script:HungSeen[$k]) -ForegroundColor Magenta
            }
        }
        if ($GuardMode) { Clear-ForegroundBoost }
        if ($Act -or $GuardMode) { Restore-All | Out-Null }
    }
}

# ---------------------------------------------------------------- report
function Show-Report {
    Show-Header
    if (-not (Test-Path $SpikeLog)) {
        Write-Host '  No spike log yet. Run:  PerfGuard.cmd watch' -ForegroundColor Yellow
        Write-Host ''
        return
    }
    $rows = @(Import-Csv $SpikeLog)
    if ($rows.Count -eq 0) { Write-Host '  Spike log is empty - nothing crossed your thresholds yet. Good.' -ForegroundColor Green; return }

    Write-Host ("  {0} spikes recorded, {1} .. {2}" -f $rows.Count, $rows[0].Time, $rows[-1].Time) -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Who caused your spikes (as the #1 CPU consumer at that moment)' -ForegroundColor Cyan
    $rows | Group-Object Top1 | ForEach-Object {
        [pscustomobject]@{
            App        = $_.Name
            Spikes     = $_.Count
            Share      = ('{0}%' -f [math]::Round($_.Count / $rows.Count * 100, 0))
            'AvgCPU%'  = [math]::Round((($_.Group | Measure-Object Top1Cpu -Average).Average), 1)
            'PeakCPU%' = [math]::Round((($_.Group | Measure-Object Top1Cpu -Maximum).Maximum), 1)
        }
    } | Sort-Object Spikes -Descending | Select-Object -First 10 |
        Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }

    Write-Host '  Biggest RAM holder during spikes' -ForegroundColor Cyan
    $rows | Group-Object TopRamApp | ForEach-Object {
        [pscustomobject]@{
            App       = $_.Name
            Spikes    = $_.Count
            'AvgMB'   = [math]::Round((($_.Group | Measure-Object TopRamMB -Average).Average), 0)
            'PeakMB'  = [math]::Round((($_.Group | Measure-Object TopRamMB -Maximum).Maximum), 0)
        }
    } | Sort-Object Spikes -Descending | Select-Object -First 6 |
        Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }

    if (Test-Path $HangLog) {
        $hg = @(Import-Csv $HangLog)
        if ($hg.Count -gt 0) {
            Write-Host '  Aplikasi yang berhenti merespons (freeze)' -ForegroundColor Magenta
            $hg | Group-Object App | ForEach-Object {
                [pscustomobject]@{
                    App = $_.Name; Kejadian = $_.Count
                    'RAM bebas rata2 MB' = [math]::Round((($_.Group | ForEach-Object { [int]$_.FreeMB } | Measure-Object -Average).Average),0)
                }
            } | Sort-Object Kejadian -Descending | Select-Object -First 8 |
                Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
        }
    }

    $lowRam = @($rows | Where-Object { [int]$_.FreeMB -lt 500 }).Count
    if ($lowRam -gt 0) {
        Write-Host ("  Warning: in {0} of {1} spikes free RAM was under 500 MB." -f $lowRam, $rows.Count) -ForegroundColor Red
        Write-Host '  At that point Windows starts compressing and paging, and CPU goes to 100% on its own.' -ForegroundColor Red
        Write-Host '  Throttling cannot fix that - it is a capacity problem. More RAM is the real fix.' -ForegroundColor Red
        Write-Host ''
    }
}

# ---------------------------------------------------------------- hang detection
# A freeze is not a CPU number. It is a window that has stopped pumping its
# message loop. Only processes that own a window can hang in the way a user
# means, so we ask just those - Responding blocks for up to 5s per process.
function Get-HungApps {
    $out = @()
    try {
        $wins = @(Get-Process -ErrorAction SilentlyContinue |
                  Where-Object { $_.MainWindowHandle -ne 0 } |
                  Select-Object -First 25)
        foreach ($p in $wins) {
            try {
                if (-not $p.Responding) {
                    $out += [pscustomobject]@{ Name = $p.ProcessName; Pid = $p.Id; Title = $p.MainWindowTitle }
                }
            } catch {}
        }
    } catch {}
    return @($out)
}

# ---------------------------------------------------------------- foreground boost
# Lag is usually not "the CPU is full", it is "the app I am typing into lost the
# race". Nudging the focused app above the noise fixes that directly, and costs
# nothing when the machine is idle.
function Set-ForegroundBoost {
    param([string]$Foreground)

    if ($script:BoostedName -eq $Foreground) { return }

    # Drop the previous boost first, so only ever one app is elevated.
    if ($script:BoostedPids) {
        foreach ($id in $script:BoostedPids) {
            try { (Get-Process -Id $id -ErrorAction Stop).PriorityClass = 'Normal' } catch {}
        }
    }
    $script:BoostedPids = @()
    $script:BoostedName = $Foreground
    if (-not $Foreground) { return }
    foreach ($n in $Cfg.NeverTouch) { if ($Foreground -ieq $n) { return } }

    foreach ($p in (Get-Process -Name $Foreground -ErrorAction SilentlyContinue)) {
        try {
            # Only lift a process sitting at Normal. Never touch one the app
            # itself parked low - Chrome does that to its background tabs.
            if ($p.PriorityClass -eq 'Normal') {
                $p.PriorityClass = 'AboveNormal'
                $script:BoostedPids += $p.Id
            }
        } catch {}
    }
}

function Clear-ForegroundBoost {
    if ($script:BoostedPids) {
        foreach ($id in $script:BoostedPids) {
            try { (Get-Process -Id $id -ErrorAction Stop).PriorityClass = 'Normal' } catch {}
        }
    }
    $script:BoostedPids = @()
    $script:BoostedName = $null
}

# ---------------------------------------------------------------- guard pass
# Preventive, not reactive. Runs every tick at lower thresholds than relief,
# because by the time you hit 80% the stutter has already happened.
function Invoke-Guard {
    param($Snap, [string]$Foreground)

    $acted = @()

    if ($Cfg.BoostForeground) {
        Set-ForegroundBoost $Foreground
        if ($script:BoostedPids.Count -gt 0 -and $script:LastBoostReported -ne $Foreground) {
            $script:LastBoostReported = $Foreground
            $acted += "prioritaskan $Foreground ($($script:BoostedPids.Count) proses)"
        }
    }

    # Keep background burners down continuously, not only during a spike.
    if ($Snap.Cpu -ge $Cfg.GuardCpuThreshold) {
        $cands = $Snap.Processes | Where-Object {
            (-not (Test-Protected $_.Name $_.Pid)) -and
            ((-not $Foreground) -or ($_.Name -ine $Foreground)) -and
            $_.Cpu -ge $Cfg.EcoMinCpu -and ($Cfg.EcoTargets -contains $_.Name)
        } | Sort-Object Cpu -Descending | Select-Object -First 8
        foreach ($p in $cands) {
            if (Invoke-Eco $p.Pid $p.Name) { $acted += "tahan $($p.Name) ($($p.Pid)) di $($p.Cpu)% CPU" }
        }
    }

    # Early memory defence. Once Windows starts compressing, the freeze is
    # already under way, so act while there is still headroom.
    if ($Snap.RamPct -ge $Cfg.GuardRamThreshold) {
        $idle = $Snap.Processes | Where-Object {
            (-not (Test-Protected $_.Name $_.Pid)) -and
            ((-not $Foreground) -or ($_.Name -ine $Foreground)) -and
            $_.Cpu -le $Cfg.IdleCpuPercent -and $_.RamMB -ge 60 -and ($Cfg.TrimTargets -contains $_.Name)
        } | Sort-Object RamMB -Descending | Select-Object -First 10
        $t = 0
        foreach ($p in $idle) { if ((Invoke-Trim $p.Pid $p.Name) -ge 5) { $t++ } }
        if ($t -gt 0) { $acted += "lepas memori $t proses dorman" }
    }

    Save-Touched
    return $acted
}

# ---------------------------------------------------------------- system tuning audit
# Everything here is REPORT ONLY unless -Apply is passed, and -Apply is limited
# to two settings that are trivially reversible. Silently rewriting someone
# else's machine is not acceptable, so the rest stays as instructions.
function Get-TuneChecks {
    $c = @()
    $caps = $script:Caps

    # --- power plan
    try {
        $scheme = (powercfg /getactivescheme) 2>$null
        $isSaver = $scheme -match 'Power saver|Hemat daya'
        $c += [pscustomobject]@{
            Key='power'; Ok=(-not $isSaver); Sev=$(if ($isSaver){'warn'}else{'ok'})
            Title='Power plan'
            Now=$(if ($scheme -match '\((.+)\)') { $matches[1] } else { 'tidak diketahui' })
            Why='Power saver menurunkan clock CPU secara agresif. Di CPU lemah itu terasa sebagai lag konstan.'
            Fix='Control Panel > Power Options > pilih Balanced atau High performance.'
            CanApply=$true
        }
    } catch {}

    # --- disk type and free space
    try {
        $sysDrive = $env:SystemDrive
        $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'"
        $freePct = [math]::Round($ld.FreeSpace / $ld.Size * 100, 0)
        $c += [pscustomobject]@{
            Key='diskfree'; Ok=($freePct -ge 15); Sev=$(if ($freePct -lt 10){'crit'}elseif($freePct -lt 15){'warn'}else{'ok'})
            Title="Ruang kosong $sysDrive"
            Now="$freePct% ($([math]::Round($ld.FreeSpace/1GB,1)) GB dari $([math]::Round($ld.Size/1GB,1)) GB)"
            Why='Di bawah 15% Windows kesulitan menaruh page file dan file sementara. Ini penyebab freeze yang sering terlewat.'
            Fix='Kosongkan ruang: Disk Cleanup, hapus file besar, pindahkan data ke drive lain.'
            CanApply=$false
        }
    } catch {}

    try {
        $md = 'tidak diketahui'
        $pd = Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.DeviceId -eq 0 } | Select-Object -First 1
        if ($pd) { $md = "$($pd.MediaType)" }
        # "Unspecified" means the driver did not report a media type - it is NOT
        # a clean result, and must not be shown as if the disk had been checked.
        $isHdd  = ($md -match 'HDD')
        $isSsd  = ($md -match 'SSD')
        $known  = ($isHdd -or $isSsd)
        $c += [pscustomobject]@{
            Key='disktype'
            Ok=$(if ($known) { -not $isHdd } else { $true })
            Sev=$(if ($isHdd) {'crit'} elseif ($isSsd) {'ok'} else {'info'})
            Title='Jenis disk sistem'
            Now=$(if ($known) { $md } else { "tidak terdeteksi (dilaporkan '$md')" })
            Why=$(if ($isHdd) {
                    'HDD mekanis adalah penyebab freeze nomor satu di laptop modern. Windows 10/11 mengasumsikan SSD.'
                  } else {
                    'Driver tidak melaporkan jenis media, jadi ini BELUM diperiksa. Kalau ternyata HDD, itu penyebab freeze paling mungkin.'
                  })
            Fix=$(if ($isHdd) {
                    'Ganti ke SSD. Ini peningkatan terbesar per rupiah untuk laptop yang ngelag.'
                  } else {
                    'Cek manual: Task Manager > Performance > Disk, lihat labelnya, atau jalankan Get-PhysicalDisk sebagai administrator.'
                  })
            CanApply=$false
        }
    } catch {}

    # --- page file
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $auto = $cs.AutomaticManagedPagefile
        $pf = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
        $none = ($pf.Count -eq 0 -and -not $auto)
        $c += [pscustomobject]@{
            Key='pagefile'; Ok=(-not $none); Sev=$(if ($none){'crit'}else{'ok'})
            Title='Page file'
            Now=$(if ($auto) { 'dikelola otomatis' } elseif ($pf.Count -gt 0) { "manual, $([math]::Round(($pf | Measure-Object AllocatedBaseSize -Sum).Sum/1024,1)) GB" } else { 'DIMATIKAN' })
            Why="Dengan RAM $($caps.RamGB) GB, mematikan page file membuat aplikasi crash atau sistem membeku saat memori habis."
            Fix='System Properties > Advanced > Performance > Advanced > Virtual memory > centang Automatically manage.'
            CanApply=$false
        }
    } catch {}

    # --- startup load
    try {
        $su = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue)
        $n = $su.Count
        $c += [pscustomobject]@{
            Key='startup'; Ok=($n -le 10); Sev=$(if ($n -gt 18){'crit'}elseif($n -gt 10){'warn'}else{'ok'})
            Title='Aplikasi startup'; Now="$n item"
            Why='Tiap item startup merebut CPU dan disk saat login, dan sebagian besar terus berjalan di background sesudahnya.'
            Fix='Task Manager > tab Startup > Disable yang tidak perlu. Jangan matikan driver dan antivirus.'
            CanApply=$false
            Detail=@($su | Select-Object -First 15 | ForEach-Object { $_.Name })
        }
    } catch {}

    # --- visual effects
    try {
        $vfx = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -ErrorAction SilentlyContinue).VisualFXSetting
        $isPerf = ($vfx -eq 2)
        $c += [pscustomobject]@{
            Key='visualfx'; Ok=$isPerf; Sev=$(if ($isPerf){'ok'}else{'info'})
            Title='Efek visual'
            Now=$(switch ($vfx) { 2 {'best performance'} 1 {'best appearance'} 3 {'custom'} default {'let Windows choose'} })
            Why='Animasi dan bayangan dirender oleh CPU/GPU yang sudah sibuk. Di mesin lemah ini terasa sebagai lag saat membuka menu.'
            Fix='System Properties > Advanced > Performance Settings > Adjust for best performance.'
            CanApply=$true
        }
    } catch {}

    # --- SysMain / Superfetch
    try {
        $sm = Get-Service SysMain -ErrorAction SilentlyContinue
        if ($sm) {
            $c += [pscustomobject]@{
                Key='sysmain'; Ok=$true; Sev='info'; Title='SysMain (Superfetch)'; Now="$($sm.Status)"
                Why='Kadang disalahkan sebagai penyebab disk 100%. Di HDD justru membantu, di SSD manfaatnya kecil.'
                Fix='JANGAN matikan kecuali terbukti dari mode Watch bahwa SysMain memang pelakunya.'
                CanApply=$false
            }
        }
    } catch {}

    # --- Windows Search indexer
    try {
        $ws = Get-Service WSearch -ErrorAction SilentlyContinue
        if ($ws -and $ws.Status -eq 'Running') {
            $c += [pscustomobject]@{
                Key='wsearch'; Ok=$true; Sev='info'; Title='Windows Search indexer'; Now='berjalan'
                Why='Indexing bisa menahan disk berjam-jam setelah instalasi baru atau setelah menyalin banyak file.'
                Fix='Kalau mode Watch menunjukkan SearchIndexer sebagai pelaku: Indexing Options > Modify, kurangi folder yang diindeks.'
                CanApply=$false
            }
        }
    } catch {}

    # --- pending reboot
    try {
        $pending = $false
        foreach ($k in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
            if (Test-Path $k) { $pending = $true }
        }
        $up = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $longUp = ($up.TotalDays -ge 7)
        if ($pending -or $longUp) {
            $c += [pscustomobject]@{
                Key='reboot'; Ok=$false; Sev='warn'; Title='Perlu restart'
                Now=$(if ($pending) { 'ada update menunggu restart' } else { "uptime $([int]$up.TotalDays) hari" })
                Why='Uptime panjang menumpuk kebocoran memori dan handle. Sebagian besar keluhan "makin lama makin lambat" hilang setelah restart.'
                Fix='Restart laptop.'
                CanApply=$false
            }
        }
    } catch {}

    # --- RAM headroom
    $c += [pscustomobject]@{
        Key='ram'; Ok=($caps.RamGB -gt 8); Sev=$(if ($caps.RamGB -le 4){'crit'}elseif($caps.RamGB -le 8){'warn'}else{'ok'})
        Title='Kapasitas RAM'; Now="$($caps.RamGB) GB"
        Why='Windows 10/11 dengan browser modern realistis butuh 16 GB. Di bawah itu freeze karena kehabisan memori tinggal soal waktu.'
        Fix='Tambah RAM. Tidak ada pengaturan software yang bisa menggantikan kapasitas.'
        CanApply=$false
    }

    return @($c)
}

function Invoke-Tune {
    param([switch]$Apply)

    $checks = Get-TuneChecks
    $sevCol = @{ crit='Red'; warn='Yellow'; ok='Green'; info='DarkGray' }
    $sevTag = @{ crit='KRITIS   '; warn='PERHATIAN'; ok='BAIK     '; info='INFO     ' }

    Write-Host '  Audit penyebab lag dan freeze di level sistem' -ForegroundColor Cyan
    Write-Host ''
    foreach ($k in $checks) {
        Write-Host ("  [{0}] {1}" -f $sevTag[$k.Sev], $k.Title) -ForegroundColor $sevCol[$k.Sev] -NoNewline
        Write-Host ("  -  {0}" -f $k.Now) -ForegroundColor White
        if (-not $k.Ok -or $k.Sev -eq 'info') {
            Write-Host ("      {0}" -f $k.Why) -ForegroundColor Gray
            Write-Host ("      -> {0}" -f $k.Fix) -ForegroundColor DarkGray
        }
        if ($k.Key -eq 'startup' -and $k.Detail) {
            Write-Host ("      isi: {0}" -f (($k.Detail | Select-Object -First 10) -join ', ')) -ForegroundColor DarkGray
        }
        Write-Host ''
    }

    $fixable = @($checks | Where-Object { $_.CanApply -and -not $_.Ok })
    if ($fixable.Count -eq 0) {
        Write-Host '  Tidak ada yang bisa diperbaiki otomatis. Sisanya perlu tindakan manual di atas.' -ForegroundColor DarkGray
        return
    }

    if (-not $Apply) {
        Write-Host ("  {0} hal bisa diperbaiki otomatis: {1}" -f $fixable.Count, (($fixable | ForEach-Object { $_.Title }) -join ', ')) -ForegroundColor Yellow
        Write-Host '  Jalankan:  PerfGuard.cmd tune -Apply' -ForegroundColor Yellow
        Write-Host '  Sisanya sengaja TIDAK diotomatiskan - terlalu berisiko di PC orang lain.' -ForegroundColor DarkGray
        return
    }

    Write-Host '  Menerapkan perbaikan yang aman...' -ForegroundColor Cyan
    $undo = @()
    foreach ($k in $fixable) {
        if ($k.Key -eq 'power') {
            try {
                $before = (powercfg /getactivescheme) 2>$null
                if ($before -match 'GUID: ([0-9a-f-]+)') { $undo += "powercfg /setactive $($matches[1])" }
                # 8c5e7fda... = High performance, a built-in GUID present on every Windows.
                & powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null
                Write-Host '    Power plan -> High performance' -ForegroundColor Green
            } catch { Write-Host "    Power plan gagal: $($_.Exception.Message)" -ForegroundColor Red }
        }
        if ($k.Key -eq 'visualfx') {
            try {
                $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                $old = (Get-ItemProperty $path -Name VisualFXSetting -ErrorAction SilentlyContinue).VisualFXSetting
                if ($null -ne $old) { $undo += "Set VisualFXSetting = $old" }
                Set-ItemProperty -Path $path -Name VisualFXSetting -Value 2 -Type DWord
                Write-Host '    Efek visual -> best performance (butuh sign-out untuk penuh)' -ForegroundColor Green
            } catch { Write-Host "    Efek visual gagal: $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
    if ($undo.Count -gt 0) {
        $undoFile = Join-Path $LogDir 'tune-undo.txt'
        # Append, never overwrite. Running tune -Apply a second time must not
        # destroy the record of the ORIGINAL values - that first block is the
        # only way back to the machine's untouched state.
        $block = @('', "Nilai sebelum diubah, $(Get-Date -Format 'yyyy-MM-dd HH:mm')") + $undo
        Add-Content -Path $undoFile -Value $block -Encoding utf8
        Write-Host ("  Nilai lama dicatat di: {0}" -f $undoFile) -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------- RAMMap-style memory clearing
# The five operations RAMMap exposes under its Empty menu. All of them go
# through NtSetSystemInformation and all of them need elevation plus an
# explicitly enabled privilege - without that they fail with STATUS_PRIVILEGE_
# NOT_HELD (0xC0000061) rather than doing nothing quietly.
if (-not ('PerfGuardMem' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class PerfGuardMem
{
    public const int SystemFileCacheInformation  = 21;
    public const int SystemMemoryListInformation = 80;

    // SYSTEM_MEMORY_LIST_COMMAND
    public const int MemoryEmptyWorkingSets           = 2;
    public const int MemoryFlushModifiedList          = 3;
    public const int MemoryPurgeStandbyList           = 4;
    public const int MemoryPurgeLowPriorityStandbyList = 5;

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_FILECACHE_INFORMATION
    {
        public IntPtr CurrentSize;
        public IntPtr PeakSize;
        public uint   PageFaultCount;
        public IntPtr MinimumWorkingSet;
        public IntPtr MaximumWorkingSet;
        public IntPtr CurrentSizeIncludingTransitionInPages;
        public IntPtr PeakSizeIncludingTransitionInPages;
        public uint   TransitionRePurposeCount;
        public uint   Flags;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public int LuidLow;
        public int LuidHigh;
        public int Attributes;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtSetSystemInformation(int infoClass, IntPtr info, int length);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string host, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr prior, IntPtr returnLength);

    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] public static extern bool   CloseHandle(IntPtr h);

    public static bool EnablePrivilege(string name)
    {
        IntPtr token;
        // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out token)) return false;
        try
        {
            long luid;
            if (!LookupPrivilegeValue(null, name, out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.LuidLow    = (int)(luid & 0xFFFFFFFFL);
            tp.LuidHigh   = (int)(luid >> 32);
            tp.Attributes = 0x0002;                 // SE_PRIVILEGE_ENABLED
            if (!AdjustTokenPrivileges(token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
                return false;
            // AdjustTokenPrivileges returns TRUE even when it assigned nothing;
            // ERROR_NOT_ALL_ASSIGNED (1300) is the real failure signal.
            return Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }

    // Empty Working Sets / Flush Modified List / Purge Standby / Purge Priority-0 Standby
    public static int MemoryCommand(int command)
    {
        IntPtr buf = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            Marshal.WriteInt32(buf, command);
            return NtSetSystemInformation(SystemMemoryListInformation, buf, sizeof(int));
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // Empty System Working Set: shrink the system file cache by setting both
    // bounds to -1, which is how RAMMap does it.
    public static int EmptySystemWorkingSet()
    {
        SYSTEM_FILECACHE_INFORMATION info = new SYSTEM_FILECACHE_INFORMATION();
        info.MinimumWorkingSet = (IntPtr)(-1);
        info.MaximumWorkingSet = (IntPtr)(-1);
        int size = Marshal.SizeOf(info);
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, buf, false);
            return NtSetSystemInformation(SystemFileCacheInformation, buf, size);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
'@ -Language CSharp
}

# The five operations, in the order RAMMap lists them. Cost is stated plainly:
# these are not all equally harmless, and two of them throw away useful cache.
$MemOps = @(
    [pscustomobject]@{ Key='workingsets'; Label='Empty Working Sets'
        Priv='SeProfileSingleProcessPrivilege'
        Note='Lepas working set semua proses. Halaman pindah ke standby, bukan hilang.' }
    [pscustomobject]@{ Key='systemws';    Label='Empty System Working Set'
        Priv='SeIncreaseQuotaPrivilege'
        Note='Kecilkan cache file sistem. Baca berikutnya kembali ke disk.' }
    [pscustomobject]@{ Key='modified';    Label='Empty Modified Page List'
        Priv='SeProfileSingleProcessPrivilege'
        Note='Tulis halaman kotor ke disk lalu pindahkan ke standby. Ada I/O.' }
    [pscustomobject]@{ Key='standby';     Label='Empty Standby List'
        Priv='SeProfileSingleProcessPrivilege'
        Note='BUANG SELURUH CACHE DISK mesin. Free RAM melonjak, tapi semua baca berikutnya ke disk.' }
    [pscustomobject]@{ Key='standby0';    Label='Empty Priority 0 Standby List'
        Priv='SeProfileSingleProcessPrivilege'
        Note='Hanya buang cache prioritas terendah. Jauh lebih aman dari Empty Standby List.' }
)

function Invoke-MemOp {
    param([string]$Key)
    $op = $MemOps | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
    if (-not $op) { return [pscustomobject]@{ Ok=$false; Msg="operasi tidak dikenal: $Key" } }

    if (-not [PerfGuardMem]::EnablePrivilege($op.Priv)) {
        return [pscustomobject]@{ Ok=$false; Msg="privilege $($op.Priv) ditolak - jalankan sebagai administrator" }
    }

    $rc = 0
    switch ($Key) {
        'workingsets' { $rc = [PerfGuardMem]::MemoryCommand([PerfGuardMem]::MemoryEmptyWorkingSets) }
        'systemws'    { $rc = [PerfGuardMem]::EmptySystemWorkingSet() }
        'modified'    { $rc = [PerfGuardMem]::MemoryCommand([PerfGuardMem]::MemoryFlushModifiedList) }
        'standby'     { $rc = [PerfGuardMem]::MemoryCommand([PerfGuardMem]::MemoryPurgeStandbyList) }
        'standby0'    { $rc = [PerfGuardMem]::MemoryCommand([PerfGuardMem]::MemoryPurgeLowPriorityStandbyList) }
    }
    if ($rc -eq 0) { return [pscustomobject]@{ Ok=$true; Msg='ok' } }
    $msg = "NTSTATUS 0x{0:X8}" -f $rc
    if ($rc -eq -1073741727) { $msg = 'STATUS_PRIVILEGE_NOT_HELD - butuh administrator' }  # 0xC0000061
    if ($rc -eq -1073741820) { $msg = 'STATUS_INFO_LENGTH_MISMATCH' }                       # 0xC0000004
    return [pscustomobject]@{ Ok=$false; Msg=$msg }
}

function Get-FreeMB {
    $os = Get-CimInstance Win32_OperatingSystem
    return [int]($os.FreePhysicalMemory / 1KB)
}

# Live RAM %, cheap enough to re-read between purge passes. Get-Snapshot also
# reports this, but it samples CPU and enumerates every process to do it -
# far too expensive to call just to ask "are we under the target yet?".
function Get-RamPct {
    $os = Get-CimInstance Win32_OperatingSystem
    $tot = [double]$os.TotalVisibleMemorySize
    if ($tot -le 0) { return 0 }
    return [int][math]::Round((($tot - [double]$os.FreePhysicalMemory) / $tot) * 100)
}

function Clear-SystemMemory {
    param([string[]]$Ops, [switch]$Quiet)

    if (-not $script:Caps.IsAdmin) {
        if (-not $Quiet) {
            Write-Host '  Butuh hak administrator.' -ForegroundColor Red
            Write-Host '  Klik kanan Start.cmd > Run as administrator, lalu ulangi.' -ForegroundColor Red
            Write-Host '  (RAMMap juga menuntut hal yang sama - ini batasan Windows, bukan alat ini.)' -ForegroundColor DarkGray
        }
        return [pscustomobject]@{ Ok=$false; Freed=0; Ran=@() }
    }

    $before = Get-FreeMB
    $ran = @()
    foreach ($k in $Ops) {
        $op = $MemOps | Where-Object { $_.Key -eq $k } | Select-Object -First 1
        if (-not $op) { continue }
        $r = Invoke-MemOp $k
        if (-not $Quiet) {
            if ($r.Ok) { Write-Host ("    OK    {0}" -f $op.Label) -ForegroundColor Green }
            else       { Write-Host ("    GAGAL {0} - {1}" -f $op.Label, $r.Msg) -ForegroundColor Red }
        }
        if ($r.Ok) { $ran += $op.Label }
        Start-Sleep -Milliseconds 120
    }
    Start-Sleep -Milliseconds 400
    $after = Get-FreeMB
    $freed = $after - $before
    $script:LastMemPurge = Get-Date

    if (-not $Quiet) {
        Write-Host ''
        # The honest number: change in ACTUALLY available memory, not the sum of
        # what was released. That distinction is the whole difference between
        # this and a fake RAM booster.
        if ($freed -gt 0) { Write-Host ("  RAM bebas naik {0} MB  ({1} -> {2} MB)" -f $freed, $before, $after) -ForegroundColor Green }
        else              { Write-Host ("  RAM bebas tidak bertambah ({0} -> {1} MB)" -f $before, $after) -ForegroundColor Yellow }
    }
    return [pscustomobject]@{ Ok=$true; Freed=$freed; Ran=$ran; Before=$before; After=$after }
}

function Show-MemClear {
    param([string[]]$Ops)
    Show-Header
    Write-Host '  Pembersihan memori tingkat sistem (setara menu Empty di RAMMap)' -ForegroundColor Cyan
    Write-Host ''
    foreach ($k in $Ops) {
        $op = $MemOps | Where-Object { $_.Key -eq $k } | Select-Object -First 1
        if ($op) {
            Write-Host ("    - {0}" -f $op.Label) -ForegroundColor Gray
            Write-Host ("      {0}" -f $op.Note) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    if ($DryRun) { Write-Host '  -DryRun: tidak ada yang dijalankan.' -ForegroundColor Yellow; Write-Host ''; return }
    Write-Host '  Menjalankan...' -ForegroundColor Cyan
    [void](Clear-SystemMemory -Ops $Ops)
    Write-Host ''
}


# ---------------------------------------------------------------- auto purge trigger
# Shared by ceiling, auto, guard and relieve. Returns the purge result, or $null
# when nothing was done (below trigger, no admin, or still inside the cooldown).
#
# It works as a band, not a single shot: it fires at MemPurgeAtRam (80%) and
# keeps sweeping until RAM is back under MemPurgeTargetLow (75%). One pass often
# lands at 79% - just under the trigger, so the next tick does nothing and the
# machine sits pinned at the ceiling. Sweeping to a lower floor buys real
# headroom instead. Passes are capped, and a pass that gains nothing stops the
# loop, so a genuinely full machine costs three sweeps rather than an endless
# grind.
function Invoke-AutoMemPurge {
    param($Snap, [string]$Indent = '            ')

    if ($Snap.RamPct -lt [int]$Cfg.MemPurgeAtRam) { return $null }

    if (-not $script:Caps.IsAdmin) {
        if (-not $script:WarnedNoAdmin) {
            $script:WarnedNoAdmin = $true
            Write-Host ("{0}RAM {1}% >= {2}%: pembersihan memori butuh administrator - dilewati." -f `
                $Indent, $Snap.RamPct, [int]$Cfg.MemPurgeAtRam) -ForegroundColor Yellow
            Write-Host ("{0}Jalankan Start.cmd sebagai administrator agar ini otomatis." -f $Indent) -ForegroundColor DarkGray
        }
        return $null
    }

    # Cooldown: a machine that simply lives above the trigger must not throw its
    # disk cache away every few seconds.
    $cool = [int]$Cfg.MemPurgeCooldownSec
    if ($null -ne $script:LastMemPurge -and ((Get-Date) - $script:LastMemPurge).TotalSeconds -lt $cool) {
        return $null
    }

    $low = [int]$Cfg.MemPurgeTargetLow
    Write-Host ("{0}RAM {1}% >= {2}% - membersihkan memori tingkat sistem (target <{3}%)..." -f `
        $Indent, $Snap.RamPct, [int]$Cfg.MemPurgeAtRam, $low) -ForegroundColor Magenta

    $ops    = @($Cfg.MemPurgeOps)
    $passes = 0
    $first  = $null
    $last   = $null
    $ran    = @()
    $pct    = $Snap.RamPct
    while ($passes -lt 3) {
        $r = Clear-SystemMemory -Ops $ops -Quiet
        $passes++
        if ($null -eq $first) { $first = $r }
        $last = $r
        $ran += @($r.Ran)
        $pct = Get-RamPct
        if ($pct -lt $low) { break }
        # A pass that freed nothing will not do better on the next one: what is
        # left is memory in active use, and no amount of sweeping releases that.
        if ($r.Freed -le 0) { break }
        Start-Sleep -Milliseconds 300
    }

    $freed = $last.After - $first.Before
    if ($freed -gt 0) {
        Write-Host ("{0}RAM bebas +{1} MB ({2} -> {3} MB), RAM {4}% dalam {5} lintasan" -f `
            $Indent, $freed, $first.Before, $last.After, $pct, $passes) -ForegroundColor Green
    } else {
        Write-Host ("{0}tidak ada tambahan RAM bebas ({1} -> {2} MB), RAM {3}%" -f `
            $Indent, $first.Before, $last.After, $pct) -ForegroundColor Yellow
    }
    if ($pct -ge $low) {
        Write-Host ("{0}masih di {1}% (target <{2}%) - sisanya memori yang sedang dipakai." -f `
            $Indent, $pct, $low) -ForegroundColor DarkGray
    }
    return [pscustomobject]@{
        Ok     = $true
        Freed  = $freed
        Ran    = $ran
        Before = $first.Before
        After  = $last.After
        RamPct = $pct
        Passes = $passes
    }
}

# ---------------------------------------------------------------- ceiling mode
# Holds CPU and RAM below a hard ceiling using a four-step escalation ladder.
# Every step is reversible, and the mode measures its own success rate rather
# than assuming it worked.

# Suspending a process is what finally makes its memory reclaimable: a running
# process faults trimmed pages straight back in (measured: 2.8 GB "freed",
# 253 MB actually gained, CPU 6% -> 40%). A suspended one cannot, so the pages
# stay evicted. Suspend first, trim second - never the other way round.
function Invoke-SuspendAndTrim {
    param([int]$Id, [string]$Name, [int]$Level = 0)
    if (-not (Invoke-Suspend $Id $Name)) { return $false }
    if ($Level -gt 0 -and $script:Touched.ContainsKey($Id)) { $script:Touched[$Id].Lvl = $Level }
    Start-Sleep -Milliseconds 30
    [void](Invoke-Trim $Id $Name)
    return $true
}

# PIDs that own a visible top-level window. Suspending one of these freezes
# something the user can see, so they are excluded from every suspend step.
function Get-WindowPids {
    $h = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        if ($p.MainWindowHandle -ne 0) { $h[$p.Id] = $true }
    }
    return $h
}

function Get-CeilingBands {
    param([int]$Ceiling)
    $low = [int]$Cfg.CeilingTargetLow
    if ($low -ge $Ceiling) { $low = $Ceiling - 5 }
    return [pscustomobject]@{
        L1  = [math]::Max(1, $low - 10)
        L2  = [math]::Max(2, $low - 3)
        L3  = [math]::Max(3, $low + 1)
        L4  = [math]::Max(4, $Ceiling - 1)
        Low = $low
    }
}

function Get-CeilingLevel {
    param([int]$Value, [int]$Ceiling)
    $b = Get-CeilingBands $Ceiling
    if ($Value -ge $b.L4) { return 4 }
    if ($Value -ge $b.L3) { return 3 }
    if ($Value -ge $b.L2) { return 2 }
    if ($Value -ge $b.L1) { return 1 }
    return 0
}

function Invoke-Ceiling {
    param($Snap, [string]$Foreground)

    $acted  = @()
    $cpuC   = [int]$Cfg.CeilingCpu
    $ramC   = [int]$Cfg.CeilingRam
    $cpuLvl = Get-CeilingLevel $Snap.Cpu    $cpuC
    $ramLvl = Get-CeilingLevel $Snap.RamPct $ramC
    $lvl    = [math]::Max($cpuLvl, $ramLvl)

    # Keep whatever the user is actually looking at responsive.
    if ($Cfg.BoostForeground) { Set-ForegroundBoost $Foreground }

    $free = $Snap.Processes | Where-Object {
        (-not (Test-Protected $_.Name $_.Pid)) -and
        ((-not $Foreground) -or ($_.Name -ine $Foreground))
    }

    # --- graded de-escalation with one level of hysteresis. A suspension made at
    # level N is released as soon as we sit at N-2 or lower, so easing pressure
    # gives apps back promptly even on a machine that never reaches level 0.
    $released = 0
    foreach ($id in @($script:Touched.Keys)) {
        $rec = $script:Touched[$id]
        if ($rec.Suspended -and $rec.Lvl -gt 0 -and $lvl -le ($rec.Lvl - 2)) {
            if (Invoke-Resume ([int]$id)) { $released++ }
        }
    }
    if ($released -gt 0) { $acted += "tekanan turun - $released proses dilanjutkan kembali" }

    if ($lvl -eq 0) {
        $script:CalmTicks++
        if ($script:CalmTicks -ge 2 -and $script:Touched.Count -gt 0) {
            $n = Restore-All -Quiet
            if ($n -gt 0) { $acted += "tekanan reda - $n proses dikembalikan normal" }
            $script:CalmTicks = 0
        }
        Save-Touched
        return $acted
    }
    $script:CalmTicks = 0

    # --- level 1: EcoQoS + BelowNormal on background burners
    if ($cpuLvl -ge 1) {
        foreach ($p in ($free | Where-Object { $_.Cpu -ge $Cfg.EcoMinCpu -and ($Cfg.EcoTargets -contains $_.Name) } |
                        Sort-Object Cpu -Descending | Select-Object -First 10)) {
            if (Invoke-Eco $p.Pid $p.Name) { $acted += "L1 tahan $($p.Name) ($($p.Pid)) $($p.Cpu)%" }
        }
    }
    if ($ramLvl -ge 1) {
        $t = 0
        foreach ($p in ($free | Where-Object {
                    $_.Cpu -le $Cfg.IdleCpuPercent -and $_.RamMB -ge 60 -and ($Cfg.TrimTargets -contains $_.Name) } |
                    Sort-Object RamMB -Descending | Select-Object -First 12)) {
            if ((Invoke-Trim $p.Pid $p.Name) -ge 5) { $t++ }
        }
        if ($t -gt 0) { $acted += "L1 lepas memori $t proses dorman" }
    }

    # --- level 2: cap the biggest background hog to a subset of cores
    if ($cpuLvl -ge 2 -and $script:Caps.HasAffinity) {
        foreach ($p in ($free | Where-Object { $_.Cpu -ge 5 -and ($Cfg.EcoTargets -contains $_.Name) } |
                        Sort-Object Cpu -Descending | Select-Object -First 3)) {
            $rec = $script:Touched[$p.Pid]
            if ($rec -and $rec.AffChanged) { continue }
            try {
                $proc = Get-Process -Id $p.Pid -ErrorAction Stop
                if (-not $rec) { $rec = New-Record $p.Pid $p.Name }
                $rec.OrigAffinity = [int64]$proc.ProcessorAffinity
                $half = [math]::Max(1, [math]::Floor($script:Caps.Cores / 2))
                $proc.ProcessorAffinity = [IntPtr][int64]((([math]::Pow(2, $half)) - 1))
                $rec.AffChanged = $true
                $rec.Eco = $true
                $script:Touched[$p.Pid] = $rec
                $acted += "L2 batasi $($p.Name) ($($p.Pid)) ke $half core"
            } catch {}
        }
    }

    $winPids = @{}
    if ($lvl -ge 3) { $winPids = Get-WindowPids }

    # --- level 3: suspend opted-in tray software outright
    if ($lvl -ge 3) {
        foreach ($p in ($free | Where-Object { ($Cfg.SuspendTargets -contains $_.Name) -and (-not $winPids.ContainsKey($_.Pid)) } |
                        Sort-Object RamMB -Descending | Select-Object -First 8)) {
            if (Invoke-SuspendAndTrim $p.Pid $p.Name 3) { $acted += "L3 tangguhkan $($p.Name) ($($p.Pid))" }
        }
    }

    # --- level 4: last reversible lever - suspend background windows of heavy
    # apps that are not in focus. Announced up front, undone the moment the
    # pressure drops or the user switches back to that app.
    if ($lvl -ge 4 -and $Cfg.CeilingAggressive) {
        $cand = $free | Where-Object {
            ($Cfg.EcoTargets -contains $_.Name) -and (-not $winPids.ContainsKey($_.Pid))
        }
        if ($ramLvl -ge 4) {
            $heavy = $cand | Where-Object { $_.RamMB -ge 150 -and $_.Cpu -le 5 } |
                     Sort-Object RamMB -Descending | Select-Object -First 6
            foreach ($p in $heavy) {
                if (Invoke-SuspendAndTrim $p.Pid $p.Name 4) { $acted += "L4 tangguhkan $($p.Name) ($($p.Pid)) $($p.RamMB) MB" }
            }
        }
        if ($cpuLvl -ge 4) {
            $burn = $cand | Where-Object { $_.Cpu -ge 10 } |
                    Sort-Object Cpu -Descending | Select-Object -First 4
            foreach ($p in $burn) {
                if (Invoke-SuspendAndTrim $p.Pid $p.Name 4) { $acted += "L4 tangguhkan $($p.Name) ($($p.Pid)) $($p.Cpu)% CPU" }
            }
        }
    }

    Save-Touched
    return $acted
}

function Start-Ceiling {
    $cpuC = [int]$Cfg.CeilingCpu
    $ramC = [int]$Cfg.CeilingRam
    $sample = [math]::Min([int]$Cfg.SampleSeconds, 3)   # react fast enough to matter

    Show-Header
    $b = Get-CeilingBands $cpuC
    Write-Host ("  Mode: CEILING - target {0}-{1}%, maksimal {1}%" -f $b.Low, $cpuC) -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Tangga eskalasi (makin dekat plafon, makin tegas):' -ForegroundColor Gray
    Write-Host ("    L1  >= {0,2}%   EcoQoS + prioritas rendah, lepas memori dorman" -f $b.L1) -ForegroundColor DarkGray
    Write-Host ("    L2  >= {0,2}%   batasi proses rakus ke separuh core" -f $b.L2) -ForegroundColor DarkGray
    Write-Host ("    L3  >= {0,2}%   tangguhkan software tray" -f $b.L3) -ForegroundColor DarkGray
    if ($Cfg.CeilingAggressive) {
        Write-Host ("    L4  >= {0,2}%   tangguhkan window background aplikasi berat" -f $b.L4) -ForegroundColor Yellow
        Write-Host '          catatan: kalau ada tab background yang memutar audio, suaranya berhenti' -ForegroundColor Yellow
        Write-Host '          sampai tekanan reda. Matikan dengan -Gentle.' -ForegroundColor Yellow
    } else {
        Write-Host '    L4        dimatikan (-Gentle)' -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  Semua otomatis dikembalikan begitu tekanan reda, dan saat mode ditutup.' -ForegroundColor DarkGray
    Write-Host '  Aplikasi yang sedang kamu pakai tidak pernah ditahan.' -ForegroundColor DarkGray
    Write-Host ''

    $deadline = $null
    if ($Seconds -gt 0) { $deadline = (Get-Date).AddSeconds($Seconds) }
    $script:CalmTicks = 0
    $script:WarnedHog = $null
    $ticks = 0; $cpuBreach = 0; $ramBreach = 0
    $purges = 0; $purgeFreed = 0
    $script:WarnedNoAdmin = $false
    $cpuPeak = 0; $ramPeak = 0

    try {
        while ($true) {
            if ($deadline -and (Get-Date) -gt $deadline) { break }
            $snap = Get-Snapshot
            $fg   = Get-ForegroundApp
            $ticks++
            if ($snap.Cpu    -gt $cpuPeak) { $cpuPeak = $snap.Cpu }
            if ($snap.RamPct -gt $ramPeak) { $ramPeak = $snap.RamPct }
            $cb = ($snap.Cpu    -ge $cpuC)
            $rb = ($snap.RamPct -ge $ramC)
            if ($cb) { $cpuBreach++ }
            if ($rb) { $ramBreach++ }

            $stamp = (Get-Date).ToString('HH:mm:ss')
            $col = 'DarkGray'
            if ($snap.Cpu -ge ($cpuC-12) -or $snap.RamPct -ge ($ramC-12)) { $col = 'Yellow' }
            if ($cb -or $rb) { $col = 'Red' }
            $mark = ''
            if ($cb) { $mark += '  <- CPU TEMBUS' }
            if ($rb) { $mark += '  <- RAM TEMBUS' }
            Write-Host ("  {0}  CPU {1,3}%  RAM {2,3}%{3}" -f $stamp, $snap.Cpu, $snap.RamPct, $mark) -ForegroundColor $col

            foreach ($a in (Invoke-Ceiling $snap $fg)) {
                Write-Host ("            {0}" -f $a) -ForegroundColor DarkCyan
            }

            $pr = Invoke-AutoMemPurge $snap
            if ($pr) { $purges++; $purgeFreed += $pr.Freed }

            if ($cb) {
                $top = $snap.Processes | Where-Object { -not (Test-Protected $_.Name $_.Pid) } |
                       Sort-Object Cpu -Descending | Select-Object -First 1
                if ($top -and $top.Cpu -ge 10 -and ($Cfg.EcoTargets -notcontains $top.Name) -and
                    ($fg -ine $top.Name) -and ($script:WarnedHog -ne $top.Name)) {
                    $script:WarnedHog = $top.Name
                    Write-Host ("            TIDAK BISA DITAHAN: {0} pakai {1}% CPU tapi tidak ada di EcoTargets." -f $top.Name, $top.Cpu) -ForegroundColor Red
                    Write-Host  '            Tambahkan namanya ke EcoTargets di config.json, atau tutup aplikasinya.' -ForegroundColor Red
                }
                elseif ($top -and ($fg -ieq $top.Name)) {
                    if ($script:WarnedHog -ne "fg:$($top.Name)") {
                        $script:WarnedHog = "fg:$($top.Name)"
                        Write-Host ("            {0} pakai {1}% CPU tapi itu aplikasi yang sedang kamu pakai - sengaja tidak ditahan." -f $top.Name, $top.Cpu) -ForegroundColor Yellow
                    }
                }
            }
            Start-Sleep -Seconds $sample
        }
    }
    finally {
        Clear-ForegroundBoost
        Restore-All -Quiet | Out-Null
        Write-Host ''
        Write-Host '  ---------------------------------------------------------------' -ForegroundColor DarkGray
        Write-Host ("  Hasil dari {0} sampel:" -f $ticks) -ForegroundColor Cyan
        if ($ticks -gt 0) {
            $cpuOk = [math]::Round((($ticks - $cpuBreach) / $ticks) * 100, 0)
            $ramOk = [math]::Round((($ticks - $ramBreach) / $ticks) * 100, 0)
            $cc = $(if ($cpuBreach -eq 0) { 'Green' } else { 'Yellow' })
            $rc = $(if ($ramBreach -eq 0) { 'Green' } else { 'Red' })
            Write-Host ("    CPU di bawah {0}% : {1}% waktu   (tembus {2}x, puncak {3}%)" -f $cpuC, $cpuOk, $cpuBreach, $cpuPeak) -ForegroundColor $cc
            Write-Host ("    RAM di bawah {0}% : {1}% waktu   (tembus {2}x, puncak {3}%)" -f $ramC, $ramOk, $ramBreach, $ramPeak) -ForegroundColor $rc
            if ($purges -gt 0) {
                Write-Host ("    Pembersihan memori : {0}x, total RAM bebas bertambah {1} MB" -f $purges, $purgeFreed) -ForegroundColor Cyan
            }
            Write-Host ''
            if ($ramBreach -gt ($ticks * 0.3)) {
                Write-Host '  RAM tidak bisa ditahan di bawah plafon.' -ForegroundColor Red
                Write-Host '  Ini bukan kegagalan penjadwalan - memorinya memang tidak cukup.' -ForegroundColor Red
                Write-Host '  Menahan prioritas tidak menciptakan RAM. Yang bisa menurunkannya:' -ForegroundColor Red
                Write-Host '  tutup tab browser, kurangi aplikasi bersamaan, atau tambah RAM.' -ForegroundColor Red
            }
            elseif ($cpuBreach -eq 0 -and $ramBreach -eq 0) {
                Write-Host '  Plafon berhasil dipertahankan sepanjang periode ini.' -ForegroundColor Green
            }
        }
        Write-Host ''
    }
}

# ---------------------------------------------------------------- one-shot optimise
# "Just optimise the device": profile, fix what is safe to fix automatically,
# state plainly what still needs a human, then hold the ceiling.
function Invoke-Optimize {
    Show-Header
    Write-Host '  OPTIMIZE - urutan lengkap' -ForegroundColor Cyan
    Write-Host '  ---------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host ''

    Write-Host '  [1/4] Memindai mesin ini...' -ForegroundColor Cyan
    New-Profile -Loud | Out-Null
    Write-Host ''

    Write-Host '  [2/4] Audit sistem dan perbaikan otomatis yang aman...' -ForegroundColor Cyan
    Write-Host ''
    Invoke-Tune -Apply
    Write-Host ''

    Write-Host '  [3/4] Melepas memori dari proses yang dorman...' -ForegroundColor Cyan
    $before = Get-Snapshot
    Invoke-Relief $before (Get-ForegroundApp) -Loud | Out-Null
    Start-Sleep -Milliseconds 500
    $after = Get-Snapshot
    Write-Host ("        CPU {0}% -> {1}%   RAM {2}% -> {3}%   ({4} MB bebas)" -f `
        $before.Cpu, $after.Cpu, $before.RamPct, $after.RamPct, $after.FreeMB) -ForegroundColor Gray
    Write-Host ''

    # Anything software cannot fix goes on the record BEFORE the ceiling starts,
    # so nobody reads a running ceiling as "the machine is fine now".
    $blockers = @(Get-TuneChecks | Where-Object { -not $_.Ok -and -not $_.CanApply })
    if ($blockers.Count -gt 0) {
        Write-Host '  MASIH PERLU TINDAKAN MANUAL - tidak bisa diperbaiki software:' -ForegroundColor Red
        foreach ($b in $blockers) {
            Write-Host ("    - {0}: {1}" -f $b.Title, $b.Now) -ForegroundColor Red
            Write-Host ("      {0}" -f $b.Fix) -ForegroundColor DarkGray
        }
        Write-Host ''
    }

    Write-Host '  [4/4] Menjaga plafon CPU / RAM. Tekan Ctrl+C untuk berhenti.' -ForegroundColor Cyan
    Write-Host ''
    Start-Sleep -Seconds 2
    Start-Ceiling
}

# ---------------------------------------------------------------- diagnosis
# Turns the spike log into a verdict. The point is to separate three very
# different illnesses that all look identical to a user: "the PC is at 100%".
function Get-Verdict {
    param($Rows)

    $n = $Rows.Count
    # Plain arrays, not List[T]: casting a hashtable holding a generic List
    # to [pscustomobject] throws "Argument types do not match" on PS 5.1.
    $findings = @()
    $actions  = @()

    function _num($v) { [double]$o = 0; [void][double]::TryParse("$v", [ref]$o); return $o }
    $pct = { param($c) if ($n -eq 0) { 0 } else { [math]::Round($c / $n * 100, 0) } }

    $lowRam   = @($Rows | Where-Object { (_num $_.FreeMB) -gt 0 -and (_num $_.FreeMB) -lt 500 }).Count
    $memComp  = @($Rows | Where-Object { $_.Top1 -match 'Memory ?Compression' }).Count
    $paging   = @($Rows | Where-Object { (_num $_.PagesSec) -ge 1000 }).Count
    $diskBusy = @($Rows | Where-Object { (_num $_.DiskPct) -ge 80 }).Count
    $cpuHigh  = @($Rows | Where-Object { (_num $_.CpuPct) -ge [int]$Cfg.CeilingCpu }).Count

    $byApp = $Rows | Group-Object Top1 | Sort-Object Count -Descending
    $top   = $byApp | Select-Object -First 1

    $ramScore  = (& $pct $lowRam) + (& $pct $memComp) + (& $pct $paging)
    $diskScore = (& $pct $diskBusy)
    $appShare  = 0
    if ($top) { $appShare = (& $pct $top.Count) }

    $headline = 'Tidak ada pola dominan'
    $severity = 'info'

    if ($ramScore -ge 60) {
        $headline = 'Kehabisan RAM (bukan masalah aplikasi)'
        $severity = 'crit'
        $findings += [pscustomobject]@{ t='Tekanan memori'; s='crit'; d="Free RAM di bawah 500 MB pada $lowRam dari $n spike. Proses Memory Compression milik Windows muncul sebagai pemakan CPU teratas $memComp kali, dan paging melewati 1000/detik $paging kali. Ini pola klasik CPU 100% yang disebabkan RAM habis: Windows sibuk mengompres dan menukar halaman memori, bukan menjalankan aplikasi." }
        $actions += 'Tambah RAM. Ini satu-satunya perbaikan nyata untuk pola ini.'
        $actions += 'Sementara: kurangi jumlah tab browser dan aplikasi yang berjalan bersamaan.'
        $actions += 'Aktifkan Memory Saver di Chrome/Edge (chrome://settings/performance).'
    }
    elseif ($diskScore -ge 50) {
        $headline = 'Bottleneck disk, bukan CPU'
        $severity = 'crit'
        $findings += [pscustomobject]@{ t='Disk jenuh'; s='crit'; d="Disk berada di atas 80% sibuk pada $diskBusy dari $n spike. CPU yang terlihat penuh sering kali hanya proses menunggu I/O. Curigai HDD yang sudah tua, disk hampir penuh, atau scan antivirus." }
        $actions += 'Cek kesehatan disk (SMART) dan sisa ruang kosong.'
        $actions += 'Kalau masih HDD, mengganti ke SSD memberi lompatan terbesar.'
    }
    elseif ($appShare -ge 40 -and $top) {
        $headline = "Didominasi satu aplikasi: $($top.Name)"
        $severity = 'warn'
        $avg = [math]::Round((($top.Group | ForEach-Object { _num $_.Top1Cpu } | Measure-Object -Average).Average), 1)
        $findings += [pscustomobject]@{ t="$($top.Name) mendominasi"; s='warn'; d="Aplikasi ini menjadi pemakan CPU nomor satu pada $($top.Count) dari $n spike ($appShare%), rata-rata $avg% CPU. Beban terkonsentrasi di sini, bukan tersebar." }
        $actions += "Tangani $($top.Name) lebih dulu: update, kurangi beban kerjanya, atau throttle lewat mode Auto."
    }
    elseif ($cpuHigh -gt 0) {
        $headline = 'Beban tersebar di banyak proses'
        $severity = 'warn'
        $findings += [pscustomobject]@{ t='Tidak ada pelaku tunggal'; s='warn'; d="CPU menembus $([int]$Cfg.CeilingCpu)% pada $cpuHigh dari $n spike, tetapi tidak ada satu aplikasi pun yang mendominasi. Biasanya ini berarti terlalu banyak aplikasi background untuk kapasitas CPU yang ada." }
        $actions += 'Kurangi aplikasi startup (Task Manager > Startup).'
        $actions += 'Jalankan mode Auto untuk menekan proses background secara otomatis.'
    }
    elseif ($n -eq 0) {
        # Zero samples is not a clean bill of health, and must never read like one.
        $headline = 'Belum ada data - laporan ini hanya kondisi sesaat'
        $severity = 'info'
        $findings += [pscustomobject]@{ t='Belum ada pemantauan'; s='info'; d='Tidak ada satu pun sampel yang terekam, jadi laporan ini TIDAK menyimpulkan apa pun tentang penyebab masalah. Yang tercantum di bawah hanya potret sesaat. Jalankan mode Watch selama 1-2 jam saat PC dipakai normal, lalu ekspor ulang.' }
        $actions += 'Jalankan Watch dulu (menu 2), baru Export lagi. Tanpa itu tidak ada yang bisa disimpulkan.'
    }
    else {
        $findings += [pscustomobject]@{ t='Tidak ada masalah berat terdeteksi'; s='ok'; d="Dari $n sampel, tidak ada pola tekanan yang konsisten. Kalau user tetap mengeluh lambat, jalankan Watch lebih lama pada jam sibuk mereka." }
    }

    # Hangs, read from their own log. A user says "it freezes"; this is the
    # only evidence that actually corresponds to that word.
    $hangs = @()
    if (Test-Path $HangLog) { try { $hangs = @(Import-Csv $HangLog) } catch {} }
    if ($hangs.Count -gt 0) {
        $byApp = $hangs | Group-Object App | Sort-Object Count -Descending
        $worst = $byApp | Select-Object -First 1
        $list  = ($byApp | Select-Object -First 4 | ForEach-Object { "$($_.Name) ($($_.Count)x)" }) -join ', '
        $underRam = @($hangs | Where-Object { (_num $_.FreeMB) -gt 0 -and (_num $_.FreeMB) -lt 500 }).Count
        $d = "Tercatat $($hangs.Count) kejadian window berhenti merespons: $list."
        if ($underRam -gt 0) {
            $d += " Dari jumlah itu, $underRam terjadi saat free RAM di bawah 500 MB - freeze-nya kemungkinan besar akibat memori habis, bukan bug aplikasi."
        }
        $findings += [pscustomobject]@{ t="Aplikasi membeku: $($worst.Name)"; s='crit'; d=$d }
        if ($underRam -eq 0) {
            $actions += "Selidiki $($worst.Name) secara khusus: update ke versi terbaru, atau cek Event Viewer > Application untuk error di jam yang sama."
        }
        # A recorded freeze outranks any headline except an already-critical one
        # (RAM exhaustion or a saturated disk, which are usually the CAUSE of it).
        if ($severity -ne 'crit') {
            $headline = "Aplikasi membeku: $($worst.Name)"
            $severity = 'crit'
        }
    }

    # Secondary findings, reported regardless of the headline.
    if ($ramScore -lt 60 -and $lowRam -gt 0) {
        $findings += [pscustomobject]@{ t='Memori mulai menipis'; s='warn'; d="Free RAM sempat di bawah 500 MB pada $lowRam dari $n spike. Belum dominan, tapi layak diawasi." }
    }
    if ($diskScore -lt 50 -and $diskBusy -gt 0) {
        $findings += [pscustomobject]@{ t='Disk sesekali jenuh'; s='warn'; d="Disk di atas 80% sibuk pada $diskBusy dari $n spike." }
    }
    if (-not $script:Caps.HasEcoQoS) {
        $findings += [pscustomobject]@{ t='EcoQoS tidak tersedia'; s='info'; d="Windows build $($script:Caps.Build) belum mendukung EcoQoS. PerfGuard memakai jalur priority" + $(if ($script:Caps.HasAffinity) { ' + affinity' } else { ' saja' }) + " di mesin ini." }
    }
    if (-not $script:Caps.IsAdmin) {
        $findings += [pscustomobject]@{ t='Dijalankan tanpa hak admin'; s='info'; d='Proses milik user lain atau aplikasi elevated tidak ikut terukur maupun bisa diatur. Untuk laporan paling lengkap, jalankan sebagai administrator.' }
    }

    return [pscustomobject]@{
        Headline = $headline
        Severity = $severity
        Findings = @($findings)
        Actions  = @($actions)
        Stats    = [pscustomobject]@{
            Samples = $n; LowRam = $lowRam; MemComp = $memComp
            Paging = $paging; DiskBusy = $diskBusy; CpuHigh = $cpuHigh
            TopApp = $(if ($top) { $top.Name } else { '-' }); TopShare = $appShare
        }
    }
}

# ---------------------------------------------------------------- report export
function ConvertTo-HtmlText([string]$t) {
    if ($null -eq $t) { return '' }
    return ($t -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function New-Sparkline {
    param($Rows, [string]$Field, [string]$Colour)
    $vals = @($Rows | ForEach-Object { [double]$v = 0; [void][double]::TryParse("$($_.$Field)", [ref]$v); $v })
    if ($vals.Count -lt 2) { return '' }
    $w = 860.0; $h = 120.0
    $step = $w / ($vals.Count - 1)
    $pts = @()
    for ($i = 0; $i -lt $vals.Count; $i++) {
        $x = [math]::Round($i * $step, 1)
        $y = [math]::Round($h - ($vals[$i] / 100.0 * $h), 1)
        $pts += "$x,$y"
    }
    $line = $pts -join ' '
    $area = "0,$h " + $line + " $([math]::Round(($vals.Count-1)*$step,1)),$h"
    return @"
<polygon points="$area" fill="$Colour" opacity="0.12"/>
<polyline points="$line" fill="none" stroke="$Colour" stroke-width="2" stroke-linejoin="round"/>
"@
}

function Export-Report {
    $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $htmlOut = Join-Path $LogDir "PerfGuard-$($env:COMPUTERNAME)-$stamp.html"
    $txtOut  = Join-Path $LogDir "PerfGuard-$($env:COMPUTERNAME)-$stamp.txt"

    $rows = @()
    if (Test-Path $SpikeLog) { $rows = @(Import-Csv $SpikeLog) }
    $snap = Get-Snapshot
    $caps = $script:Caps
    $os   = Get-CimInstance Win32_OperatingSystem
    $cpu  = (Get-CimInstance Win32_Processor | Select-Object -First 1)
    $up   = (Get-Date) - $os.LastBootUpTime
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"

    $v = Get-Verdict $rows

    # ---- plain text, for pasting straight into a ticket
    $t = New-Object System.Text.StringBuilder
    [void]$t.AppendLine('PERFGUARD - LAPORAN DIAGNOSA')
    [void]$t.AppendLine('=' * 62)
    [void]$t.AppendLine("Komputer   : $($env:COMPUTERNAME)")
    [void]$t.AppendLine("User       : $($env:USERNAME)")
    [void]$t.AppendLine("Dibuat     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$t.AppendLine("OS         : $($caps.OSName) build $($caps.Build)")
    [void]$t.AppendLine("CPU        : $($cpu.Name.Trim()) - $($caps.Cores) logical")
    [void]$t.AppendLine("RAM        : $($caps.RamGB) GB")
    [void]$t.AppendLine("Uptime     : $([int]$up.TotalHours) jam $($up.Minutes) menit")
    if ($disk) {
        [void]$t.AppendLine("Disk $($env:SystemDrive)     $([math]::Round($disk.FreeSpace/1GB,1)) GB bebas dari $([math]::Round($disk.Size/1GB,1)) GB")
    }
    [void]$t.AppendLine('')
    [void]$t.AppendLine("KESIMPULAN : $($v.Headline)")
    [void]$t.AppendLine('-' * 62)
    foreach ($f in $v.Findings) {
        [void]$t.AppendLine("[$($f.s.ToUpper())] $($f.t)")
        [void]$t.AppendLine("   $($f.d)")
    }
    if ($v.Actions.Count -gt 0) {
        [void]$t.AppendLine('')
        [void]$t.AppendLine('REKOMENDASI')
        [void]$t.AppendLine('-' * 62)
        $i = 1
        foreach ($a in $v.Actions) { [void]$t.AppendLine("$i. $a"); $i++ }
    }
    [void]$t.AppendLine('')
    [void]$t.AppendLine("KONDISI SAAT LAPORAN DIBUAT")
    [void]$t.AppendLine('-' * 62)
    [void]$t.AppendLine("CPU $($snap.Cpu)%   RAM $($snap.RamPct)% ($($snap.FreeMB) MB bebas)   Disk $($snap.DiskPct)%")
    [void]$t.AppendLine('')
    $byApp = $snap.Processes | Group-Object Name | ForEach-Object {
        [pscustomobject]@{ App=$_.Name; N=$_.Count
            Cpu=[math]::Round((($_.Group|Measure-Object Cpu -Sum).Sum),1)
            Ram=[math]::Round((($_.Group|Measure-Object RamMB -Sum).Sum),0) }
    }
    [void]$t.AppendLine('Top RAM:')
    foreach ($a in ($byApp | Sort-Object Ram -Descending | Select-Object -First 8)) {
        [void]$t.AppendLine(("   {0,-24} {1,3} proses  {2,6} MB  {3,5}% CPU" -f $a.App, $a.N, $a.Ram, $a.Cpu))
    }
    $hangRows = @()
    if (Test-Path $HangLog) { try { $hangRows = @(Import-Csv $HangLog) } catch {} }
    if ($hangRows.Count -gt 0) {
        [void]$t.AppendLine('')
        [void]$t.AppendLine("FREEZE / NOT RESPONDING ($($hangRows.Count) kejadian)")
        [void]$t.AppendLine('-' * 62)
        foreach ($g in ($hangRows | Group-Object App | Sort-Object Count -Descending | Select-Object -First 8)) {
            $fr = [math]::Round((($g.Group | ForEach-Object { [int]$_.FreeMB } | Measure-Object -Average).Average),0)
            [void]$t.AppendLine(("   {0,-24} {1,4} kali   RAM bebas rata-rata {2,5} MB" -f $g.Name, $g.Count, $fr))
        }
    }

    if ($rows.Count -gt 0) {
        [void]$t.AppendLine('')
        [void]$t.AppendLine("RIWAYAT SPIKE ($($rows.Count) tercatat, $($rows[0].Time) s/d $($rows[-1].Time))")
        [void]$t.AppendLine('-' * 62)
        foreach ($g in ($rows | Group-Object Top1 | Sort-Object Count -Descending | Select-Object -First 8)) {
            $avg = [math]::Round((($g.Group | ForEach-Object { [double]$x=0; [void][double]::TryParse("$($_.Top1Cpu)",[ref]$x); $x } | Measure-Object -Average).Average),1)
            [void]$t.AppendLine(("   {0,-24} {1,4} spike   rata-rata {2,5}% CPU" -f $g.Name, $g.Count, $avg))
        }
    } else {
        [void]$t.AppendLine('')
        [void]$t.AppendLine('Belum ada riwayat spike. Jalankan mode Watch dulu untuk data yang berarti.')
    }
    $noBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($txtOut, $t.ToString(), $noBom)

    # ---- HTML, fully self-contained: no fonts, no CDN, no internet needed
    $sevColour = @{ crit='#b3261e'; warn='#8a6100'; ok='#1b5e20'; info='#37474f' }
    $sevLabel  = @{ crit='KRITIS'; warn='PERHATIAN'; ok='BAIK'; info='INFO' }

    $findHtml = ''
    foreach ($f in $v.Findings) {
        $c = $sevColour[$f.s]; $l = $sevLabel[$f.s]
        $findHtml += "<div class='f' style='border-left-color:$c'><div class='ft'><span class='badge' style='background:$c'>$l</span>$(ConvertTo-HtmlText $f.t)</div><p>$(ConvertTo-HtmlText $f.d)</p></div>`n"
    }
    $actHtml = ''
    if ($v.Actions.Count -gt 0) {
        $actHtml = "<h2>Rekomendasi</h2><ol class='act'>"
        foreach ($a in $v.Actions) { $actHtml += "<li>$(ConvertTo-HtmlText $a)</li>" }
        $actHtml += '</ol>'
    }

    $ramRows = ''
    foreach ($a in ($byApp | Sort-Object Ram -Descending | Select-Object -First 10)) {
        $ramRows += "<tr><td>$(ConvertTo-HtmlText $a.App)</td><td class='n'>$($a.N)</td><td class='n'>$($a.Ram)</td><td class='n'>$($a.Cpu)</td></tr>"
    }

    $spikeRows = ''
    $chart = ''
    if ($rows.Count -gt 0) {
        foreach ($g in ($rows | Group-Object Top1 | Sort-Object Count -Descending | Select-Object -First 10)) {
            $avg = [math]::Round((($g.Group | ForEach-Object { [double]$x=0; [void][double]::TryParse("$($_.Top1Cpu)",[ref]$x); $x } | Measure-Object -Average).Average),1)
            $share = [math]::Round($g.Count / $rows.Count * 100, 0)
            $spikeRows += "<tr><td>$(ConvertTo-HtmlText $g.Name)</td><td class='n'>$($g.Count)</td><td class='n'>$share%</td><td class='n'>$avg</td></tr>"
        }
        $cpuLine = New-Sparkline $rows 'CpuPct' '#b3261e'
        $ramLine = New-Sparkline $rows 'RamPct' '#1565c0'
        if ($cpuLine) {
            $chart = @"
<h2>Garis waktu spike</h2>
<div class='chart'>
<svg viewBox="0 0 860 120" preserveAspectRatio="none" width="100%" height="140" role="img"
     aria-label="Grafik CPU dan RAM sepanjang periode pemantauan">
  <line x1="0" y1="30" x2="860" y2="30" stroke="#e0e0e0" stroke-width="1"/>
  <line x1="0" y1="60" x2="860" y2="60" stroke="#e0e0e0" stroke-width="1"/>
  <line x1="0" y1="90" x2="860" y2="90" stroke="#e0e0e0" stroke-width="1"/>
  $ramLine
  $cpuLine
</svg>
<div class='legend'><span class='k' style='background:#b3261e'></span>CPU
  <span class='k' style='background:#1565c0'></span>RAM
  <span class='ax'>garis bantu: 25% / 50% / 75%</span></div>
</div>
"@
        }
    }

    $diskLine = ''
    if ($disk) {
        $diskLine = "$([math]::Round($disk.FreeSpace/1GB,1)) GB bebas dari $([math]::Round($disk.Size/1GB,1)) GB"
    }
    $ecoLine = 'EcoQoS + priority'
    if (-not $caps.HasEcoQoS) {
        if ($caps.HasAffinity) { $ecoLine = 'priority + affinity (EcoQoS tidak tersedia)' }
        else { $ecoLine = 'priority saja (EcoQoS tidak tersedia)' }
    }
    $hdrColour = $sevColour[$v.Severity]

    $css = @'
*{box-sizing:border-box}
body{margin:0;padding:32px;font:14px/1.6 "Segoe UI",system-ui,sans-serif;color:#1a1a1a;background:#fff}
.wrap{max-width:920px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:#555;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid #e0e0e0}
.sub{color:#666;margin:0 0 24px;font-size:13px}
.verdict{border:1px solid #ddd;border-top:4px solid;border-radius:6px;padding:16px 20px;margin:0 0 8px;background:#fafafa}
.verdict h3{margin:0;font-size:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:#e0e0e0;border:1px solid #e0e0e0;border-radius:6px;overflow:hidden;margin:16px 0}
.cell{background:#fff;padding:12px 14px}
.cell .lab{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#777}
.cell .val{font-size:17px;font-weight:600;margin-top:2px}
.f{border-left:4px solid;background:#fafafa;padding:12px 16px;margin:0 0 10px;border-radius:0 4px 4px 0}
.ft{font-weight:600;display:flex;align-items:center;gap:10px}
.badge{color:#fff;font-size:10px;font-weight:700;letter-spacing:.06em;padding:2px 8px;border-radius:3px}
.f p{margin:6px 0 0;color:#444}
.act li{margin:6px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#777;border-bottom:1px solid #ddd;padding:6px 8px}
td{padding:6px 8px;border-bottom:1px solid #f0f0f0}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.chart{border:1px solid #e0e0e0;border-radius:6px;padding:12px}
.legend{font-size:12px;color:#666;margin-top:8px;display:flex;align-items:center;gap:6px}
.k{display:inline-block;width:11px;height:11px;border-radius:2px;margin-left:10px}
.ax{margin-left:auto;color:#999}
.note{background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:12px 16px;margin:24px 0;font-size:13px}
footer{margin-top:36px;padding-top:12px;border-top:1px solid #e0e0e0;color:#888;font-size:12px}
@media print{body{padding:0}.verdict,.f,.chart{break-inside:avoid}}
'@

    $html = @"
<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PerfGuard - $(ConvertTo-HtmlText $env:COMPUTERNAME)</title>
<style>$css</style></head><body><div class="wrap">

<h1>Laporan Diagnosa Performa</h1>
<p class="sub">$(ConvertTo-HtmlText $env:COMPUTERNAME) &middot; user $(ConvertTo-HtmlText $env:USERNAME) &middot; dibuat $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<div class="verdict" style="border-top-color:$hdrColour">
  <h3 style="color:$hdrColour">$(ConvertTo-HtmlText $v.Headline)</h3>
</div>

<h2>Spesifikasi mesin</h2>
<div class="grid">
  <div class="cell"><div class="lab">Sistem operasi</div><div class="val">$(ConvertTo-HtmlText $caps.OSName)</div><div class="lab">build $($caps.Build)</div></div>
  <div class="cell"><div class="lab">Prosesor</div><div class="val">$($caps.Cores) logical</div><div class="lab">$(ConvertTo-HtmlText $cpu.Name.Trim())</div></div>
  <div class="cell"><div class="lab">Memori</div><div class="val">$($caps.RamGB) GB</div><div class="lab">$($snap.FreeMB) MB bebas saat ini</div></div>
  <div class="cell"><div class="lab">Disk $($env:SystemDrive)</div><div class="val">$diskLine</div></div>
  <div class="cell"><div class="lab">Uptime</div><div class="val">$([int]$up.TotalHours) j $($up.Minutes) m</div></div>
  <div class="cell"><div class="lab">Metode throttling</div><div class="val" style="font-size:13px">$ecoLine</div></div>
</div>

<h2>Temuan</h2>
$findHtml
$actHtml
$chart

$(if ($hangRows.Count -gt 0) {
"<h2>Freeze / not responding ($($hangRows.Count) kejadian)</h2>
<table><thead><tr><th>Aplikasi</th><th class='n'>Kejadian</th><th class='n'>RAM bebas rata-rata (MB)</th></tr></thead><tbody>" +
(($hangRows | Group-Object App | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
   $fr = [math]::Round((($_.Group | ForEach-Object { [int]$_.FreeMB } | Measure-Object -Average).Average),0)
   "<tr><td>$(ConvertTo-HtmlText $_.Name)</td><td class='n'>$($_.Count)</td><td class='n'>$fr</td></tr>"
 }) -join '') + "</tbody></table>"
})

<h2>Pemakai memori terbesar saat ini</h2>
<table><thead><tr><th>Aplikasi</th><th class="n">Proses</th><th class="n">RAM MB</th><th class="n">CPU %</th></tr></thead>
<tbody>$ramRows</tbody></table>

$(if ($rows.Count -gt 0) {
"<h2>Pelaku spike ($($rows.Count) tercatat, $(ConvertTo-HtmlText $rows[0].Time) s/d $(ConvertTo-HtmlText $rows[-1].Time))</h2>
<table><thead><tr><th>Aplikasi</th><th class='n'>Spike</th><th class='n'>Porsi</th><th class='n'>Rata-rata CPU %</th></tr></thead>
<tbody>$spikeRows</tbody></table>"
} else {
"<div class='note'><strong>Belum ada riwayat spike.</strong> Laporan ini hanya berisi kondisi sesaat. Jalankan mode <em>Watch</em> selama 1-2 jam saat PC dipakai normal, lalu ekspor ulang untuk mendapat diagnosa berbasis data.</div>"
})

<div class="note">
<strong>Batas alat ini.</strong> PerfGuard mengatur prioritas dan penjadwalan proses.
Ia tidak bisa menciptakan memori yang tidak ada. Kalau kesimpulan di atas menyebut
kehabisan RAM, menambah kapasitas adalah satu-satunya perbaikan nyata.
</div>

<footer>PerfGuard &middot; laporan mandiri, tidak membutuhkan koneksi internet untuk dibuka.</footer>
</div></body></html>
"@
    [System.IO.File]::WriteAllText($htmlOut, $html, $noBom)

    return [pscustomobject]@{ Html = $htmlOut; Text = $txtOut; Verdict = $v }
}

# ---------------------------------------------------------------- scheduled task
function Install-Task {
    $name = 'PerfGuard Auto'
    $ps   = (Get-Command powershell.exe).Source
    $args = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Mode auto' -f (Join-Path $Root 'PerfGuard.ps1')

    if (-not (Get-Command New-ScheduledTaskAction -ErrorAction SilentlyContinue)) {
        # Windows 7 / Server 2008 R2: no ScheduledTasks module, use schtasks.exe.
        $cmd = '"{0}" {1}' -f $ps, $args
        & schtasks.exe /Create /TN $name /TR $cmd /SC ONLOGON /F | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host "  Registered '$name' via schtasks (legacy Windows)." -ForegroundColor Green }
        else { Write-Host "  schtasks failed with exit code $LASTEXITCODE." -ForegroundColor Red }
        return
    }
    $action    = New-ScheduledTaskAction -Execute $ps -Argument $args
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Host "  Registered scheduled task '$name' - PerfGuard auto mode now starts at logon." -ForegroundColor Green
    Write-Host "  Remove it with:  PerfGuard.cmd uninstall" -ForegroundColor DarkGray
}

function Uninstall-Task {
    $name = 'PerfGuard Auto'
    try {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "  Removed scheduled task '$name'." -ForegroundColor Green
    } catch {
        Write-Host "  No scheduled task named '$name' was registered." -ForegroundColor DarkGray
    }
}

function Show-Help {
    Show-Header
    Write-Host @'
  PerfGuard.cmd <mode> [options]

  MODES
    status      Snapshot of CPU / RAM and the top consumers.        (default)
    profile     Re-scan this machine and regenerate config.json.
    watch       Monitor and log spikes. Takes NO action.
    auto        Monitor and apply relief when thresholds are crossed.
    optimize    One shot: profile, apply safe fixes, then hold the ceiling.
    memclear    RAMMap-style system memory clearing. Needs administrator.
                Default set skips the full standby purge; -Purge adds it.
    ceiling     Keep CPU and RAM below a hard ceiling (default 80%) via a
                four-step escalation ladder. -Gentle disables the last step.
    guard       Anti-lag mode: prevents stutter instead of reacting to it.
                Boosts the focused app, holds background apps down continuously,
                acts at lower thresholds, and reports apps that stop responding.
    tune        Audit system-level causes of lag and freezing. Add -Apply to fix
                the two settings that are safe to change automatically.
    relieve     Apply one relief pass right now, then exit.
    restore     Undo everything: resume, un-throttle, restore priority.
    report      Summarise the spike log - your repeat offenders.
    export      Write a self-contained HTML + TXT diagnosis report to logs\.
    install     Run auto mode automatically at every logon.
    uninstall   Remove that scheduled task.

  OPTIONS
    -CpuThreshold <n>   CPU % that counts as a spike        (default 80)
    -RamThreshold <n>   RAM % that counts as a spike        (default 80)
    -Seconds <n>        Stop watch/auto after n seconds     (default: run forever)
    -PurgeAt <n>        RAM % that triggers the automatic memory purge (80)
    -PurgeTo <n>        RAM % the purge keeps sweeping down to      (75)
    -Aggressive         Also SUSPEND background apps listed in SuspendTargets
    -DryRun             Show what would happen, change nothing

  WHAT IT ACTUALLY DOES
    EcoQoS + BelowNormal priority on background CPU burners.
      Identical to Task Manager's "Efficiency mode". Fully reversible.
    Working-set trim, but ONLY on processes that are idle right now.
      Trimming a busy process is what makes fake "RAM boosters" slow you down.
    Optional suspend of background apps you opt into, auto-resumed the
      moment you switch back to them.

    It never kills a process, never touches Windows internals, Defender,
    your shell, or whatever app you currently have in focus.

  EDIT config.json to change thresholds and the target lists.
'@ -ForegroundColor Gray
    Write-Host ''
}

# ---------------------------------------------------------------- dispatch
switch ($Mode) {
    'help'      { Show-Help }
    'status'    {
        Show-Header
        $s = Get-Snapshot
        Show-Snapshot $s (Get-ForegroundApp)
        $active = @($script:Touched.Values | Where-Object { $_.Eco -or $_.Suspended })
        if ($active.Count -gt 0) {
            Write-Host ("  PerfGuard is currently holding {0} process(es) throttled/suspended." -f $active.Count) -ForegroundColor Yellow
            foreach ($a in $active) {
                $what = 'throttled'
                if ($a.Suspended) { $what = 'SUSPENDED' }
                Write-Host ("    {0} ({1}) - {2}" -f $a.Name, $a.Pid, $what) -ForegroundColor Yellow
            }
            Write-Host '    Run:  PerfGuard.cmd restore' -ForegroundColor DarkGray
            Write-Host ''
        }
    }
    'profile'   { Show-Header; New-Profile -Loud | Out-Null; Write-Host ''
                  Write-Host '  Edit config.json to adjust, or re-run profile after installing/removing apps.' -ForegroundColor DarkGray
                  Write-Host '' }
    'watch'     { Start-Loop }
    'auto'      { Start-Loop -Act }
    'guard'     { Start-Loop -Act -GuardMode }
    'ceiling'   { Start-Ceiling }
    'optimize'  { Invoke-Optimize }
    'memclear'  {
        $ops = @($Cfg.MemPurgeOps)
        if ($Purge) { $ops = @('workingsets','systemws','modified','standby','standby0') }
        Show-MemClear -Ops $ops
    }
    'tune'      { Show-Header; Invoke-Tune -Apply:$Apply; Write-Host '' }
    'relieve'   {
        Show-Header
        $s = Get-Snapshot
        Write-Host ("  CPU {0}%   RAM {1}%   ({2} MB free)" -f $s.Cpu, $s.RamPct, $s.FreeMB) -ForegroundColor White
        Write-Host ''
        Invoke-Relief $s (Get-ForegroundApp) -Loud | Out-Null
        [void](Invoke-AutoMemPurge $s '  ')
        Start-Sleep -Milliseconds 600
        $after = Get-Snapshot
        Write-Host ''
        Write-Host ("  Now: CPU {0}%   RAM {1}%   ({2} MB free, {3} MB gained)" -f `
            $after.Cpu, $after.RamPct, $after.FreeMB, ($after.FreeMB - $s.FreeMB)) -ForegroundColor Cyan
        if ($after.RamPct -ge [int]$Cfg.CeilingRam) {
            Write-Host ''
            Write-Host ("  RAM masih di atas {0}%. Menahan prioritas tidak menciptakan memori:" -f [int]$Cfg.CeilingRam) -ForegroundColor Red
            Write-Host '  tutup tab, atau tambah RAM. Alat yang menjanjikan sebaliknya membohongi kamu.' -ForegroundColor Red
        }
        Write-Host '  Undo with:  PerfGuard.cmd restore' -ForegroundColor DarkGray
        Write-Host ''
    }
    'restore'   { Show-Header; Restore-All | Out-Null; Write-Host '' }
    'report'    { Show-Report }
    'export'    {
        Show-Header
        Write-Host '  Menyusun laporan...' -ForegroundColor DarkGray
        $r = Export-Report
        Write-Host ''
        Write-Host ("  Kesimpulan: {0}" -f $r.Verdict.Headline) -ForegroundColor Cyan
        Write-Host ''
        Write-Host '  Laporan tersimpan:' -ForegroundColor Green
        Write-Host ("    {0}" -f $r.Html) -ForegroundColor Gray
        Write-Host ("    {0}" -f $r.Text) -ForegroundColor Gray
        Write-Host ''
        Write-Host '  HTML bisa dibuka tanpa internet, dan bisa langsung di-print ke PDF.' -ForegroundColor DarkGray
        Write-Host '  TXT siap ditempel ke tiket.' -ForegroundColor DarkGray
        Write-Host ''
    }
    'install'   { Show-Header; Install-Task; Write-Host '' }
    'uninstall' { Show-Header; Uninstall-Task; Write-Host '' }
}
