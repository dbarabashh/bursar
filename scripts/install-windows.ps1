#Requires -Version 5.1
# Installs bursar on Windows. The daemon runs as a Windows service under its own
# virtual account (NT SERVICE\bursar): no password, cannot log in. The key and
# policy live in %ProgramData%\bursar, locked with an ACL so that only that
# account (read) and elevated Administrators can open them; the code lives in
# %ProgramFiles%\bursar, which your normal (non-elevated) user cannot change.
# An agent running as you without elevation can do neither.
#
# From a terminal opened with "Run as administrator":
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-windows.ps1
param(
  # `npm run setup` pipes the policy in, so it never sits in a file a
  # non-elevated process (an agent) could rewrite before this script reads it.
  [switch]$PolicyStdin,
  [switch]$ReplacePolicy
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Name = 'bursar'
$Account = "NT SERVICE\$Name"
$Prefix = Join-Path $env:ProgramFiles $Name
$State = Join-Path $env:ProgramData $Name
$Src = Split-Path -Parent $PSScriptRoot
$NodeExe = Join-Path $Prefix 'bin\node.exe'
$Cli = Join-Path $Prefix 'app\src\index.ts'
$ServiceExe = Join-Path $Prefix 'bin\bursar-service.exe'
$PolicyPath = Join-Path $State 'policy.yaml'
$KeyPath = Join-Path $State 'key'
$Port = 8402
# Well-known SIDs, so this works on non-English Windows too.
$SYSTEM = '*S-1-5-18'
$ADMINS = '*S-1-5-32-544'

function Die([string]$msg) { [Console]::Error.WriteLine("install: $msg"); exit 1 }

function Native([string]$exe, [string[]]$argList) {
  & $exe @argList
  if ($LASTEXITCODE -ne 0) { Die "$exe $($argList -join ' ') failed (exit $LASTEXITCODE)" }
}

function Write-Utf8([string]$path, [string]$text) {
  [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding $false))
}

# Only SYSTEM, Administrators and (read) the service account may open a secret file.
function Lock-Secret([string]$path) {
  Native icacls.exe @($path, '/inheritance:r', '/grant:r', "${SYSTEM}:F", "${ADMINS}:F", "${Account}:R") | Out-Null
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Die 'run from a terminal opened with "Run as administrator"'
}
if ($PSVersionTable.PSEdition -ne 'Desktop') {
  Die 'run with Windows PowerShell (powershell.exe), not pwsh: the service host is compiled with the .NET Framework'
}
if (-not (Test-Path (Join-Path $Src 'node_modules\@noble\curves'))) { Die "run npm ci in $Src first" }

# The service runs the official Node build, pinned here by SHA-256, never the
# operator's own node.exe: that can sit in a folder a non-elevated process
# (an agent) can write. Keep NodeVersion in step with scripts/node-release.sh.
$NodeVersion = 'v22.23.4'
$NodeSha256 = 'cbc74b5e0982c9dbb41525fd8fb5dcd32fbee237863f7829072f4639a1ce5f20'
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { Die "no pinned Node build for $env:PROCESSOR_ARCHITECTURE" }
$NodeTmp = Join-Path ([IO.Path]::GetTempPath()) ("bursar-node-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $NodeTmp | Out-Null
$NodeZip = Join-Path $NodeTmp 'node.zip'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -UseBasicParsing -Uri "https://nodejs.org/dist/$NodeVersion/node-$NodeVersion-win-x64.zip" -OutFile $NodeZip
# .NET directly, not Get-FileHash / Expand-Archive: those live in script modules
# that Windows PowerShell cannot load when started from pwsh (PSModulePath).
$sha = [Security.Cryptography.SHA256]::Create()
$stream = [IO.File]::OpenRead($NodeZip)
try { $got = -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) } finally { $stream.Dispose() }
if ($got -ne $NodeSha256) {
  Remove-Item -Recurse -Force $NodeTmp
  Die "node-$NodeVersion-win-x64.zip does not match its pinned SHA-256; not installing it"
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory($NodeZip, $NodeTmp)
$NodeExeSrc = Join-Path $NodeTmp "node-$NodeVersion-win-x64\node.exe"
Write-Host "downloaded Node $NodeVersion (SHA-256 checked)"

# Stop a running daemon first: Windows does not let us replace files in use.
$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
  Stop-Service -Name $Name -Force
  $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

# ---------- code ----------
$New = "$Prefix.new"
$Old = "$Prefix.old"
if (Test-Path $New) { Remove-Item -Recurse -Force $New }
New-Item -ItemType Directory -Force -Path (Join-Path $New 'bin'), (Join-Path $New 'app'), (Join-Path $New 'cli') | Out-Null
Copy-Item -Path $NodeExeSrc -Destination (Join-Path $New 'bin\node.exe')
Remove-Item -Recurse -Force $NodeTmp
foreach ($item in 'src', 'node_modules', 'package.json') {
  Copy-Item -Recurse -Path (Join-Path $Src $item) -Destination (Join-Path $New 'app')
}

# A minimal service host: starts node, logs its output, restarts it if it dies,
# stops it with the service. Compiled here so no third-party binary is needed.
$serviceSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;

public sealed class BursarService : ServiceBase {
  readonly string bin = AppDomain.CurrentDomain.BaseDirectory;
  readonly string state = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "bursar");
  readonly object gate = new object();
  volatile bool stopping;
  Process child;
  Thread loop;
  StreamWriter log;

  public BursarService() { ServiceName = "bursar"; CanStop = true; CanShutdown = true; }

  static string Quote(string s) { return "\"" + s + "\""; }

  void Log(string line) {
    if (line == null) return;
    lock (gate) {
      try { if (log != null) log.WriteLine(line); } catch { }
    }
  }

  void Run() {
    while (!stopping) {
      try {
        var psi = new ProcessStartInfo(
          Path.Combine(bin, "node.exe"),
          Quote(Path.GetFullPath(Path.Combine(bin, @"..\app\src\index.ts"))) +
            " serve --policy " + Quote(Path.Combine(state, "policy.yaml")));
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.WorkingDirectory = state;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        var p = new Process();
        p.StartInfo = psi;
        p.OutputDataReceived += (s, e) => Log(e.Data);
        p.ErrorDataReceived += (s, e) => Log(e.Data);
        p.Start();
        child = p;
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        p.WaitForExit();
        if (!stopping) Log(DateTime.UtcNow.ToString("o") + " bursar exited with code " + p.ExitCode + ", restarting in 10s");
      } catch (Exception e) {
        Log(DateTime.UtcNow.ToString("o") + " " + e.Message);
      }
      for (int i = 0; i < 100 && !stopping; i++) Thread.Sleep(100);
    }
  }

  protected override void OnStart(string[] args) {
    log = new StreamWriter(Path.Combine(state, "bursar.log"), true);
    log.AutoFlush = true;
    loop = new Thread(Run);
    loop.IsBackground = true;
    loop.Start();
  }

  protected override void OnStop() { Halt(); }
  protected override void OnShutdown() { Halt(); }

  void Halt() {
    stopping = true;
    try {
      var p = child;
      if (p != null && !p.HasExited) { p.Kill(); p.WaitForExit(5000); }
    } catch { }
    if (loop != null) loop.Join(5000);
    lock (gate) {
      if (log != null) { log.Dispose(); log = null; }
    }
  }

  public static void Main() { ServiceBase.Run(new BursarService()); }
}
'@
Add-Type -TypeDefinition $serviceSource -Language CSharp `
  -ReferencedAssemblies System.ServiceProcess `
  -OutputAssembly (Join-Path $New 'bin\bursar-service.exe') -OutputType ConsoleApplication

# The bursar command. It lives in its own folder so that adding it to PATH does
# not put a second node.exe there. It needs elevation: the state is admin-only.
$wrapper = @'
@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
  echo bursar: run this from a terminal opened with "Run as administrator" 1>&2
  exit /b 1
)
set "NODE=%~dp0..\bin\node.exe"
set "CLI=%~dp0..\app\src\index.ts"
set "NEEDPOLICY=1"
if "%~1"=="" set "NEEDPOLICY="
if /i "%~1"=="keygen" set "NEEDPOLICY="
if /i "%~1"=="-h" set "NEEDPOLICY="
if /i "%~1"=="--help" set "NEEDPOLICY="
echo.%*| findstr /c:"--policy" >nul && set "NEEDPOLICY="
if not defined NEEDPOLICY goto plain
"%NODE%" "%CLI%" %* --policy "%ProgramData%\bursar\policy.yaml"
exit /b %ERRORLEVEL%
:plain
"%NODE%" "%CLI%" %*
exit /b %ERRORLEVEL%
'@
Set-Content -Encoding Ascii -Path (Join-Path $New 'cli\bursar.cmd') -Value $wrapper

if (Test-Path $Old) { Remove-Item -Recurse -Force $Old }
if (Test-Path $Prefix) { Rename-Item -Path $Prefix -NewName "$Name.old" }
Rename-Item -Path $New -NewName $Name
if (Test-Path $Old) { Remove-Item -Recurse -Force $Old -ErrorAction SilentlyContinue }

$cliDir = Join-Path $Prefix 'cli'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($machinePath -split ';') -notcontains $cliDir) {
  [Environment]::SetEnvironmentVariable('Path', ($machinePath.TrimEnd(';') + ';' + $cliDir), 'Machine')
  Write-Host "added $cliDir to PATH (open a new terminal to use the bursar command)"
}
Write-Host "installed code to $Prefix (only Administrators can change it)"

# ---------- service account ----------
if ($null -eq (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
  New-Service -Name $Name -BinaryPathName "`"$ServiceExe`"" -DisplayName 'bursar wallet daemon' `
    -Description 'Signs agent payments within the bursar spending policy.' -StartupType Automatic | Out-Null
  Write-Host "created service $Name"
}
Native sc.exe @('config', $Name, 'obj=', $Account) | Out-Null
Native sc.exe @('sidtype', $Name, 'unrestricted') | Out-Null
Native sc.exe @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/10000/restart/10000/restart/60000') | Out-Null
Native icacls.exe @($Prefix, '/grant', "${Account}:(OI)(CI)RX") | Out-Null

# ---------- state ----------
# Any user may create folders in %ProgramData% and owns what it creates, and
# icacls below keeps explicit ACEs it does not name. A state folder this
# installer made is owned by Administrators (set just below) and only
# Administrators and the service can write in it, so it is enough to refuse a
# pre-existing folder with any other owner: someone else made it, may have
# planted a key or policy and may keep write access.
if (Test-Path -LiteralPath $State) {
  $owner = (Get-Acl -LiteralPath $State).GetOwner([Security.Principal.SecurityIdentifier]).Value
  if (@('S-1-5-32-544', 'S-1-5-18') -notcontains $owner) {
    Die "$State is owned by $owner, not Administrators: this installer did not create it. Check what is inside, delete it as Administrator and run the install again"
  }
}
New-Item -ItemType Directory -Force -Path $State | Out-Null
Native icacls.exe @($State, '/setowner', $ADMINS) | Out-Null
Native icacls.exe @($State, '/inheritance:r', '/grant:r', "${SYSTEM}:(OI)(CI)F", "${ADMINS}:(OI)(CI)F", "${Account}:(OI)(CI)M") | Out-Null

if (-not (Test-Path $KeyPath)) {
  Native $NodeExe @($Cli, 'keygen', '--out', $KeyPath) | Out-Null
  Write-Host "generated a new wallet key in $KeyPath (only the service and Administrators can read it)"
}
Lock-Secret $KeyPath

$newToken = $null
$backup = "$PolicyPath.bak"
if ($PolicyStdin) {
  # A policy prepared by `npm run setup`; it already holds its own agent token.
  $policyText = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($policyText)) { Die '-PolicyStdin but no policy came in on stdin' }
  if (Test-Path $PolicyPath) {
    if (-not $ReplacePolicy) { Die "$PolicyPath exists; pass -ReplacePolicy to replace it" }
    Copy-Item -Force $PolicyPath $backup
    Lock-Secret $backup
  }
  Write-Utf8 $PolicyPath $policyText
  Write-Host "wrote $PolicyPath from setup (the service can only read it)"
} elseif (-not (Test-Path $PolicyPath)) {
  # The same policy `npm run setup` writes with its defaults (testnet, careful limits).
  $newToken = (& $NodeExe -e 'process.stdout.write(require(''node:crypto'').randomBytes(24).toString(''hex''))')
  $printed = (& $NodeExe (Join-Path $Prefix 'app\src\setup.ts') --print-policy --yes) -join "`n"
  if ($LASTEXITCODE -ne 0 -or $printed -notmatch '__AGENT_TOKEN_SET_BY_INSTALLER__') {
    Die 'could not write the default policy (npm run setup -- --print-policy --yes failed)'
  }
  Write-Utf8 $PolicyPath (($printed -replace '__AGENT_TOKEN_SET_BY_INSTALLER__', $newToken) + "`n")
  Write-Host "wrote $PolicyPath (the service can only read it)"
}
Lock-Secret $PolicyPath

& $NodeExe $Cli address --policy $PolicyPath | Out-Null
if ($LASTEXITCODE -ne 0) {
  if ($PolicyStdin -and (Test-Path $backup)) {
    Copy-Item -Force $backup $PolicyPath
    Lock-Secret $PolicyPath
    Die 'the new policy did not pass the check; the previous one is restored'
  }
  Die "policy check failed, fix $PolicyPath (notepad, as Administrator)"
}

# ---------- start ----------
Start-Service -Name $Name
$up = $false
for ($i = 0; $i -lt 20 -and -not $up; $i++) {
  Start-Sleep -Milliseconds 500
  $tcp = New-Object Net.Sockets.TcpClient
  try { $tcp.Connect('127.0.0.1', $Port); $up = $true } catch { } finally { $tcp.Close() }
}
if (-not $up) {
  $logFile = Join-Path $State 'bursar.log'
  if (Test-Path $logFile) { Get-Content -Tail 20 $logFile }
  Die "the daemon did not start listening on 127.0.0.1:$Port (log: $logFile)"
}
Write-Host ''
Write-Host "daemon: Get-Service $Name (log: $State\bursar.log)"
& $NodeExe $Cli address --policy $PolicyPath
if ($newToken) {
  Write-Host ''
  Write-Host "agent token for claude-code (shown once, it is also in $PolicyPath):"
  Write-Host "  $newToken"
}
