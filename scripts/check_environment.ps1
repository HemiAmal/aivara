<#
.SYNOPSIS
    AIVARA Phase 1 Environment Validator
.DESCRIPTION
    Validates local development environment prerequisites for AIVARA strictly offline.
    Never connects to the internet, never downloads packages, and never installs software.
    Returns 0 on success (all mandatory prerequisites met), or non-zero if mandatory items are missing.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
$Script:ExitCode = 0

function Write-Header {
    param([string]$Text)
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Write-CheckResult {
    param(
        [string]$Item,
        [string]$Value,
        [string]$Status, # "PASS", "WARN", "FAIL"
        [string]$Note = ""
    )
    switch ($Status) {
        "PASS" {
            Write-Host " [PASS] " -ForegroundColor Green -NoNewline
            Write-Host "$Item : " -ForegroundColor White -NoNewline
            Write-Host "$Value" -ForegroundColor Gray
        }
        "WARN" {
            Write-Host " [WARN] " -ForegroundColor Yellow -NoNewline
            Write-Host "$Item : " -ForegroundColor White -NoNewline
            Write-Host "$Value" -ForegroundColor Yellow
            if ($Note) {
                Write-Host "        -> $Note" -ForegroundColor DarkYellow
            }
        }
        "FAIL" {
            Write-Host " [FAIL] " -ForegroundColor Red -NoNewline
            Write-Host "$Item : " -ForegroundColor White -NoNewline
            Write-Host "$Value" -ForegroundColor Red
            if ($Note) {
                Write-Host "        -> $Note" -ForegroundColor Red
            }
            $Script:ExitCode = 1
        }
    }
}

Write-Header "AIVARA Phase 1: Offline Environment Check"

# 1. Operating System
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-CheckResult "Operating System" "$($os.Caption) ($($os.OSArchitecture), Build $($os.Version))" "PASS"
} catch {
    Write-CheckResult "Operating System" "Unable to query WMI/CIM for OS" "WARN"
}

# 2. CPU & Memory
try {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeRamGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    Write-CheckResult "Processor (CPU)" "$($cpu.Name) ($($cpu.NumberOfCores) Cores / $($cpu.NumberOfLogicalProcessors) Threads)" "PASS"
    
    if ($totalRamGB -ge 16) {
        Write-CheckResult "System Memory (RAM)" "$totalRamGB GB Total ($freeRamGB GB Free)" "PASS"
    } elseif ($totalRamGB -ge 8) {
        Write-CheckResult "System Memory (RAM)" "$totalRamGB GB Total ($freeRamGB GB Free)" "WARN" "16GB+ recommended for large image dataset embeddings."
    } else {
        Write-CheckResult "System Memory (RAM)" "$totalRamGB GB Total ($freeRamGB GB Free)" "FAIL" "Minimum 8GB RAM required."
    }
} catch {
    Write-CheckResult "CPU / RAM" "Error reading hardware specs" "WARN"
}

# 3. Disk Space
try {
    $cDrive = Get-PSDrive -Name "C" -ErrorAction SilentlyContinue
    $dDrive = Get-PSDrive -Name "D" -ErrorAction SilentlyContinue

    if ($cDrive) {
        $cFreeGB = [math]::Round($cDrive.Free / 1GB, 1)
        if ($cFreeGB -lt 15) {
            Write-CheckResult "Disk Space (C:)" "$cFreeGB GB free" "WARN" "Low disk space on C:. Configure models and virtualenvs on Drive D:."
        } else {
            Write-CheckResult "Disk Space (C:)" "$cFreeGB GB free" "PASS"
        }
    }
    if ($dDrive) {
        $dFreeGB = [math]::Round($dDrive.Free / 1GB, 1)
        if ($dFreeGB -ge 50) {
            Write-CheckResult "Disk Space (D: Project Drive)" "$dFreeGB GB free" "PASS"
        } else {
            Write-CheckResult "Disk Space (D: Project Drive)" "$dFreeGB GB free" "WARN" "Recommended 50GB+ for model caches and dataset imports."
        }
    }
} catch {
    Write-CheckResult "Disk Storage" "Error checking disk spaces" "WARN"
}

# 4. Git
$gitCmd = Get-Command "git" -ErrorAction SilentlyContinue
if ($gitCmd) {
    $gitVer = & git --version
    Write-CheckResult "Git Version" $gitVer "PASS"
} else {
    Write-CheckResult "Git" "Not installed or not in PATH" "FAIL" "Git is a mandatory prerequisite."
}

# 5. Node.js & npm
$nodeCmd = Get-Command "node" -ErrorAction SilentlyContinue
if ($nodeCmd) {
    $nodeVer = & node --version
    Write-CheckResult "Node.js Version" $nodeVer "PASS"
} else {
    Write-CheckResult "Node.js" "Not installed or not in PATH" "FAIL" "Node.js (LTS v18+) is required for frontend building."
}

$npmCmd = Get-Command "npm" -ErrorAction SilentlyContinue
if ($npmCmd) {
    $npmVer = & npm --version
    Write-CheckResult "npm Version" $npmVer "PASS"
} else {
    Write-CheckResult "npm" "Not installed or not in PATH" "FAIL" "npm is required for frontend dependency management."
}

# 6. Python Version and Compatibility
$pythonCmd = Get-Command "python" -ErrorAction SilentlyContinue
if ($pythonCmd) {
    $pyVerStr = & python --version 2>&1
    if ($pyVerStr -match "Python\s+([0-9]+)\.([0-9]+)\.([0-9]+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        
        if ($major -eq 3 -and ($minor -ge 11 -and $minor -le 12)) {
            Write-CheckResult "Python Version" "$pyVerStr ($($pythonCmd.Source))" "PASS"
        } elseif ($major -eq 3 -and $minor -ge 13) {
            Write-CheckResult "Python Version" "$pyVerStr ($($pythonCmd.Source))" "WARN" "Python 3.11 or 3.12 is strongly recommended. Python 3.13+ lacks pre-compiled wheels for PyTorch and ONNX Runtime on Windows."
        } elseif ($major -eq 3 -and $minor -eq 10) {
            Write-CheckResult "Python Version" "$pyVerStr ($($pythonCmd.Source))" "WARN" "Python 3.10 is functional but Python 3.11+ recommended."
        } else {
            Write-CheckResult "Python Version" "$pyVerStr ($($pythonCmd.Source))" "FAIL" "Python 3.11 or 3.12 64-bit is required."
        }
    } else {
        Write-CheckResult "Python" "$pyVerStr" "WARN" "Unable to parse Python version string."
    }
} else {
    Write-CheckResult "Python" "Not found in PATH" "FAIL" "Python 3.11/3.12 64-bit is a mandatory prerequisite."
}

# 7. C/C++ Toolchain
$gccCmd = Get-Command "gcc" -ErrorAction SilentlyContinue
$clCmd = Get-Command "cl" -ErrorAction SilentlyContinue
if ($clCmd) {
    Write-CheckResult "C/C++ Compiler" "MSVC cl.exe detected ($($clCmd.Source))" "PASS"
} elseif ($gccCmd) {
    $gccVer = & gcc --version | Select-Object -First 1
    Write-CheckResult "C/C++ Compiler" "GCC detected: $gccVer" "PASS"
} else {
    Write-CheckResult "C/C++ Toolchain" "No MSVC or GCC compiler in PATH" "WARN" "Pre-compiled binary wheels (.whl) must be used for native packages."
}

# 8. GPU & NVIDIA Driver
$nvCmd = Get-Command "nvidia-smi" -ErrorAction SilentlyContinue
if ($nvCmd) {
    $nvOutput = & nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>&1
    if ($LASTEXITCODE -eq 0 -and $nvOutput) {
        Write-CheckResult "NVIDIA GPU" "$nvOutput" "PASS"
    } else {
        Write-CheckResult "NVIDIA GPU" "nvidia-smi present but hardware query failed" "WARN" "Fallback to CPU baseline will be used."
    }
} else {
    Write-CheckResult "NVIDIA GPU" "nvidia-smi not detected" "PASS" "Using guaranteed CPU-only execution baseline."
}

# 9. Docker & Docker Compose
$dockerCmd = Get-Command "docker" -ErrorAction SilentlyContinue
if ($dockerCmd) {
    $dockerVer = & docker --version
    Write-CheckResult "Docker CLI" "$dockerVer" "PASS"

    # Check Compose
    $composeVer = & docker compose version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-CheckResult "Docker Compose" "$composeVer" "PASS"
    } else {
        Write-CheckResult "Docker Compose" "docker compose plugin not found" "WARN" "Required for containerized offline deployments."
    }

    # Check daemon availability without hanging
    $daemonCheck = & docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-CheckResult "Docker Daemon" "Docker Engine is running" "PASS"
    } else {
        Write-CheckResult "Docker Daemon" "Docker Desktop Engine is not currently running" "WARN" "Start Docker Desktop when building or validating container bundles."
    }
} else {
    Write-CheckResult "Docker" "Not installed in PATH" "WARN" "Docker is required for containerized air-gapped bundle builds."
}

Write-Header "Environment Check Summary"

if ($Script:ExitCode -eq 0) {
    Write-Host " [STATUS] All mandatory prerequisites passed.`n" -ForegroundColor Green
} else {
    Write-Host " [STATUS] One or more mandatory prerequisites failed. Please resolve above issues.`n" -ForegroundColor Red
}

exit $Script:ExitCode
