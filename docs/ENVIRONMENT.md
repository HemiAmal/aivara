# AIVARA — Environment Inspection & Validation Report

**Phase:** Phase 1 — Environment Validation  
**Date:** 2026-08-31  
**Target Environment:** Windows 11 Desktop (Offline / Air-gapped Capable)  
**Host Machine:** Antigravity Development Workstation  

---

## 1. Executive Summary

An exhaustive environment inspection was conducted for the AIVARA project workspace (`d:\Downloads\Projects\AiVara`). All hardware, OS, toolchain, and container virtualization aspects were evaluated against the core project requirements:
- Complete offline capability
- Air-gapped deployment readiness
- CPU-only execution baseline with optional NVIDIA GPU acceleration
- No runtime external network dependencies

---

## 2. Detected System Environment

| Component | Specification / Detected Value | Status |
| :--- | :--- | :--- |
| **Operating System** | Microsoft Windows 11 Home Single Language (Build 10.0.26200, 64-bit) | ✅ Supported |
| **Processor (CPU)** | 13th Gen Intel(R) Core(TM) i7-13650HX (14 Cores / 20 Logical Threads, ~2.60 GHz) | ✅ Exceeds Baseline |
| **System Memory (RAM)** | 24,866,680 KB (~23.7 GB Total, ~4.4 GB Available Physical) | ✅ Sufficient for Baseline |
| **Primary Storage (C:)** | Total: 230.6 GB \| Free: 9.8 GB \| Used: 220.8 GB | ⚠️ Low Free Space (< 10 GB) |
| **Project Storage (D:)** | Total: 244.1 GB \| Free: 182.9 GB \| Used: 61.3 GB | ✅ Ample Storage for Models/Data |
| **GPU Hardware** | NVIDIA GeForce RTX 3050 6GB Laptop GPU (Bus ID: `00000000:01:00.0`) | ✅ Supported (6 GB VRAM) |
| **NVIDIA Driver** | Driver Version: `581.86` \| CUDA Driver API: `13.0` | ✅ Installed & Operational |
| **Git** | `git version 2.54.0.windows.1` | ✅ Installed |
| **Python** | Python `3.14.5` (64-bit) at `C:\Python314\python.exe` \| pip `26.2.1` | ⚠️ Compatibility Risk |
| **Node.js** | Node.js `v24.15.0` (64-bit) | ✅ Installed |
| **npm** | npm `11.12.1` | ✅ Installed |
| **Docker CLI** | Docker CLI `29.7.2` (build `a7dcaa6`) | ✅ Installed |
| **Docker Compose** | Docker Compose plugin `v5.4.0` | ✅ Installed |
| **Docker Daemon** | Docker Desktop Engine not currently running / daemon pipe unreachable | ⚠️ Service Stopped |
| **C/C++ Toolchain** | MSYS2 UCRT64 GCC `16.1.0` (`D:\msys64\ucrt64\bin\gcc.exe`) | ✅ GCC Available (MSVC absent) |

---

## 3. Detailed Component Findings

### 3.1 Hardware & GPU Acceleration
- **CPU:** The 14-core Intel Core i7-13650HX provides strong parallel execution capabilities for in-process async tasks, perceptual hashing, and image validation routines.
- **RAM:** ~24 GB total system RAM easily supports the targeted 100K image dataset audits and in-memory perceptual hash clustering.
- **GPU & CUDA:** The system features an NVIDIA GeForce RTX 3050 Laptop GPU with 6GB VRAM running driver 581.86 (CUDA 13.0 compatible). 
  - Baseline execution remains strictly CPU-only per architecture principles.
  - When GPU acceleration is enabled, ONNX Runtime (`CUDAExecutionProvider`) and PyTorch can utilize CUDA.
- **Disk Space Allocation:**
  - **Drive C: (9.8 GB free):** Drive C has critical space limitations. Storing heavy Docker image layers, pip wheels, or model weights in user home directories on `C:` will quickly cause disk exhaustion.
  - **Drive D: (182.9 GB free):** Drive D contains the project and ample storage. **All virtual environments, model caches (`data/model_cache/`), and test fixtures must reside on Drive D.**

### 3.2 Python Runtime & Ecosystem Compatibility
- **Current Installation:** Python `3.14.5` is active as the default Python interpreter.
- **CRITICAL RISK:** Core computer vision, deep learning, and mathematical packages required by AIVARA (including `torch`, `torchvision`, `onnxruntime`, `numpy`, `scipy`, `cleanlab`, and `opencv-python`) typically lag behind the latest Python major releases and do not provide pre-compiled wheels for Python 3.14 yet.
- **Recommended Python Version:** **Python 3.11 or Python 3.12 (64-bit)** is the industry standard for stable, pre-built wheel distribution for PyTorch, ONNX Runtime, and scientific libraries on Windows.

### 3.3 Node.js & Web Toolchain
- Node.js `v24.15.0` and npm `11.12.1` are installed and fully compatible with Vite, TypeScript, Tailwind CSS, and modern React frontend bundling.

### 3.4 Containerization (Docker Desktop)
- Docker CLI `29.7.2` and Docker Compose `v5.4.0` are installed.
- The Docker Desktop daemon service is currently stopped or not running in the background. Starting Docker Desktop will enable container builds and air-gapped bundle testing.

### 3.5 C/C++ Build Toolchain
- `D:\msys64\ucrt64\bin\gcc.exe` (GCC 16.1.0) is present in `PATH`.
- Microsoft Visual C++ Build Tools (`cl.exe`) are not detected in `PATH`. 
- To avoid requiring native compilation on Windows, binary pre-compiled wheels (`.whl`) should be used for all Python dependencies. Using a Python version with full wheel coverage (Python 3.11/3.12) eliminates the need for MSVC C++ compilation.

---

## 4. Missing Prerequisites & Action Items

### 4.1 Prerequisites Requiring User Action
1. **Python Version Alignment (Critical):**
   - Install **Python 3.11.x (64-bit)** or **Python 3.12.x (64-bit)**.
   - Using Python 3.14 will cause build failures during Phase 2 when resolving native ML wheels (`torch`, `onnxruntime`).
2. **Docker Desktop Startup (When container testing is needed):**
   - Launch Docker Desktop to start the background container daemon.
   - Configure Docker Desktop to store images/containers on Drive D: if Drive C: space is constrained.
3. **Storage Hygiene on Drive C:**
   - Free up space on Drive C: (or configure environment variables `PIP_CACHE_DIR`, `HF_HOME`, `TORCH_HOME` to point to `D:\.cache\...` to prevent filling `C:`).

---

## 5. Recommended Development Configuration

```toml
# Recommended Developer Profile for AIVARA on this workstation

[python]
recommended_version = "3.11.9 or 3.12.x (64-bit)"
venv_path = "D:\\Downloads\\Projects\\AiVara\\.venv"

[storage_paths]
workspace_root = "D:\\Downloads\\Projects\\AiVara"
model_cache = "D:\\Downloads\\Projects\\AiVara\\data\\model_cache"
temp_cache = "D:\\cache"

[hardware_profile]
target_inference = "CPU (default baseline)"
accelerator = "NVIDIA CUDA (optional profile: RTX 3050 Laptop 6GB)"
num_workers = 8  # 14-core / 20-thread CPU allows up to 8-12 parallel workers
```

---

## 6. Compatibility & Security Risk Assessment

1. **Python 3.14 Wheel Availability:**
   - Severity: **HIGH**.
   - Impact: Pre-compiled binary wheels for PyTorch and ONNX Runtime are not published for Python 3.14 on Windows. Source compilation without MSVC build tools will fail.
   - Resolution: Run development virtual environment under Python 3.11 or 3.12.
2. **Drive C: Space Exhaustion:**
   - Severity: **MEDIUM**.
   - Impact: Default `%LOCALAPPDATA%` and `%USERPROFILE%\.cache` locations on `C:` will be exhausted by PyTorch models and Docker layers.
   - Resolution: Point cache directories to `D:`.
3. **Docker Daemon Status:**
   - Severity: **LOW**.
   - Impact: Local development can proceed natively with Uvicorn and Vite. Docker daemon is only required when building/testing offline container bundles.
