# Anti-Cheat Best Practices - BFV Aimbot Analysis

## Overview

This document provides an **educational analysis** of how modern anti-cheat systems detect game cheats, and identifies the detection vectors present in this codebase. Understanding these principles is valuable for game security research and reverse engineering education.

---

## 1. How Modern Anti-Cheat Systems Work

### 1.1 Kernel-Level Monitoring (EAC, BattlEye, Vanguard)
- Anti-cheat drivers run at **Ring 0** (kernel level)
- They monitor all system calls, especially `ReadProcessMemory`, `WriteProcessMemory`, `NtQueryInformationThread`
- They can detect any user-mode process that accesses game memory

### 1.2 Behavioral Analysis
- Server-side systems analyze player behavior patterns
- Inhuman reaction times, perfect tracking, and unnatural aim patterns are flagged
- Statistical analysis over multiple matches detects subtle aiming assistance

### 1.3 Signature Detection
- Known cheat binaries are fingerprinted and detected on launch
- Memory patterns (byte sequences, strings, offsets) are scanned
- Hash-based detection of known cheat modules

### 1.4 Integrity Verification
- Game files and memory regions are checksummed at runtime
- Code injection and patching is detected via hash mismatches
- Stack integrity checks detect unauthorized thread manipulation

---

## 2. Detection Vectors in This Codebase

### 2.1 Memory Access Patterns

**File:** `lib/MemAccess.py`

| Vector | Risk Level | Description |
|--------|-----------|-------------|
| `ReadProcessMemory` calls | **HIGH** | Direct RPM calls are the #1 detection method. Kernel AC hooks `NtReadVirtualMemory` and logs all cross-process reads. |
| Access frequency | **HIGH** | The `_access` counter shows continuous memory reads every frame. Regular, high-frequency RPM calls are easily profiled. |
| `WriteProcessMemory` | **CRITICAL** | The `patch()` function uses WPM + `VirtualProtectEx` to change page protections. This is immediately flagged by any AC. |

### 2.2 Pointer Decryption & Obfuscation Manager

**File:** `lib/PointerManager.py`

| Vector | Risk Level | Description |
|--------|-----------|-------------|
| `NtQueryInformationThread` | **HIGH** | Used in `StackAccess()` to read the protected thread's stack. AC systems monitor this syscall. |
| Obfuscation Manager search | **HIGH** | Scanning for magic values (`OBFUS_MGR_PTR_1 = 0x1438B46D0`) is a known pattern that AC can detect. |
| DX11 secret extraction | **HIGH** | GPU memory pointer scraping is a well-known technique that AC vendors specifically monitor. |
| `decrypt_ptr()` XOR pattern | **MEDIUM** | The decryption algorithm mirrors the game's own logic, making it identifiable via code analysis. |

### 2.3 Hardcoded Offsets

**File:** `lib/offsets.py`

| Vector | Risk Level | Description |
|--------|-----------|-------------|
| Static addresses | **MEDIUM** | Addresses like `GAMERENDERER = 0x1447F6FB8` break on every game update and can be honeypotted. |
| Known cheat offsets | **HIGH** | Offsets to `CSE_Occluded`, `HealthComponent`, `TeamID` are well-known to AC teams. Access to these specific memory locations is monitored. |
| No signature scanning | **LOW** | While this makes the code simpler, it means offsets must be manually updated. |

### 2.4 Input Simulation

**File:** `lib/aimer.py`

| Vector | Risk Level | Description |
|--------|-----------|-------------|
| `SendInput` API | **MEDIUM** | AC can hook `SendInput`/`NtUserSendInput` to detect programmatic mouse movement. |
| Fixed 0.02s delay | **HIGH** | Constant timing between inputs is inhuman. Real humans have variable delays following a distribution curve. |
| Delta division by 2 | **LOW** | Simple division doesn't replicate human mouse acceleration curves. |
| Perfect bone targeting | **HIGH** | Always targeting exact bone positions (head/spine center) is statistically impossible for humans. |

### 2.5 Behavioral Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| Instant target acquisition | Server-side: time-to-target analysis |
| Perfect FOV snapping | Server-side: aim angle velocity analysis |
| No overshoot/undershoot | Server-side: aim correction pattern analysis |
| Consistent accuracy across distances | Server-side: statistical anomaly detection |
| Target switching speed | Server-side: reaction time distribution |

---

## 3. Anti-Cheat Best Practices (Educational Reference)

### 3.1 Understanding Detection Layers

Modern anti-cheat operates on **multiple layers**:

```
Layer 1: Kernel Driver    - Monitors syscalls, memory access, loaded modules
Layer 2: User-Mode Agent  - Scans process memory, checks file integrity
Layer 3: Server-Side      - Behavioral analysis, statistical detection
Layer 4: Manual Review    - Human analysts review flagged accounts
```

Each layer must be considered independently. Bypassing one layer does not mean safety from others.

### 3.2 Memory Access Principles

- **ReadProcessMemory** is the most monitored API in gaming
- Kernel-level AC (EAC, BattlEye) hooks `NtReadVirtualMemory` at the SSDT level
- Even "undetected" RPM calls leave traces in kernel callback logs
- The access pattern (which addresses, how often) creates a unique fingerprint

### 3.3 Input Simulation Principles

- `SendInput` and `mouse_event` are hooked by most AC
- Hardware-level input (USB HID) is harder to distinguish but not impossible
- **Timing regularity** is the biggest giveaway - humans are inherently inconsistent
- Human mouse movement follows specific mathematical models (Fitts' Law, minimum jerk)

### 3.4 Behavioral Realism

Real human aiming has these characteristics:
- **Reaction time**: 150-300ms average, following a normal distribution
- **Overshoot/undershoot**: Humans rarely land on target in one motion
- **Micro-corrections**: Small adjustments after initial flick
- **Fatigue**: Performance degrades over time
- **Variable accuracy**: Dependent on distance, movement speed, stress

### 3.5 Code Security Principles

| Principle | Description |
|-----------|-------------|
| No hardcoded strings | Cheat-related strings ("aimbot", "ESP", offsets) are signature-scanned |
| No static offsets | Use pattern scanning instead of fixed addresses |
| Process hiding | The cheat process itself can be enumerated by AC |
| No admin elevation | Running as admin is flagged by some AC systems |
| Clean exit | Failing to clean up hooks/patches leaves detectable artifacts |

---

## 4. Specific Findings in This Codebase

### 4.1 Things Done Well
- Uses the game's own decryption logic rather than patching encryption out
- External approach (no DLL injection) reduces some detection vectors
- Read-only memory access (except unused `patch()` function)
- Proper pointer chain walking instead of raw address access

### 4.2 Key Weaknesses

1. **No process concealment** - Python process is visible in task manager
2. **Regular timing** - Fixed `sleep(0.02)` creates detectable pattern
3. **Direct RPM** - No abstraction or indirection for memory reads
4. **Protected thread access** - `NtQueryInformationThread` on the game's protected thread is highly suspicious
5. **No human-like behavior** - Aim movement is purely mathematical with no randomization
6. **Python overhead** - GC pauses and interpreter overhead create irregular frame times
7. **Hardcoded offsets** - Break on every game update, no auto-update mechanism
8. **No integrity checks** - Doesn't verify it's reading valid game data
9. **Single-threaded** - Blocking reads cause frame drops and inconsistent timing
10. **Console output** - Print statements reveal cheat activity to screen capture

---

## 5. How Game Developers Fight Cheats

### 5.1 Server-Side Validation
- **Authoritative servers**: Server controls game state, client only sends inputs
- **Replay analysis**: Recording and analyzing suspicious matches
- **Statistical profiling**: Machine learning models trained on cheat vs legit players
- **Kill cam analysis**: Automated review of aim patterns in kill recordings

### 5.2 Client-Side Protection
- **Code obfuscation**: Making reverse engineering harder
- **Pointer encryption**: Dynamic key rotation (as seen in BFV's obfuscation manager)
- **Integrity monitoring**: CRC checks on game memory
- **Anti-debugging**: Detecting attached debuggers and analysis tools
- **Driver-level monitoring**: Kernel callbacks for process/thread creation

### 5.3 Deterrence
- **Hardware bans**: Banning based on hardware fingerprint (HWID)
- **Delayed bans**: Collecting data before banning in waves
- **Trust scoring**: Reducing matchmaking quality for suspicious accounts
- **Phone verification**: Requiring phone numbers for competitive modes

---

## 6. Summary

This codebase demonstrates core game hacking concepts:
- Memory reading and pointer chain walking
- Encryption/obfuscation handling
- 3D math (world-to-screen projection)
- Input simulation

However, it has **minimal anti-cheat awareness**. Modern anti-cheat systems (EAC in BFV's case) would detect this through multiple independent vectors: kernel-level RPM monitoring, behavioral analysis, and signature detection.

Understanding these detection mechanisms is essential knowledge for:
- Game security researchers
- Anti-cheat developers
- Reverse engineering students
- Game developers implementing protection systems

---

*This document is for educational and research purposes only.*
