# Anti-Cheat Best Practices - BFV Aimbot Analysis

## Overview

This document provides an **educational analysis** of how modern anti-cheat systems detect game cheats, and identifies the detection vectors present in this codebase. Understanding these principles is valuable for game security research and reverse engineering education.

---

## 1. How Modern Anti-Cheat Systems Work

### 1.1 Kernel-Level Monitoring (EAC, BattlEye, Vanguard)
- Anti-cheat drivers run at **Ring 0** (kernel level)
- They monitor all system calls, especially `ReadProcessMemory`, `WriteProcessMemory`, `NtQueryInformationThread`
- They can detect any user-mode process that accesses game memory
- Kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`) track process/thread creation and handle operations

### 1.2 Behavioral Analysis
- Server-side systems analyze player behavior patterns
- Inhuman reaction times, perfect tracking, and unnatural aim patterns are flagged
- Statistical analysis over multiple matches detects subtle aiming assistance
- Machine learning models compare aim patterns against known cheat signatures

### 1.3 Signature Detection
- Known cheat binaries are fingerprinted and detected on launch
- Memory patterns (byte sequences, strings, offsets) are scanned
- Hash-based detection of known cheat modules
- Import table analysis reveals suspicious API usage patterns

### 1.4 Integrity Verification
- Game files and memory regions are checksummed at runtime
- Code injection and patching is detected via hash mismatches
- Stack integrity checks detect unauthorized thread manipulation
- Heartbeat systems verify client-side AC agent is running

---

## 2. Detection Vectors in This Codebase

### 2.1 Memory Access Patterns (`lib/MemAccess.py`)

| Vector | Risk Level | Code Location | Description |
|--------|-----------|---------------|-------------|
| `ReadProcessMemory` calls | **CRITICAL** | `MemAccess.py:176-354` — All `rpm_*` functions | Direct RPM calls are the #1 detection method. Kernel AC hooks `NtReadVirtualMemory` and logs all cross-process reads. Every single frame triggers dozens of RPM calls. |
| Access frequency counter | **HIGH** | `MemAccess.py:90` — `self._access` counter | The `_access` counter shows continuous memory reads every frame. In `BFV.py:151`, it resets to 0 each tick — meaning high-frequency RPM calls are easily profiled by AC. |
| `WriteProcessMemory` | **CRITICAL** | `MemAccess.py:266-286` — `wpm_uint32/64` functions | WPM calls are immediately flagged by any AC. Used by `patch()` at line 622 with `VirtualProtectEx` to change page protections. |
| `VirtualProtectEx` abuse | **CRITICAL** | `MemAccess.py:599-601` — `get_codecave()` | Changes memory page protections on game's executable sections — a classic code injection technique that AC specifically monitors. |
| Process handle with full access | **HIGH** | `BFV.py:58` — `OpenProcess(0x1f0fff)` | Opens the game process with `PROCESS_ALL_ACCESS` rights. AC monitors handle creation via `ObRegisterCallbacks` and flags overly broad access masks. |
| `CreateToolhelp32Snapshot` | **MEDIUM** | `MemAccess.py:144` | Process enumeration to find `bfv.exe` is a known cheat behavior pattern. |

### 2.2 Pointer Decryption & Obfuscation Manager (`lib/PointerManager.py`)

| Vector | Risk Level | Code Location | Description |
|--------|-----------|---------------|-------------|
| `NtQueryInformationThread` | **HIGH** | `MemAccess.py:675` — `StackAccess.__init__()` | Used to read the protected thread's TEB (Thread Environment Block) to find the stack. AC systems specifically monitor this syscall on protected threads. |
| Protected thread access | **CRITICAL** | `PointerManager.py:57` — `offsets.PROTECTED_THREAD` | Directly reads the game's protected thread ID from `0x144752654` and opens it with `THREAD_ALL_ACCESS (0x001F03FF)` at `MemAccess.py:671`. AC protects this thread. |
| Obfuscation Manager stack scanning | **HIGH** | `PointerManager.py:58-71` — `GetObfuscationMgr()` | Scans the protected thread's stack for magic value `OBFUS_MGR_PTR_1 = 0x1438B46D0`. This is a well-known technique AC vendors specifically detect. |
| DX11 secret extraction | **HIGH** | `PointerManager.py:77-145` — `GetDx11Secret()` | GPU memory pointer scraping to extract the DX11 encryption key. Searches protected thread stack for `OBFUS_MGR_RET_1 = 0x147E38436`. AC vendors monitor this technique. |
| `decrypt_ptr()` XOR algorithm | **MEDIUM** | `PointerManager.py:35-49` | The decryption algorithm mirrors the game's own pointer encryption logic. The specific XOR pattern (`y * 0x3B`, `subkey += 8`) is a known signature. |
| Hash table traversal | **MEDIUM** | `PointerManager.py:171-208` | Walking the ObfuscationManager's internal hash tables (`ObfManager + 0x78`, `ObfManager + 0x10`) accesses internal AC-protected data structures. |

### 2.3 Hardcoded Offsets (`lib/offsets.py`)

| Vector | Risk Level | Code Location | Description |
|--------|-----------|---------------|-------------|
| Static game addresses | **MEDIUM** | `offsets.py:9-28` | Addresses like `GAMERENDERER = 0x1447F6FB8`, `CLIENT_GAME_CONTEXT = 0x1447522A8` break on every game update and can be honeypotted by AC. |
| Known cheat offsets | **HIGH** | `offsets.py:53-57` | `CSE_Occluded = 0xA7B`, `CSE_HealthComponent = 0x2E8`, `CSE_Player = 0x3A8` are well-known to AC teams. Access to these specific memory locations is monitored. |
| Hardcoded encryption constants | **HIGH** | `offsets.py:2` | `Dx11Secret = 0x598447EFD7A36912` — static fallback key is a unique signature that can be pattern-matched in process memory. |
| Magic pointer values | **HIGH** | `offsets.py:26-28` | `OBFUS_MGR_PTR_1`, `OBFUS_MGR_RET_1`, `OBFUS_MGR_DEC_FUNC` — these constants in memory are signature-scannable by AC. |
| No signature scanning | **LOW** | — | While this makes the code simpler, offsets must be manually updated per game patch. |

### 2.4 Input Simulation (`lib/aimer.py`)

| Vector | Risk Level | Code Location | Description |
|--------|-----------|---------------|-------------|
| `SendInput` API | **MEDIUM** | `aimer.py:251` — `windll.user32.SendInput()` | AC hooks `SendInput`/`NtUserSendInput` to detect programmatic mouse movement. The `MOUSEINPUT` struct with `dwFlags=0x1` (MOUSEEVENTF_MOVE) is monitored. |
| Fixed 20ms delay | **HIGH** | `aimer.py:193` — `time.sleep(0.02)` | Constant 20ms timing between inputs is inhuman. Real humans have variable delays following a log-normal distribution (typically 50-200ms with variance). |
| Delta division by 2 | **LOW** | `aimer.py:217` — `delta_x / 2, delta_y / 2` | Simple halving doesn't replicate human mouse acceleration curves. No smoothing, easing, or Bezier interpolation. |
| Perfect bone targeting | **HIGH** | `aimer.py:236` in `BFV.py` — `read_vec4(aim_location * 0x20)` | Always targeting exact bone positions (head/spine center) is statistically impossible for humans. No offset jitter or natural spread. |
| Instant target lock | **HIGH** | `aimer.py:100-158` — target acquisition loop | Target switching is instantaneous — checks `lastSoldier` pointer and immediately re-acquires. No human-like reaction delay. |
| No movement prediction smoothing | **MEDIUM** | `aimer.py:118-119` — acceleration WIP | Velocity compensation (`accel`) is commented out. Raw delta movement with no interpolation or smoothing curves. |
| `GetAsyncKeyState` polling | **LOW** | `aimer.py:80,101,153,179` | Constant polling of trigger key state. While not directly detected, the polling pattern in combination with RPM calls creates a detectable profile. |

### 2.5 Process & Environment (`assist.py`, `ok.bat`)

| Vector | Risk Level | Code Location | Description |
|--------|-----------|---------------|-------------|
| Python interpreter | **MEDIUM** | `assist.py` | Running as `python.exe` — a non-game process performing RPM on game memory is inherently suspicious. AC can profile process behavior. |
| Admin elevation | **MEDIUM** | `ok.bat:6-21` — UAC bypass pattern | VBScript-based UAC elevation is a well-known pattern. Running as admin is flagged by some AC. |
| Console output | **LOW** | Multiple `print()` calls | Print statements like `"[+] BFV.exe found"`, `"ObfuscationMgr"` reveal cheat activity to screen capture and could be OCR-scanned. |
| Process name visible | **MEDIUM** | `ok.bat:28` — `python assist.py` | The process is visible in Task Manager. No process name obfuscation or concealment. |

### 2.6 Behavioral Indicators (Server-Side Detection)

| Indicator | Detection Method | Code Location |
|-----------|-----------------|---------------|
| Instant target acquisition | Server-side: time-to-target analysis | `aimer.py:100-158` — no reaction delay |
| Perfect FOV snapping | Server-side: aim angle velocity analysis | `aimer.py:191` — raw delta movement |
| No overshoot/undershoot | Server-side: aim correction pattern analysis | `calcAim()` — single-step aim |
| Consistent accuracy across distances | Server-side: statistical anomaly detection | No distance-based accuracy degradation |
| Target switching speed | Server-side: reaction time distribution | Immediate re-acquisition in main loop |
| Occluded target release | Server-side: visibility correlation | `aimer.py:106` — instant disengage on occlusion |

---

## 3. Anti-Cheat Best Practices (Educational Reference)

### 3.1 Understanding Detection Layers

Modern anti-cheat operates on **multiple independent layers**:

```
Layer 1: Kernel Driver    — Monitors syscalls, memory access, loaded modules
                           (EAC, BattlEye, Vanguard)
Layer 2: User-Mode Agent  — Scans process memory, checks file integrity,
                           monitors API hooks
Layer 3: Network/Server   — Behavioral analysis, statistical detection,
                           replay analysis
Layer 4: Manual Review    — Human analysts review flagged accounts,
                           delayed ban waves
```

Each layer must be considered independently. Bypassing one layer does not mean safety from others. Modern AC systems use **defense in depth** — multiple overlapping detection mechanisms.

### 3.2 Memory Access Principles

- **ReadProcessMemory** is the most monitored API in gaming
- Kernel-level AC (EAC, BattlEye) hooks `NtReadVirtualMemory` at the SSDT level
- Even "undetected" RPM calls leave traces in kernel callback logs
- The access pattern (which addresses, how often, from which process) creates a unique fingerprint
- **This codebase**: Makes direct RPM calls via `kernel32.ReadProcessMemory` with no abstraction. Each frame generates 50+ RPM calls to known cheat-targeted offsets.

### 3.3 Handle & Process Security

- `OpenProcess` with `PROCESS_ALL_ACCESS` is the most suspicious access mask
- AC uses `ObRegisterCallbacks` to intercept and inspect handle creation
- **This codebase**: Uses `OpenProcess(0x1f0fff)` — full access rights on the game process (BFV.py:58). Minimum required rights (e.g., `PROCESS_VM_READ`) would be slightly less suspicious.

### 3.4 Input Simulation Principles

- `SendInput` and `mouse_event` are hooked by most AC
- Hardware-level input (USB HID) is harder to distinguish but not impossible
- **Timing regularity** is the biggest giveaway — humans are inherently inconsistent
- Human mouse movement follows specific mathematical models (Fitts' Law, minimum jerk trajectory)
- **This codebase**: Uses `SendInput` with a fixed `0.02s` sleep and raw pixel deltas divided by 2. No human-like characteristics whatsoever.

### 3.5 Behavioral Realism

Real human aiming has these characteristics:
- **Reaction time**: 150-300ms average, following a log-normal distribution
- **Overshoot/undershoot**: Humans rarely land on target in one motion (2-3 corrections typical)
- **Micro-corrections**: Small adjustments after initial flick
- **Fatigue**: Performance degrades over time within a session
- **Variable accuracy**: Dependent on distance, target movement speed, player stress
- **Natural mouse curves**: Follow minimum-jerk or Bezier-like trajectories, not straight lines
- **Occasional misses**: Even pro players miss — perfect accuracy is impossible

### 3.6 Code Security Principles

| Principle | Current State | Description |
|-----------|--------------|-------------|
| No hardcoded strings | **VIOLATED** | Strings like `"ObfuscationMgr"`, `"BFV.exe"`, `"Dx11 key"` are signature-scannable |
| No static offsets | **VIOLATED** | 30+ hardcoded addresses in `offsets.py` break on every game update |
| Process concealment | **ABSENT** | Python process is fully visible in task manager and process list |
| Minimal access rights | **VIOLATED** | Uses `PROCESS_ALL_ACCESS` instead of minimum required |
| Clean exit | **ABSENT** | No cleanup of handles, no graceful shutdown on AC detection |
| Anti-debugging awareness | **ABSENT** | No checks for attached debuggers or AC monitoring |
| String encryption | **ABSENT** | All strings stored in plaintext in Python source |

---

## 4. Specific Findings in This Codebase

### 4.1 Things Done Well
- Uses the game's own decryption logic (`decrypt_ptr`) rather than patching encryption out
- **External approach** (no DLL injection) reduces some detection vectors — no code modification inside game process
- Primarily **read-only** memory access (the `patch()` and `wpm_*` functions exist but aren't called in main logic)
- Proper **pointer chain walking** via `MemAccess` class with validity checks (`isValid()`)
- **Caching system** (`_cache`, `_cache_en`) to reduce redundant RPM calls
- **WeakPtr resolution** (`weakptr()` method) correctly handles Frostbite's weak pointer pattern
- Handles both **static and dynamic encryption modes** (`CryptMode 0` vs `1`)
- **Signature scanner** exists (`sigscan` class) even though static offsets are currently used

### 4.2 Key Weaknesses (Ranked by Severity)

1. **CRITICAL: Direct RPM with no abstraction** — `kernel32.ReadProcessMemory` is called directly. No driver-level read, no memory-mapped file trick, no DMA. This is the #1 detection vector.

2. **CRITICAL: Protected thread access** — Opening the game's protected thread (`THREAD_ALL_ACCESS`) and calling `NtQueryInformationThread` to read its stack is specifically monitored by EAC.

3. **HIGH: No process concealment** — Python process is visible. `CreateToolhelp32Snapshot` + process enumeration is detectable.

4. **HIGH: Fixed timing** — `sleep(0.02)` creates a perfectly regular 50Hz pattern. Should use randomized intervals (e.g., gaussian distribution around target framerate).

5. **HIGH: No human-like aim behavior** — Raw pixel deltas with division by 2. No smoothing curves, no overshoot simulation, no reaction delay, no jitter.

6. **HIGH: Hardcoded magic values in memory** — Constants like `0x598447EFD7A36912`, `0x1438B46D0` sitting in Python process memory are signature-scannable.

7. **MEDIUM: Full access handle** — `PROCESS_ALL_ACCESS (0x1f0fff)` when only `PROCESS_VM_READ` is needed for the main aimbot loop.

8. **MEDIUM: Python overhead** — GC pauses create irregular timing. Python's memory allocator creates unusual memory patterns. The interpreter itself may be fingerprinted.

9. **LOW: Console output** — Print statements with cheat-related text could be captured by screen recording or OCR.

10. **LOW: No data validation** — Doesn't verify game state before acting (e.g., checking if in menu, loading screen, or actually in-game).

---

## 5. How Game Developers Fight Cheats

### 5.1 Server-Side Validation
- **Authoritative servers**: Server controls game state, client only sends inputs
- **Replay analysis**: Recording and analyzing suspicious matches frame-by-frame
- **Statistical profiling**: ML models trained on cheat vs legit player datasets
- **Kill cam analysis**: Automated review of aim patterns in kill recordings
- **Movement validation**: Server-side bounds checking on reported positions

### 5.2 Client-Side Protection
- **Code obfuscation**: Making reverse engineering harder (VMProtect, Themida)
- **Pointer encryption**: Dynamic key rotation (as seen in BFV's ObfuscationManager)
- **Integrity monitoring**: CRC/hash checks on game memory regions
- **Anti-debugging**: Detecting attached debuggers and analysis tools
- **Driver-level monitoring**: Kernel callbacks for process/thread creation, handle operations
- **Syscall hooking**: SSDT hooks to intercept `NtReadVirtualMemory`, `NtOpenProcess`

### 5.3 Deterrence
- **Hardware bans (HWID)**: Banning based on hardware fingerprint (CPU, GPU, disk serial, MAC address)
- **Delayed ban waves**: Collecting data silently before banning thousands at once — makes it hard to know what was detected
- **Trust scoring / shadow bans**: Reducing matchmaking quality for suspicious accounts without explicit notification
- **Phone/SMS verification**: Requiring phone numbers for competitive modes raises cost of new accounts
- **Account value**: Making accounts harder to replace (rank progression, purchases)

### 5.4 BFV-Specific Protections
- **EasyAntiCheat (EAC)**: Kernel-level driver monitors process creation, handle operations, and memory access
- **Pointer encryption**: ObfuscationManager with XOR-based pointer encryption and DX11-derived dynamic keys
- **Protected threads**: Game runs sensitive operations on protected threads that AC specifically monitors
- **Server-side stats**: EA's FairFight system analyzes player statistics for anomalies

---

## 6. Code Architecture Overview

```
assist.py              — Entry point, user config (FOV, trigger, bone targets)
├── lib/aimer.py       — Aim logic: target selection, World2Screen, SendInput
├── lib/BFV.py         — Game data extraction: player list, entity reading
├── lib/MemAccess.py   — Low-level memory access: RPM/WPM, StackAccess, sigscan
├── lib/PointerManager.py — Encryption handling: ObfuscationMgr, decrypt_ptr
├── lib/offsets.py     — Hardcoded addresses and struct offsets
├── lib/bones.py       — Bone index mapping (Head=0x8, Spine=0x3, etc.)
├── lib/helpers.py     — Utility: admin check, Python version check
└── lib/keycodes.py    — Virtual key code constants
```

### Data Flow
```
1. BFV.py:process() called each frame
2. PointerManager → GetLocalPlayer() → decrypt via ObfuscationMgr
3. GetEntityList() → iterate ClientSoldierEntity linked list
4. For each soldier: read transform, health, occlusion, bone positions
5. aimer.py:calcAim() → World2Screen projection → distance calculation
6. Find closest valid target within FOV
7. SendInput() with pixel delta ÷ 2
8. sleep(0.02) → repeat
```

---

## 7. Summary

This codebase demonstrates core game hacking concepts:
- Memory reading via `ReadProcessMemory` and pointer chain walking
- Frostbite engine's pointer encryption/obfuscation handling
- 3D math (World-to-Screen projection using view matrix)
- Input simulation via Windows `SendInput` API
- Entity enumeration through encrypted linked lists

However, it has **minimal anti-cheat awareness**. Modern anti-cheat systems (EAC in BFV's case) would detect this through **multiple independent vectors**:

| Detection Layer | Vectors Found |
|----------------|---------------|
| Kernel Driver | RPM calls, handle creation, thread access, NtQueryInformationThread |
| User-Mode Agent | Process enumeration, magic constants in memory, Python interpreter |
| Server-Side | Perfect aim, fixed timing, instant target acquisition, no misses |
| Signature | Hardcoded offsets, encryption constants, known API call patterns |

Understanding these detection mechanisms is essential knowledge for:
- Game security researchers
- Anti-cheat developers building protection systems
- Reverse engineering students
- Game developers implementing client-side protection

---

*This document is for educational and research purposes only.*
