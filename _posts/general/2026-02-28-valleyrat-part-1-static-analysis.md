---
layout: post
title: "ValleyRAT (Part 1): Static Analysis - From Go Loader to Decrypted Implant"
date: 2026-02-28
categories:
  - malware-analysis
  - reverse-engineering
tags:
  - malware-analysis
  - reverse-engineering
  - static-analysis
  - windows
  - go
  - backdoor
  - loader
  - donut
  - c2
series: ValleyRAT
series_part: 1
series_total: 2
---

This write-up documents my static analysis of the sample [*ValleyRAT*](https://malops.io/challenges/valleyrat) from MalOps. The goal was to understand what the binary does without leaning on dynamic analysis, packet capture, or full behavioral emulation. I stuck to triage, disassembly, and payload extraction to build a narrative while answering the challenge questions.

I noticed that the sample used a binary protocol for C2 communication, so this write-up does not cover protocol analysis or network emulation. I will cover that in **Part 2**.

> Safety note: all analysis was done in an isolated lab. Don't run unknown samples on a host you care about.

## 1. String Analysis / Initial Triage

I started with basic triage: **FLOSS + PE Studio**. The goal was to form hypotheses before touching a disassembler.

### 1.1 FLOSS Output: Go Build Fingerprinting

FLOSS immediately suggested a **Go v1.20-compiled** binary:

![Running floss against the challenge binary]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-string-analysis/1-floss-challenge.png" | relative_url}})

Opening the file we dumped the strings to, we then see a Go toolchain fingerprint confirming the above observation:

![Go compiler toolchain strings]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-string-analysis/2-toolchain-strings.png" | relative_url}})

At this point, my default "Go malware" mental model kicked in: minimal imports and runtime API resolution.

### 1.2 High-level Capability Hypotheses from Strings

From raw strings alone, the sample looked like it could do:

* Filesystem/ Path Operations
* Windows Registry Interaction
* Network Activity Interaction
* Process/ Thread primitives (to be confirmed)

![Observed capabilities]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-string-analysis/3-observed-capabilities.png" | relative_url}})

One string that stood out is:

* `./loader.go`

This is not proof by itself, but it is a strong signal that this was built from a Go project with an explicit loader component.

### 1.3 Persistence Indicator

A very strong persistence indicator appeared directly:

![Registry run key]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-string-analysis/4-registry-run-persistance.png" | relative_url}})

This indicates Run key persistence[^1], which immediately becomes a working hypothesis:
> The sample persists by adding itself to the Run key.

### 1.4 Imports: Minimal Footprint

The import footprint was small (just `Kernel32.dll`), which matches the "resolve everything dynamically" style that shows up in many loader stubs.

![Library imports]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-string-analysis/5-library-imports.png" | relative_url}})

By the end of triage, the model I wanted to prove was:

* Go Loader Stub
* Persistence via Run key
* Embedded Encrypted Payload
* Decrypt -> Allocate -> Execute in-memory Pattern

## 2. Disassembly / Entrypoint Investigation (Go Runtime)

### 2.1 Cutter: Early Crypto Hints

I like Cutter's Overview tab, so to start the journey, we'll look at it first:

![Sample's Cutter Overview]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-disassembly/1-cutter-overview.png" | relative_url}})

Initial analysis flagged crypto-relevant code paths, which lined up with the embedded-payload hypothesis.

### 2.2 Ghidra: Entrypoint -> Go Runtime -> `main.main`

In Ghidra, following the PE entrypoint landed us in the standard Go startup (`runtime.rt0_go` and friends). The important part is that the runtime eventually scheduled and called the program logic via `main.main`.

![Sample's Cutter Overview]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-disassembly/2-main-main.png" | relative_url}})

So `main.main` is the true behavioral start of this sample, not the raw entrypoint. We can also see the previously noted `./loader.go` string, which suggests this address maps to line 67 in the original Go source.

## 3. Stage 1/3 - Loader Logic: `main.main` Call Tree

Once we reach `main.main`, the structure was clean and very loader-shaped:

* Establish Persistence
* Perform Payload Decryption
* Perform Payload Loading (in-memory execution)

This story was clearly evident when we look at the function call tree within the `main.main` function:

![Main.main function call tree]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-disassembly/3-ghidra-main-main-call-tree.png" | relative_url}})

We will walk through each of these stages implemented by the functions above to verify the hypotheses.

### 3.1 Persistence: `enableAutoStart()`

Persistence is implemented via the function `enableAutoStart()`, using `os.Executable()` and `golang.org/x/sys/windows/registry`.

![Persistence setup]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-disassembly/4-enable-auto-start-call.png" | relative_url}})

#### 3.1.1 Locate The Current Executable Path

The binary calls `os.Executable()` and then normalizes it (i.e. `filepath.Abs()`), meaning it persists *whatever path the binary is currently running from* rather than a hardcoded install location.

Disassembly fragments I used as anchors:

```c
0047b969 e8 52 52        CALL       os::os.Executable
0047b978 e8 23 7d        CALL       path/filepath::path/filepath.abs
```

#### 3.1.2 Open The Run Key (HKCU)

The sample opens:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

This matched the string-derived hypothesis exactly.

#### 3.1.3 Set Value Name: `CalculatorApp_AutoStart`

It writes a string value named:

* `CalculatorApp_AutoStart`

whose data is the absolute path to the current executable.

#### 3.1.4 Cleanup

It closes the registry key via a small closure (`enableAutoStart.func1`). Nothing fancy, but it's a useful tell that this is "real" Go code rather than a crude stub.

### 3.2 Payload Decryption: `AesDecryptByECB()`

Next came the payload decryption routine.

Looking through the disassembly, we can see the preparatory steps for the payload decryption routine below.

![Payload Decryption Logic]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-disassembly/5-aes-decrypt-by-ecb-call.png" | relative_url}})

#### 3.2.1 Encrypted Blob Location and Size

From the above we determine:

* The address of the encrypted blob: `DAT_004b4fa8`
* The size of the payload: `0x25660` bytes (153,184 bytes)

```c
0047be4c 48 8d 35        LEA        RSI,[DAT_004b4fa8]
0047be5b bb 60 56        MOV        EBX,0x25660
```

#### 3.2.2 Key Material

The AES key is hardcoded as a 16-byte string (AES-128 length):


```c
0047be63 48 8d 3d        LEA        RDI,[s_1ws12uuu11j*p5fr_00495639]
0047be6a be 10 00        MOV        ESI,0x10
0047be6f e8 4c fc        CALL       main::main.AesDecryptByECB
```

More specifically, the key is:

```text
1ws12uuu11j*p5fr
```

There's also a staging/copy loop before the decrypt call. Effectively, the loader copies the embedded bytes into a buffer and then decrypts in memory using the above key.

#### 3.2.3 Static Payload Extraction

Given the information above, we can extract the payload without running the sample and dumping memory at runtime. The following script uses the recovered constants directly.

```python
import pefile
from Crypto.Cipher import AES
from pathlib import Path

PE_PATH = "challenge"                   # Sample Name

PAYLOAD_VA   = 0x004B4FA8               # Virtual address of payload
PAYLOAD_SIZE = 0x25660                  # Size of payload
AES_KEY      = b"1ws12uuu11j*p5fr"      # AES decryption key

OUT_ENC = "payload.encrypted"
OUT_DEC = "payload.decrypted"


def va_to_file_offset(pe, va):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    return pe.get_offset_from_rva(rva)

def extract_decrypted_payload(pe, offset, payload_va, payload_size, decryption_key):
    print(f"[+] Encrypted Payload Virtual Address: 0x{payload_va:X} → At file offset: 0x{offset:X}")
    encrypted = pe.__data__[offset:offset + payload_size]

    if len(encrypted) != payload_size:
        raise RuntimeError("[-] Failed to read full payload")

    Path(OUT_ENC).write_bytes(encrypted)

    if len(encrypted) % 16 != 0:
        raise RuntimeError("[-] Payload not AES block-aligned")

    cipher = AES.new(decryption_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)

    Path(OUT_DEC).write_bytes(decrypted)
    print(f"[+] Extracted {len(decrypted)} decrypted bytes")
    print(f"[+] Final decrypted payload written to file: {OUT_DEC}")


def main():
    print("[*] Starting payload extraction...\n")
    pe = pefile.PE(PE_PATH)
    offset = va_to_file_offset(pe, PAYLOAD_VA)
    extract_decrypted_payload(pe, offset, PAYLOAD_VA, PAYLOAD_SIZE, AES_KEY)
    print("\n[*] Payload extraction completed successfully.")

if __name__ == "__main__":
    main()
```

Running the script successfully extracted and decrypted the payload using the identified key.

![Payload Decryption and Extraction]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/1-payload-extraction.png" | relative_url}})

Running the `file` command on the extracted decrypted payload, we see that it can't find any recognizable header information to tell us what type of file this is. This will be our next task, to determine what this payload is.

### 3.3 Payload Loading: In-Memory Execution via `kernel32`

Immediately after decryption, the loader follows the classic sequence:

* load `kernel32.dll`
* resolve APIs dynamically
* allocate RWX (or allocate + change protection)
* copy decrypted bytes
* execute via new thread
* wait

The resolved API set included:

* `VirtualAlloc`
* `RtlMoveMemory`
* `CreateThread`
* `WaitForSingleObject`

In Go this showed up via syscall wrappers like `syscall.MustLoadDLL` and `(*DLL).MustFindProc`.

At this point, the stage-0 identity was no longer a hypothesis: this binary is a loader.

## 4. Stage 2/3 - Decrypted Payload: Shellcode Container

The next question was simple: what is the 153,184-byte decrypted buffer?

### 4.1 Extraction Confirmation

Using the loader's own constants, as proven above, we confirmed the following about the payload:

* Virtual Address: `0x4B4FA8`
* File Offset: `0xB37A8`
* Size: `0x25660`

After extracting and decrypting the embedded payload, I loaded the resulting blob into Cutter expecting something PE-shaped (MZ header, sections, import table, etc.). Instead, Cutter reported:

![Payload Cutter Overview]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/2-cutter-overview.png" | relative_url}})

The file format is unknown because it does not start with a recognizable executable container format, which correlates with the `file` command output. Regardless, a few observations stand out:

* **Bits: 64**
Even without a recognized file format, Cutter can still infer architecture from heuristics (instruction patterns, entropy, and typical prologues). It identified this blob as 64-bit code, which is consistent with what we later confirm via DIE.

* **Base Addr: `0x00000000`**
Normal PE binaries embed an ImageBase and relocation information. Shellcode does not. With “Format: N/A”, Cutter has no structural metadata to anchor the blob, so it maps it as a flat buffer and assigns a default base address.

This is one of the first observations that hints to us that we might be dealing with shellcode, i.e. it’s not meant to be loaded by the Windows loader. It’s meant to be copied into memory and executed.

* **Mode: `r-x`**
Cutter is indicating that it is treating this payload as executable code. Which aligns with a memory execution pipeline (`VirtualAlloc` -> `RtlMoveMemory` -> `CreateThread`).

So, even though Cutter couldn’t classify it as a PE, its view is consistent with what the stage-0 Go loader does, which is to decrypt a blob, allocate memory, and then execute it.

### 4.2 Shellcode Characteristics

Next we try to sanity-check the payload with scdbg:

![Payload Shellcode Debugger]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/3-shellcode-debug-peb-walk.png" | relative_url}})

At first glance, the line that jumps out is:

```c
mov eax, [0x30]
```

#### 4.2.1 Why `mov eax, [0x30]`?

I have seen this technique before. It suggests the shellcode is trying to reach the PEB (Process Environment Block) to enumerate loaded modules (kernel32, ntdll, etc.) without relying on imports[^3].

* On x86, shellcode commonly uses fs:[0x30] to get the PEB pointer.
* On x64, the analogous approach uses gs:[0x60] for the PEB.

The trace shows `mov eax, [0x30]` — not `mov eax, fs:[0x30]`.

That detail matters.

#### 4.2.2 Why `scdbg` Stopped: Wrong Execution Model

`scdbg` is historically oriented around 32-bit shellcode emulation patterns[^4] and simplified Windows environment emulation. The payload here is `AMD64` Donut shellcode, which expects:

* A 64-bit execution context
* Correct segment register usage (GS access for PEB style lookups)
* Correct assumptions about memory layout and loader-provided structures

So `scdbg` trying to interpret this blob ends up in a mismatch:

* It hits memory reads that should have been relative to a segment base or runtime-resolved pointer,
* But instead it tries to read absolute address `0x00000000` or `0x30` in a flat emulation space,
* It then dies with error accessing `0x00000000` not mapped.

Essentially this tells us that the emulator is the wrong tool for this job.

So the conclusion from here is:

> This blob behaves like shellcode, but scdbg can’t execute it meaningfully because it’s the wrong architecture/assumption set.

That’s what pushed me to switch tools.


### 4.3 Donut Identification and Unpacking

Since scdbg wasn’t a good fit, I ran the blob through Detect It Easy (DIE). DIE classified it as:

> Shellcode: Donut(0.9.2)[AMD64]

![Payload DIE Detection]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/4-die-donut-detected.png" | relative_url}})

DIE suggested the payload is **Donut** shellcode[^2]: a position-independent wrapper commonly used to deliver PE payloads. We know that:

* A PE file is meant to be loaded by the Windows loader (it has headers, sections, imports, relocations).
* Shellcode is meant to be dropped into memory and executed without the OS loader.
* Donut bridges the gap by packaging a PE (or other module) into a self-contained shellcode “launcher” that:
    * Resolves needed APIs dynamically,
    * Allocates memory,
    * Reconstructs or maps the embedded module,
    * And transfers execution to it.

So in this multi-stage chain:
* Go loader decrypts blob → executes it
* Blob is Donut shellcode → whose job is to unpack/map an embedded PE
* That embedded PE is the real implant (the part that actually “does things”)

I used a tool called [donut_decryptor](https://github.com/volexity/donut-decryptor), which can parse the shellcode and extract the embedded `DONUT_INSTANCE` structure. Running it against `payload.decrypted` produced:

![Undonut the payload]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/5-donut-undonut.png" | relative_url}})

The tool does find the `DONUT_INSTANCE` structure, and recovers the binary and writes it to `mod_payload.decrypted`, and also produces more information about the instance.

![Undonut instance information]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/6-donut-instance-info.png" | relative_url}})

After "undonuting," we can see that the recovered artifact is a real PE:

![Undonut recovered PE]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/7-donut-third-stage-payload.png" | relative_url}})

That's the transition point where the Go loader stops being interesting and the native implant begins.

## 5. Stage 3/3 - Deobfuscated Donut Payload: Native x64 PE Implant

Once the Donut wrapper is peeled away, the recovered payload behaves like a conventional native Windows implant. We again load it into cutter to get a general overview of it.

![Undonut recovered PE]({{"/public/images/2026-02-15-valleyrat-part-1-static-analysis/valley-rat-payload-extraction/8-mod-payload-cutter.png" | relative_url}})

Analysing it we observe that it enters through the PE entrypoint, runs CRT startup, sets up process-local state, and then transitions into its “real” operational loop.

### 5.1 CRT Startup and Heap Setup

From the implant entrypoint, execution flows through the usual C/C++ runtime machinery (the CRT).

```c
                        entry 
140009a74 48 83 ec 28     SUB        RSP,0x28
140009a78 e8 93 3c        CALL       __security_init_cookie
140009a7d 48 83 c4 28     ADD        RSP,0x28
140009a81 e9 76 fe        JMP        __tmainCRTStartup()
```

That means it is preparing the process for normal Win32 execution: initializing security cookies, setting up thread-local storage, initializing global constructors (if any), and establishing an allocator strategy.

A detail that stood out is that the implant did not simply rely on the default process heap forever. Instead, early in initialization it created a **private heap** using:

* `HeapCreate()` - allocates a dedicated heap object owned by the process
* `HeapAlloc()` - uses that heap for subsequent allocations

This was handled by a `_heap_init()` call:

```c
140009950 89 5c 24 40     MOV        dword ptr [RSP + local_res8],EBX
140009954 e8 6f 05        CALL       _heap_init
```

In the failure paths of the above operations (calls resembling `FUN_14000a30c(0x1c)` / `FUN_14000a30c(0x10)`), the behavior matches fail-fast CRT-style enforcement. The implant checks critical initialization results (like heap handle creation). If the handle is null, it does not continue; it aborts through an error routine. This can be seen as early environment checking: if something about the environment is wrong (emulation, restricted sandbox, incompatible runtime), it exits early and avoids noisy crashes later.

### 5.2 Environment Check

Again, in `_heap_init()` the implant calls `GetVersion()`.

```c
140009eeb 48 85 c0        TEST       RAX,RAX
140009eee 74 29           JZ         LAB_140009f19
140009ef0 ff 15 02        CALL       qword ptr [->KERNEL32.DLL::GetVersion]
```

This was interpreted as the implant asking, "what kind of Windows am I on?" It likely does this to support:

* **Compatibility gates**: Avoid executing paths that rely on APIs not present on older systems.
* **Behavior selection**: Different injection methods, persistence tactics, or system paths by version.
* **Profiling**: OS version becomes part of an environment fingerprint or telemetry report to the operator.

Given the rest of the implant’s behavior (threading, registry usage, dumping via DbgHelp), the most conservative interpretation is that it’s used for **gating and branching**.

## 6. Anti-Analysis and Self-Process Dumping

After initial setup, execution reaches `FUN_140008580`. This function is best understood as a **runtime staging hub**: it wires up crash/exception handling, performs stealthy UI behavior, and then kicks off the long-running worker thread that later drives C2 behavior. Specifically, this function does at least four distinct things:

* Installs the unhandled exception filter
* Hides the console window
* Posts a thread message (likely to pump or unblock something UI/message related)
* Spawns the worker thread (FUN_1400080e0) and waits on it

The first important call here is `SetUnhandledExceptionFilter`. This registers `FUN_140008550` as the process-wide unhandled exception filter. If an exception occurs and nothing catches it, Windows will invoke this handler instead of immediately terminating the process with the default crash UI.

```c
                        FUN_140008580
140008580 48 83 ec 38     SUB        RSP,0x38
140008584 48 8d 0d        LEA        RCX,[FUN_140008550]
14000858b ff 15 97        CALL       qword ptr [->KERNEL32.DLL::SetUnhandledExceptionFilter]
```
Immediately afterward, the implant calls `GetConsoleWindow()` and then `ShowWindow(hWnd, 0)`. Passing `0` corresponds to `SW_HIDE`[^5], i.e., it hides its console window if one exists. A console-compiled payload is far noisier if it leaves a visible window on the user desktop.

```c
140008591 ff 15 a9        CALL       qword ptr [->KERNEL32.DLL::GetConsoleWindow]
140008597 33 d2           XOR        EDX,EDX
140008599 48 8b c8        MOV        RCX,RAX
14000859c ff 15 b6        CALL       qword ptr [->USER32.DLL::ShowWindow]
...
```

Finally, `FUN_140008580` spawns the worker thread, so the main thread becomes a supervisor. It creates the operational thread and waits on it.

```c
...
1400085c6 4c 8d 05        LEA        R8,[FUN_1400080e0]
1400085cd 45 33 c9        XOR        R9D,R9D
1400085d0 4c 89 5c        MOV        qword ptr [RSP + local_10],R11
1400085d5 33 d2           XOR        EDX,EDX
1400085d7 33 c9           XOR        ECX,ECX
1400085d9 44 89 5c        MOV        dword ptr [RSP + local_18],R11D
1400085de ff 15 8c        CALL       qword ptr [->KERNEL32.DLL::CreateThread]
1400085e4 83 ca ff        OR         EDX,0xffffffff
1400085e7 48 8b c8        MOV        RCX,RAX
1400085ea 48 89 05        MOV        qword ptr [DAT_1400234f0],RAX
1400085f1 ff 15 59        CALL       qword ptr [->KERNEL32.DLL::WaitForSingleObject]
1400085f7 48 8b 0d        MOV        RCX,qword ptr [DAT_1400234f0]
1400085fe ff 15 74        CALL       qword ptr [->KERNEL32.DLL::CloseHandle]
140008604 b9 2c 01        MOV        ECX,0x12c
140008609 ff 15 51        CALL       qword ptr [->KERNEL32.DLL::Sleep]
```

### 6.1 FUN_140008550: Exception Filter + Debugger Gate

The exception filter itself begins with a debugger check:

```c
                        FUN_140008550
140008550 40 53           PUSH       RBX
140008552 48 83 ec 20     SUB        RSP,0x20
140008556 48 8b d9        MOV        RBX,RCX
140008559 ff 15 01        CALL       qword ptr [->KERNEL32.DLL::IsDebuggerPresent]
14000855f 85 c0           TEST       EAX,EAX
140008561 74 08           JZ         LAB_14000856b
140008563 33 c0           XOR        EAX,EAX
140008565 48 83 c4 20     ADD        RSP,0x20
140008569 5b              POP        RBX
14000856a c3              RET
```

Two behaviors stand out immediately:
* If a debugger is detected -> return early (skip the noisy part).
* Otherwise -> proceed into a second branch that performs a dump routine (`FUN_140008370`).

As an unhandled exception filter, Windows calls this function with exception-context-like data. The hypothesis here is that the handler’s purpose is less about "handling" an exception and more about conditionally executing the dump logic.

The dump routine path includes:

```c
14000838f 48 8d 0d        LEA        RCX,[u_DbgHelp.dll_14001ab68]
140008396 ff 15 9c        CALL       qword ptr [->KERNEL32.DLL::LoadLibraryW]
...
1400083ac 48 8d 15        LEA        RDX,[s_MiniDumpWriteDump_14001ab80]
1400083b3 48 8b c8        MOV        RCX,RAX
...
1400083b6 48 89 ac        MOV        qword ptr [RSP + local_res10],RBP
1400083be ff 15 8c        CALL       qword ptr [->KERNEL32.DLL::GetProcAddress]
...
14000840d ff 15 45        CALL       qword ptr [->KERNEL32.DLL::GetLocalTime]
...
14000844a 4c 8d 05        LEA        R8,[u_!analyze_-v_14001ab98]
140008451 48 8d 15        LEA        RDX,[u_%s-%04d%02d%02d-%02d%02d%02d.dmp_14001a
140008458 48 8d 4c        LEA        RCX=>local_238,[RSP + 0x70]
14000845d ff 15 05        CALL       qword ptr [->USER32.DLL::wsprintfW]
...
140008463 4c 89 6c        MOV        qword ptr [RSP + local_278],R13
140008468 45 8d 45 03     LEA        R8D,[R13 + 0x3]
14000846c 48 8d 4c        LEA        RCX=>local_238,[RSP + 0x70]
140008471 45 33 c9        XOR        R9D,R9D
140008474 ba 00 00        MOV        EDX,0xc0000000
140008479 44 89 6c        MOV        dword ptr [RSP + local_280],R13D
14000847e c7 44 24        MOV        dword ptr [RSP + local_288],0x2
140008486 ff 15 bc        CALL       qword ptr [->KERNEL32.DLL::CreateFileW]
```

That second branch is especially interesting because creating a minidump of its own process appears deliberate and can capture sensitive runtime state. At this stage, I considered a few plausible motivations:

* **Self-debugging:** Generate a dump that can be pulled later to debug failures on victim systems.
* **Anti-analysis gating:** Only produce artifacts when not under a debugger (to avoid handing analysts decrypted state during interactive reversing).
* **Noise injection / disruption**: Dumping can pollute disk with artifacts, trigger alerts, or waste analyst time depending on how it is used operationally.

### 6.2 Analysing the Self-dump Flow (Exception-Triggered)

#### 6.2.1 Loading `DbgHelp.dll`

The dump path begins by dynamically loading `DbgHelp.dll`:

```c
LEA RCX,[u_DbgHelp.dll]
CALL [KERNEL32.LoadLibraryW]
```

This avoids a static import of DbgHelp in the PE import table. Static imports are analyst-friendly, allowing us to eyeball the IAT and immediately know what the binary wants. Dynamic resolution reduces that visibility and also makes the dumping APIs conditional, as they only appear if/when the branch executes.

#### 6.2.2 Resolving and Calling `MiniDumpWriteDump`

After loading `DbgHelp.dll`, the implant resolves `MiniDumpWriteDump` by name via `GetProcAddress`:

```c
GetProcAddress(hDbgHelp, "MiniDumpWriteDump")
```

It then performs a programmatic self-dump of the current process. The typical supporting calls in this pattern are:

* `GetCurrentProcessId()`
* `GetCurrentProcess()`
* Create/open a file handle for the dump output (`CreateFileW`)
* `MiniDumpWriteDump(processHandle, pid, fileHandle, dumpType, …)`

The key point is that this is not an OS-generated crash dump created by WerFault. This is an intentional dump created by the implant itself, and it can include:

* Decrypted configuration (in memory),
* Decrypted or unpacked modules that never touch disk,
* Runtime-resolved function pointers and state,
* Potentially keys/tokens/parameters used later in execution.

This behavior may help operators debug, but it can also leak the implant's secrets to defenders if the dump is recovered.

#### 6.2.3 Dump Filename Format

The filename is constructed using `GetLocalTime` and `wsprintfW`, with the timestamp format string:

```text
"%s-%04d%02d%02d-%02d%02d%02d.dmp"
```

This produces a timestamped dump name:

* `PREFIX-YYYYMMDD-HHMMSS.dmp`

The exact value for `%s` depends on what the caller passes at the callsite. In the disassembly we saw a string `u"!analyze -v"`, which is suspicious as a prefix candidate and may be a decoy or debug artifact. Regardless, the timestamp structure is clear: it is designed to be unique per run.

## 7. C2 Configuration Storage and Parsing

After initialization and anti-analysis staging, the implant starts to look like an actual C2 client. This logic is reached via `FUN_1400073d0` (invoked during setup), which then leads into the main configuration parser `FUN_1400073e4`. The parser operates on a compact delimited configuration string, extracts values into runtime globals, and supports a registry-based override to “retask” without patching the binary.

### 7.1 Recovered Config String

Early in the parser we saw:

```c
14000740e 48 8b cd        MOV        RCX=>DAT_14001f440,RBP
140007411 e8 a6 24        CALL       _wcsrev
```

This tells us that the string at `&DAT_14001f440` is stored in reverse. Static string extraction sees nonsense, while at runtime, `_wcsrev` flips it back just before parsing.

Once reversed, the configuration appears as a delimiter-separated table:

```text
|p1:maaahao.vip|o1:8081|t1:1
|p2:maaahao.vip|o2:8888|t2:1
|p3:maaahao.vip|o3:80|t3:1
|dd:1|cl:1|fz:|bb:1.0|bz:2025.11.7|jp:0|bh:0|ll:0|dl:0|sh:0|kl:0|bd:
```

We can see a structural detail here: the string begins with a leading `|`. That makes parsing simpler and safer because every entry is boundary-delimited, reducing the risk of accidental substring matches inside values. Even if the implementation searches for `p1:` rather than `|p1:`, this layout still reflects a deliberate "flat table" grammar.

At a glance, the grammar is intentionally minimal:
* Entries are separated by `|`
* Each entry is a `key:value` pair
* Keys are short (2 chars + optional index), values are either strings or single-digit toggles

The first cluster (`p1/o1/t1`, `p2/o2/t2`, `p3/o3/t3`) reads like a list of C2 endpoints with enable flags. The later flags (`dd`, `cl`, `jp`, `bh`, `ll`, `dl`, `sh`, `kl`, `bd`) behave like feature toggles, versioning markers, and behavior parameters.

The intent here is clear: the implant wants a compact, easily replaceable config that can be parsed without heavy dependencies.

### 7.2 Parsing Helper: Key Extractor

`FUN_1400072a0` was determined to be the implant’s mini “config getter.” Its behavior is consistent across repeated calls:

* Search the config buffer (`DAT_14001f440`) for a key prefix like `L"p1:"`.
* Once found, advance past the prefix.
* Copy characters until the next delimiter `|`.
* Write the extracted value into a destination buffer, or set a boolean if the destination is `NULL`.

This helper explains why the main parser (`FUN_1400073d0`) repeatedly calls it for keys:

* `p1`, `o1`, `p2`, `o2`, `p3`, `o3` copied into buffers
* `t1`, `t2`, `t3` handled as booleans (or via direct `1` checks)
* Additional keys extracted into other globals

Once extracted, other code never has to parse the raw string again. It simply reads from the populated runtime globals (e.g., host buffers, port buffers, and enable flags). This is why `FUN_1400080e0` looks like it selects between pre-parsed tables rather than interpreting the string directly.

### 7.3 Boolean Toggles

The toggle logic is consistent: if the character after the colon is `'1'` (`0x31`), set a corresponding global to `1`.

We saw this pattern for:

* `t1`, `t2`, `t3` -> endpoint enable flags
* And this is likely for other switches (`jp`, `bh`, `ll`, `dl`, `sh`, `kl`) depending on how the implant uses them later in execution.

### 7.4 Config Override via `HKCU\Console\IpDate`

The most operationally interesting detail is a registry-based override. The parser checks:

```text
HKCU\Console\IpDate
```

It first opens the `Console` key under `HKCU`:

```c
140007d4d 48 8d 84        LEA        RAX=>local_res18,[RSP + 0x80]
140007d55 48 8d 15        LEA        RDX,[u_Console_14001ab48]
140007d5c 41 b9 19        MOV        R9D,0x20019
140007d62 45 33 c0        XOR        R8D,R8D
140007d65 48 c7 c1        MOV        RCX,-0x7fffffff
140007d6c c7 44 24        MOV        dword ptr [RSP + local_res10],0x3
140007d74 48 89 44        MOV        qword ptr [RSP + local_48],RAX
140007d79 c7 44 24        MOV        dword ptr [RSP + local_res8],0x0
140007d81 ff 15 81        CALL       qword ptr [->ADVAPI32.DLL::RegOpenKeyExW]
```

Then it queries the `HKCU\Console\IpDate` value.

```c
140007d8b 48 8b 8c        MOV        RCX,qword ptr [RSP + local_res18]
140007d93 48 8d 44        LEA        RAX=>local_res8,[RSP + 0x70]
140007d98 4c 8d 4c        LEA        R9=>local_res10,[RSP + 0x78]
140007d9d 48 89 44        MOV        qword ptr [RSP + local_40],RAX
140007da2 48 8d 15        LEA        RDX,[u_IpDate_14001ab58]
140007da9 45 33 c0        XOR        R8D,R8D
140007dac 48 c7 44        MOV        qword ptr [RSP + local_48],0x0
140007db5 ff 15 5d        CALL       qword ptr [->ADVAPI32.DLL::RegQueryValueExW]
```

Importantly, it uses the common two-step query pattern:
* Query with a null data pointer to retrieve the required size.
* If the size passes a sanity check (in this case `> 10`), clear the config buffer and query again to fetch the actual bytes.

```c
140007dbb 83 7c 24        CMP        dword ptr [RSP + local_res8],0xa
140007dc0 0f 86 e3        JBE        LAB_1400080a9
140007dc6 33 d2           XOR        EDX,EDX
140007dc8 41 b8 d0        MOV        R8D,0x7d0
140007dce 48 8b cd        MOV        RCX=>DAT_14001f440,RBP
140007dd1 e8 ea 39        CALL       FUN_14000b7c0
140007dd6 48 8b 8c        MOV        RCX,qword ptr [RSP + local_res18]
140007dde 4c 8d 5c        LEA        R11=>local_res8,[RSP + 0x70]
140007de3 4c 89 5c        MOV        qword ptr [RSP + local_40],R11
140007de8 4c 8d 4c        LEA        R9=>local_res10,[RSP + 0x78]
140007ded 48 8d 15        LEA        RDX,[u_IpDate_14001ab58]
140007df4 45 33 c0        XOR        R8D,R8D
140007df7 48 89 6c        MOV        qword ptr [RSP + local_48],RBP=>DAT_14001f440
140007dfc ff 15 16        CALL       qword ptr [->ADVAPI32.DLL::RegQueryValueExW]
```

We interpret this as a post-deployment control channel:

* Operators can change C2 host/ports and toggles without recompiling.
* The implant can be “retasked” locally by updating a registry value.
* The key path is intentionally boring-looking (“Console” settings) which helps it blend in compared to something obviously malicious.

The end result is that configuration is effectively **baked-in but replaceable**. Static config provides defaults, while the registry override provides agility.

## 8. Where Static Analysis Stops (and Part 2 Starts)

At the end of static analysis, this is what we know:

1. **Stage-0 Go loader**
   * Resolves its own path
   * Persists via `HKCU\...\Run` as `CalculatorApp_AutoStart`
   * Decrypts an embedded blob (`0x25660` bytes) using AES-ECB with key `1ws12uuu11j*p5fr`
   * Executes the decrypted buffer in-memory via `VirtualAlloc` / `RtlMoveMemory` / `CreateThread`

2. **Embedded blob**
   * Donut shellcode container
   * Unwraps into a native `x64` PE implant

3. **Native implant**
   * CRT + heap setup (`HeapCreate`, `HeapAlloc`)
   * Environment/version checks (`GetVersion`)
   * Setup hub (`FUN_140008580`) that installs an exception filter, hides UI, and starts the operational thread
   * Debugger gate + self-process dumping (`DbgHelp.dll` + `MiniDumpWriteDump`) with timestamped `.dmp` naming
   * Reversed-string config storage + runtime parsing
   * Registry-based config override via `HKCU\Console\IpDate`

In Part 2 we’ll treat the C2 configuration as an active protocol, recover message framing, capture and emulate the exchange, and build a minimal server that keeps the implant talking long enough to expose its full behavior.

## References

[^1]: [MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
[^2]: [Donut Shellcode Generator: Beginner's Guide](https://www.hackercoolmagazine.com/donut-shellcode-generator-beginners-guide/)
[^3]: [Exploring Process Environment Block](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block)
[^4]: [Using `scdbg` to Analyze Shellcode](https://isc.sans.edu/diary/24058)
[^5]: [ShowWindow Function (winuser.h)](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow)
