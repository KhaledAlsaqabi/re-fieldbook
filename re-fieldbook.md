# Reverse Engineering Fieldbook

A single-pass reference for taking an unknown binary from `file` to flag: identification, tooling, hotkeys, the assembly patterns compilers actually emit, anti-analysis bypasses, and the automation that turns a manual afternoon into a five-second script.

---

## 1. Initial Assessment Methodology

### 1.1 Static assessment workflow

Work top-down. Each step should take seconds and can rule out entire classes of technique — don't open Ghidra until you know what you're opening it on.

1. **Identify the container.** `file ./target` — architecture, bitness, endianness, static/dynamic linking, stripped status.
2. **Hash it** for correlation against VirusTotal / known-sample databases and to detect if a "patched" copy changed. `sha256sum ./target`.
3. **Check for packing** before doing anything else — a packed binary's strings and imports are meaningless until unpacked. See packer indicators below.
4. **Pull strings** in both narrow and wide encodings; grep for flag formats, URLs, format strings, and library version banners.
5. **Enumerate imports/exports** — the import table is a free summary of what the binary *does* (crypto calls, network calls, anti-debug APIs, file I/O).
6. **Run it** in an isolated VM/container with `strace`/`ltrace` or Procmon — dynamic behavior is often faster than static reading.
7. **Open in a decompiler** only once the above narrows the search space (target function, suspected algorithm, anti-analysis technique).
8. **Set up dynamic analysis** (debugger, Frida, or emulator) matched to what step 6 revealed.

> **Quick wins first.** Before any real reversing: `strings target | grep -iE 'flag|CTF\{|pico|key|secret'`, then `ltrace ./target`. A meaningful fraction of easy CTF binaries fall to these two commands alone.

### 1.2 Binary identification across formats

| Format | Magic bytes | Identify with | Key structures |
|---|---|---|---|
| ELF (Linux) | `7F 45 4C 46` | `file`, `readelf -h` | ELF header → Program headers (segments) → Section headers; `e_type` EXEC/DYN/REL/CORE |
| PE (Windows) | `4D 5A` ("MZ") | `file`, `dumpbin /headers` | DOS header → PE signature → COFF header → Optional header → Section table → Import/Export dirs |
| Mach-O (macOS/iOS) | `CF FA ED FE` / `FE ED FA CE` | `file`, `otool -h` | `mach_header(_64)` → load commands (`LC_SEGMENT_64`, `LC_SYMTAB`) → segments/sections |
| Fat/Universal Mach-O | `CA FE BA BE` | `lipo -info`, `file` | `fat_header` → array of `fat_arch` (per-architecture Mach-O slices) |
| APK (Android) | `50 4B 03 04` ("PK") | `unzip -l`, `aapt dump badging` | ZIP container: `classes.dex`, `AndroidManifest.xml`, `lib/<abi>/*.so`, `resources.arsc` |
| .NET PE (CLR) | `4D 5A` + CLR header | `dotnet-info`, `ildasm /all` | Standard PE + CLI header pointing to metadata tables, IL method bodies |
| Java class | `CA FE BA BE` | `javap -c`, `file` | constant pool → fields → methods → bytecode attributes |
| WASM | `00 61 73 6D` | `wasm-objdump -h` | Type/Import/Function/Export/Code sections |

```bash
# One-shot ID pass — run this on every new sample
file target
sha256sum target
readelf -h target 2>/dev/null || dumpbin /headers target 2>/dev/null
readelf -d target 2>/dev/null   # dynamic deps, RPATH, PIE/RELRO flags
checksec --file=target          # RELRO, canary, NX, PIE, RPATH, Fortify
strings -n 8 target | head -50
strings -e l target | head -20  # UTF-16LE strings on Windows binaries
```

**Endianness & architecture cross-check.** Don't trust `file` blindly for exotic targets (firmware, game console dumps). Cross-check `e_machine` in the ELF header against the disassembly — a MIPS binary disassembled as little-endian when it's big-endian produces garbage that looks almost-but-not-quite like real code.

| `e_machine` value | Architecture | Typical endianness |
|---|---|---|
| `0x03` | x86 (i386) | Little |
| `0x3E` | x86-64 | Little |
| `0x28` | ARM (32-bit) | Little (usually) |
| `0xB7` | AArch64 | Little |
| `0x08` | MIPS | Either — check `ELFDATA2LSB`/`MSB` |
| `0xF3` | RISC-V | Little |
| `0x14` | PowerPC | Big (classic), either (PPC64LE) |

### 1.3 Identifying packers and protectors

Packing compresses/encrypts the real code and wraps it in a small stub that decompresses it at runtime. Protectors (VMProtect, Themida) go further and virtualize code into custom bytecode. Both defeat static string/import analysis until undone.

| Indicator | What it means |
|---|---|
| High entropy sections (>7.0/8.0) | Compressed or encrypted data — run `binwalk -E` or Detect It Easy's entropy view |
| Tiny import table (5–15 entries) | Real imports are resolved manually at runtime (`GetProcAddress`/`dlsym` loops) — classic packer stub signature |
| Single executable section, huge and RWX | Unpacking stub decompresses into this region and jumps into it |
| Entry point outside `.text`, or in a section named `UPX0`/`UPX1` | UPX or UPX-derivative packer |
| Section names like `.vmp0`, `.vmp1`, `.themida` | Named protector — VMProtect / Themida |
| Huge number of indirect jumps through a dispatcher loop | Code virtualization (VM-based protector) |
| Import Address Table populated only after a big decode loop executes | IAT reconstruction needed post-unpack (Scylla) |

```bash
die target                       # Detect It Easy CLI — signature-based packer/compiler ID
diec -e target                   # entropy per section
binwalk -E target                 # entropy graph, also finds embedded files
upx -t target                    # test if UPX-packed; upx -d target -o unpacked to strip
readelf -S target | awk '{print $2,$7}'   # flag W+E (writable+executable) sections
```

| Packer/Protector | Notes |
|---|---|
| UPX | Open-source, single-stage. `upx -d` almost always works. If header is corrupted intentionally, manually locate the decompression stub and dump at OEP. |
| Themida / WinLicense | Heavy anti-debug + optional virtualization. Dump at OEP with ScyllaHide-assisted x64dbg, fix IAT with Scylla. |
| VMProtect | Converts native code to custom VM bytecode. No generic unpacker — trace handler dispatch dynamically instead of trying to statically devirtualize. |
| ASPack / PECompact | Simple compressors, unicorn-emulate the stub or single-step to OEP, then dump. |

### 1.4 Hash extraction, string analysis & import/export triage

```bash
md5sum target; sha1sum target; sha256sum target
ssdeep target                    # fuzzy hash — similarity to known samples
pehash target                    # import-table hash, clusters packed variants
```

**String triage priorities:**
- Flag-shaped strings: `flag{`, `CTF{`, `FLAG:`
- Format strings (`%s`, `%d`) near suspicious calls
- File paths — leak build environment / author
- URLs / IPs — C2 or remote-check endpoints
- Crypto constants as ASCII (base64 alphabets, PEM headers)

**Import table → capability map:**

| Import seen | Suggests |
|---|---|
| `ptrace`, `PTRACE_TRACEME` | Anti-debug (Linux) |
| `IsDebuggerPresent`, `NtQueryInformationProcess` | Anti-debug (Windows) |
| `CryptEncrypt`, `EVP_EncryptInit`, `AES_set_encrypt_key` | Crypto routine to reverse |
| `connect`, `WSAConnect`, `socket` | Network validation / remote flag check |
| `mmap`+`PROT_EXEC`, `VirtualAlloc`+`PAGE_EXECUTE` | Self-modifying / JIT / unpacking stub |
| `GetProcAddress` in a loop | Manual import resolution — packed binary |

---

## 2. Comprehensive Toolbox Directory

### 2.1 Disassemblers & decompilers

| Tool | Best for | Core commands / actions |
|---|---|---|
| Ghidra | Free, scriptable (Java/Python), best-in-class for large stripped binaries, built-in version tracking & diffing | `analyzeHeadless proj/ tmp -import bin -postScript script.py`; Window → Script Manager for Ghidrathon (Python 3) |
| IDA Pro / IDA Free | Gold-standard decompiler (Hex-Rays), best x86/ARM signature libraries (FLIRT), fastest manual workflow | `ida64 -A -S"script.py" target`; File → Produce file → Create C file (batch decompile) |
| Binary Ninja | Clean intermediate languages (LLIL/MLIL/HLIL), excellent Python API for automation, fast headless mode | `binaryninja.load(path).analysis_completion_event.wait()`; `bn.get_function_at(addr).hlil` |
| Cutter (rizin/radare2 GUI) | Free, fast, good for quick triage without IDA/Ghidra license, integrated debugger | `r2 -d ./binary` inside Cutter's console panel; `aaa` to auto-analyze |
| dogbolt.org | Side-by-side decompiler comparison (Ghidra/IDA/BinNinja/RetDec/angr) from one upload — resolves ambiguous decompilation fast | Upload binary, compare panes directly, no install |

### 2.2 Debuggers

| Tool | Platform | Notes |
|---|---|---|
| x64dbg / x32dbg | Windows | Free, TitanEngine core, plugin ecosystem (ScyllaHide for anti-anti-debug, xAnalyzer) |
| GDB (+ GEF/PEDA/pwndbg) | Linux, cross-arch via `gdb-multiarch` | GEF adds heap analysis, pattern search, context view; scriptable in Python |
| WinDbg / WinDbg Preview | Windows, kernel-mode capable | Best for driver/kernel debugging, crash dump (.dmp) analysis, time-travel debugging (TTD) |
| dnSpy / dnSpyEx | .NET (IL) | Edit-and-continue IL debugging, decompile+debug in one tool, no source needed |
| lldb | macOS/iOS, LLVM-based | Required for Mach-O; Python scripting via `script` command |

```bash
# GEF setup (one-time)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"   # installs GEF into ~/.gdbinit
gdb -q ./target
# gef> gef config       tune context panes (disasm lines, stack lines, etc.)
```

### 2.3 PE & ELF analysis tools

| Tool | Format | Use case |
|---|---|---|
| PEstudio | PE | Static triage dashboard — imports, strings, blacklisted APIs, VirusTotal integration, no execution |
| PE-bear | PE | Visual header/section editor, good for manual patch of PE headers post-unpack |
| DIE (Detect It Easy) | PE/ELF/Mach-O | Signature-based packer/compiler/language detection, entropy view, built-in hex viewer |
| readelf | ELF | `readelf -h/-l/-S/-d/-r/-x .rodata target` |
| objdump | ELF/PE (BFD) | `objdump -d -M intel target`; `objdump -T target` (dynamic symbols) |
| nm | ELF/Mach-O | `nm -D target` (dynamic symbols), `nm -C` (demangled C++) |
| pefile (Python lib) | PE | Scriptable header/import/export parsing for automation, IAT hash computation |

### 2.4 Unpacking & memory dumping tools

| Tool | Purpose |
|---|---|
| Process Hacker / System Informer | Live process/handle/memory inspector for Windows; replaces Task Manager for RE work — inspect loaded modules, memory regions, and dump sections directly |
| Scylla | IAT rebuilder — after dumping a packed process at OEP, Scylla walks the fixed-up IAT and rewrites it into a runnable PE |
| Volatility 3 | Memory-forensics framework for full RAM dumps: `vol.py -f mem.dmp windows.pslist`, `windows.malfind` for injected/unpacked code regions |
| PE-Sieve | Scans a running process for in-memory modifications versus the on-disk PE (unpacked payloads, hooks, hollowed processes) and dumps them automatically |

```bash
# PE-Sieve: dump every module in a suspicious PID
pe-sieve64.exe /pid 4821 /dir out_dump

# Volatility 3: find hollowed/injected code in a memory image
python3 vol.py -f dump.raw windows.malfind --dump
```

---

## 3. Keybindings & Cheat Commands

### 3.1 Ghidra

| Key | Action |
|---|---|
| `G` | Go to address / symbol |
| `L` | Rename (label) current symbol |
| `Ctrl+L` | Retype variable (edit data type) |
| `Ctrl+Shift+G` | Patch instruction (assemble in place) |
| `Ctrl+E` | Edit bytes (hex patch) |
| `Ctrl+Shift+E` | Open Function Graph view |
| `X` | Show Xrefs to current symbol |
| `Ctrl+Shift+F` | Search text (strings/decompiler output) |
| `Ctrl+Alt+Left/Right` | Navigate back/forward through history |
| `F` | Create function at cursor |
| `Shift+P` | Edit function signature |
| `;` | Add end-of-line comment |

### 3.2 IDA Pro

| Key | Action |
|---|---|
| `G` | Jump to address |
| `N` | Rename symbol under cursor |
| `X` | List cross-references to item |
| `Ctrl+X` | List cross-references from item (calls made) |
| `F5` | Open Hex-Rays pseudocode for current function |
| `Space` | Toggle graph / text view of disassembly |
| `Alt+T` | Text search (across the whole binary) |
| `Alt+B` | Binary/byte-pattern search |
| `Ctrl+Alt+B` | Toggle breakpoint (debugger) |
| `P` | Create/edit function at cursor |
| `Esc` / `Ctrl+Enter` | Navigate back / forward |
| `:` / `;` | Add regular comment / repeatable comment |
| `Shift+F12` | Open Strings window |

### 3.3 x64dbg

| Key | Action |
|---|---|
| `F2` | Toggle breakpoint |
| `F7` | Step into |
| `F8` | Step over |
| `F9` | Run / continue |
| `Ctrl+F9` | Execute till return (finish current function) |
| `Ctrl+G` | Go to expression/address |
| `Ctrl+B` | Binary search in memory dump |
| `Space` | Assemble instruction at cursor (patch) |
| `Ctrl+E` | Edit bytes in hex |
| `*` (numpad) | Show current EIP/RIP in disassembly |
| `Alt+F1` | Restart debuggee |

### 3.4 GDB (+ GEF)

```gdb
b *0x401234                # breakpoint at raw address
b main                     # breakpoint at symbol
b *main+0xca                # PIE-relative breakpoint
r < input.txt                # run with stdin redirected
c                            # continue
ni / si                     # step over / step into
finish                      # run until current function returns
x/20i $pc                   # disassemble 20 instrs at PC
x/s $rsi                    # dump string at RSI
x/40gx $rsp                  # dump stack as 8-byte hex words
p/x $rax                    # print register in hex

gef> context                 # redraw full context (regs/stack/code)
gef> search-pattern "flag{"  # scan all mapped memory for a string
gef> vmmap                   # memory map with permissions
gef> telescope $rsp 30       # dereference chain down the stack
gef> patch byte $pc 0x90     # NOP a single byte
gef> heap chunks             # glibc heap chunk walk (pwn)
```

---

## 4. Common Scenarios, Anti-Analysis & Reversing Patterns

### 4.1 Control flow: source → x86-64 / ARM

**If / else**

x86-64:
```asm
cmp   edi, 10
jle   .else_branch     ; inverted condition — jumps AROUND the "if" body
    ...                 ; if-body
    jmp .end
.else_branch:
    ...                 ; else-body
.end:
```

ARM64 (AArch64):
```asm
cmp   w0, #10
b.le  .else_branch
    ...                 // if-body
    b   .end
.else_branch:
    ...                 // else-body
.end:
```

**Rule of thumb:** the compiler almost always inverts the source condition and jumps past the "true" branch — reading the jump mnemonic backward (`jle` ⇒ source condition was `>`) is the fastest way to reconstruct the original C.

**Loops (for / while)**

```asm
; x86-64 — classic "test-at-bottom" loop
    xor   ecx, ecx            ; i = 0
.loop:
    ...                        ; body, uses ecx as index
    inc   ecx
    cmp   ecx, edx             ; i < n
    jl    .loop                 ; loop condition checked at the BOTTOM (do-while shape)
```

Compilers rotate `for`/`while` loops into a do-while shape with an initial guard check before entry — if you see a single `cmp`/`jge` before the loop label plus the bottom-of-loop `cmp`/`jl`, that's a rotated `for`, not two separate loops.

**Switch statements**

| Pattern | Compiled form | Recognize by |
|---|---|---|
| Dense, sequential cases (0,1,2,3…) | Jump table: `jmp [rip+table+rax*8]` | Array of code addresses in `.rodata`/`.text`, indexed by the switch variable directly |
| Sparse cases (1, 5, 100, 9000) | Chain of `cmp`/`je` — indistinguishable from if/else-if chain | Repeated comparisons against the same register |
| Mixed density | Binary-search style comparison tree, then jump table for a dense sub-range | A few range-checks (`cmp`/`ja` "default" bailout) around a jump table |

**Function calls & calling conventions**

| Convention | Integer/pointer args (in order) | Return | Caller/callee cleanup |
|---|---|---|---|
| System V AMD64 (Linux/macOS x86-64) | `rdi, rsi, rdx, rcx, r8, r9` | `rax` (rdx:rax for 128-bit) | Caller cleans stack |
| Microsoft x64 (Windows) | `rcx, rdx, r8, r9` | `rax` | Caller cleans; 32 bytes shadow space reserved by caller |
| AArch64 AAPCS | `x0–x7` | `x0` (x1 for 128-bit) | N/A — register-based |
| x86 cdecl | Stack, right-to-left | `eax` | Caller cleans |
| x86 stdcall | Stack, right-to-left | `eax` | Callee cleans (`ret 0xN`) |

### 4.2 Anti-debugging bypasses

| Technique | Platform | Bypass |
|---|---|---|
| `IsDebuggerPresent()` | Windows | Patch return to always 0, or flip `PEB.BeingDebugged` (offset +0x2) to 0 in the debugger |
| `PEB.NtGlobalFlag` | Windows | Zero the flag at PEB+0x68 (checks for `FLG_HEAP_ENABLE_TAIL_CHECK`\|`FLG_HEAP_ENABLE_FREE_CHECK`\|`FLG_HEAP_VALIDATE_PARAMETERS`, set when launched under a debugger) |
| `NtQueryInformationProcess` (ProcessDebugPort) | Windows | Hook to force return value 0 for `ProcessDebugPort`/`ProcessDebugFlags`/`ProcessDebugObjectHandle` |
| Heap flags (HeapFlags / ForceFlags) | Windows | Patch process heap header flags post-creation, or use a plugin (ScyllaHide) that intercepts these systemically |
| TLS callbacks | Windows | Enumerate PE TLS Directory before running; set breakpoint at callback entry — it fires before `main` |
| `rdtsc` timing checks | Both | Patch out the delta comparison, or hook `rdtsc`/`QueryPerformanceCounter` to return a fixed small delta |
| Hardware breakpoint scan (DR0-DR3 via GetThreadContext) | Windows | Prefer software breakpoints (INT3) for sensitive checks, or zero DR registers before the check reads them |
| `ptrace(PTRACE_TRACEME)` | Linux | LD_PRELOAD a shim that makes `ptrace()` always return 0 (a debugger can't attach if the process already self-traced, so blocking the self-trace call lets your real debugger attach) |
| `/proc/self/status` TracerPid | Linux | Hook `open`/`read` on that path via Frida/LD_PRELOAD to rewrite `TracerPid:` to 0 |
| INT3 self-scan / code self-hashing | Both | Use hardware breakpoints instead of software INT3 where possible, or checksum-patch after inserting your own breakpoints |
| Signal-based (SIGTRAP handler catches its own breakpoint) | Linux | Set `catch signal SIGTRAP` / `handle SIGTRAP nostop noprint pass` in GDB so the app's own handler still runs |

```c
// ptrace LD_PRELOAD shim (Linux)
#include <sys/types.h>
// gcc -shared -fPIC -o antiptrace.so antiptrace.c -ldl
long ptrace(int request, ...) { return 0; }
// LD_PRELOAD=./antiptrace.so ./target
```

### 4.3 Anti-VM bypasses

| Check | What it inspects | Bypass |
|---|---|---|
| Registry artifacts | `HKLM\...\SCSI\...\Identifier` for "VMware"/"VBOX"/"QEMU" | Rename/delete offending registry keys, or hook `RegQueryValueEx` to sanitize returned strings |
| MAC address OUI | First 3 bytes matching known hypervisor vendor prefixes (00:05:69 VMware, 08:00:27 VirtualBox, 00:1C:14 VMware) | Set a custom MAC on the VM's virtual NIC before running the sample |
| CPUID hypervisor bit | `CPUID.1:ECX[31]` = 1 when running under a hypervisor | Patch out the check, or use a hypervisor with CPUID hiding (e.g. VMware's `hypervisor.cpuid.v0 = FALSE`) |
| Hypervisor vendor string | `CPUID.40000000h` leaf returns "VMwareVMware"/"VBoxVBoxVBox"/"KVMKVMKVM" | Same as above — hide via hypervisor config or hook the instruction under emulation |
| Driver/device enumeration | VBoxMouse, VBoxGuest, vmci device files | Rename devices, or run inside a VM configured to hide guest-additions artifacts |
| Disk/BIOS strings | SMBIOS vendor field ("innotek GmbH", "VMware, Inc.") | Patch SMBIOS tables in the hypervisor config where supported |
| Timing anomalies (`rdtsc` around `cpuid`) | VM-exit overhead makes privileged instructions measurably slower | Best defeated with real hardware or nested virtualization support; otherwise patch the timing check itself |

### 4.4 Stripped binaries, obfuscated control flow & custom crypto

- **Stripped symbols** — Diff against a known-open-source library version (BinDiff/Diaphora) to recover names. Look for recognizable idioms — libc's `strcpy` loop shape, glibc malloc chunk headers — to re-identify functions FLIRT signatures missed.
- **Opaque predicates** — Conditions that always evaluate the same way (e.g. `(x*x) % 2 == (x%2)`) inserted to inflate the CFG. Identify by symbolic execution — if angr proves a branch condition is a tautology, collapse it and re-read the simplified graph.
- **Control-flow flattening** — All blocks dispatched from one big `switch` on a "state" variable, destroying natural loop/if structure. Recover by tracing state-variable writes to rebuild the real edge list, then rewrite as a normal CFG (Ghidra script or manual notes).
- **Custom encryption** — Don't guess — instrument. Break right after the routine runs, dump input/output pairs, and brute-force small parameter spaces (single-byte XOR, small keys) before attempting full cryptanalysis.

> **Working strategy.** When structure is deliberately hidden, prefer **dynamic** ground-truth over static guessing: dump memory at the moment of computation, log every call into the suspect routine with Frida, and only then reconstruct the algorithm — reversing from observed input/output pairs is faster than reading obfuscated IR.

---

## 5. Automation, Symbolic Execution & Auto-Flag Scripts

### 5.1 Z3 for mathematical / constraint checks

Use Z3 whenever a binary validates input via arithmetic constraints (linear systems, bit-tricks, hash-like mixing) rather than a lookup table — model each byte as a symbolic bitvector and let the SMT solver invert the relationship.

```python
from z3 import *

FLAG_LEN = 20
s = Solver()
flag = [BitVec(f'c{i}', 8) for i in range(FLAG_LEN)]

# Constrain to printable ASCII
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# Known prefix/suffix cuts the search space drastically
s.add(flag[0] == ord('f'), flag[1] == ord('l'), flag[2] == ord('a'), flag[3] == ord('g'))

# Reimplement the binary's check function symbolically, e.g. a rolling XOR/mix:
acc = BitVecVal(0, 32)
for i, c in enumerate(flag):
    acc = (acc ^ ZeroExt(24, c)) * 0x1000193  # FNV-ish mixing, mirror the real routine exactly
s.add(acc == 0xDEADBEEF)   # the target value pulled from .rodata / the comparison

if s.check() == sat:
    m = s.model()
    result = bytes([m[c].as_long() for c in flag])
    print(result)
```

> **Where Z3 wins.** Linear/affine mixing functions, bit-rotation ciphers, sudoku/graph-coloring style validators, and any check expressible as "these bytes must satisfy this equation" — Z3 solves in milliseconds what brute force would take years on.

### 5.2 pwntools for RE automation

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('./target')
p = process('./target')          # or: p = gdb.debug('./target', gdbscript='b *main+0x40\nc')

# brute-force one byte at a time against an oracle that leaks timing/output
known = b''
for pos in range(20):
    for guess in range(0x20, 0x7f):
        p = process('./target')
        p.sendline(known + bytes([guess]))
        out = p.recvall(timeout=0.5)
        p.close()
        if b'Correct so far' in out:
            known += bytes([guess])
            log.info(known)
            break

# pattern-based offset finding (buffer/format-string layout recon)
payload = cyclic(200)
p = process('./target'); p.sendline(payload); p.wait()
core = p.corefile
offset = cyclic_find(core.read(core.rsp, 4))
```

### 5.3 Frida dynamic instrumentation

```javascript
// frida -f ./target -l hook.js --no-pause
Interceptor.attach(Module.getExportByName(null, 'strcmp'), {
  onEnter(args) {
    const a = args[0].readCString();
    const b = args[1].readCString();
    console.log(`strcmp("${a}", "${b}")`);
  },
  onLeave(retval) { retval.replace(0); }   // force "always equal" past the check
});

// Bypass ptrace-based anti-debug at the syscall boundary
Interceptor.attach(Module.getExportByName(null, 'ptrace'), {
  onLeave(retval) { retval.replace(0); }
});

// Scan process memory for a flag pattern once decrypted in RAM
Process.enumerateRanges('r--').forEach(range => {
  Memory.scan(range.base, range.size, '66 6c 61 67 7b', {  // "flag{"
    onMatch(addr) { console.log('hit @', addr, addr.readCString()); }
  });
});
```

### 5.4 angr symbolic execution

```python
import angr, claripy

proj = angr.Project('./target', auto_load_libs=False)

flag_len = 20
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

state = proj.factory.full_init_state(
    args=['./target'],
    stdin=flag,
)

# constrain to printable ASCII so the solver stays in a sane search space
for c in flag_chars:
    state.solver.add(c >= 0x20, c <= 0x7e)

simgr = proj.factory.simulation_manager(state)

# hook away expensive/irrelevant calls to avoid path explosion
proj.hook_symbol('sleep', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

simgr.explore(find=0x4012ab, avoid=0x4012f0)   # "Correct!" addr vs "Wrong!" addr

if simgr.found:
    found = simgr.found[0]
    print(found.posix.dumps(0))   # the input that reaches the success path
```

**Which tool to reach for:**

| Tool | Pick when… |
|---|---|
| Z3 (direct) | You've already extracted the exact math/logic and just need to invert it |
| angr | You want the binary itself explored — unknown/complex control flow, don't want to hand-derive the formula |
| Frida | The target must run for real (network checks, JIT, licensing servers) and you need to observe or alter live state |
| pwntools | Gluing everything together — process control, I/O automation, brute-force orchestration, exploit delivery |

---

## 6. Patching & Binary Modification

### 6.1 Instruction modification mechanics

x86/x64:

| Goal | Bytes | Notes |
|---|---|---|
| NOP out one byte | `90` | Pad any single-byte-opcode slot; for multi-byte instructions, NOP the whole instruction length or you'll corrupt the next opcode |
| Unconditional jump | `EB xx` (short) / `E9 xx xx xx xx` (near) | Relative displacement — recompute if inserting into a different location than the original branch |
| Flip JNZ → JZ | `75 → 74` | Short-form conditional jumps are single-byte opcodes; near-form (`0F 85` ↔ `0F 84`) needs both bytes swapped |
| Flip JE → JMP (force branch) | `74 xx → EB xx` | Same displacement byte, just swap the opcode — cleanest way to force a "success" path unconditionally |
| Force a comparison result | Patch operand of the preceding `cmp`, e.g. `cmp eax, 5` → `cmp eax, eax` | Makes the comparison always-equal without touching branch logic at all — often less noticeable to integrity checks |
| Return true unconditionally | `B8 01 00 00 00 C3` (mov eax,1; ret) | Overwrite an entire function prologue when you don't care about its side effects |

ARM(64):

| Goal | Notes |
|---|---|
| NOP | `1F 20 03 D5` (AArch64) — instructions are fixed 4-byte width, no partial-NOP concept |
| Flip B.EQ → B.NE | Condition code is the low 4 bits of the branch encoding — flip bit 0 of the condition field (EQ=0000 ↔ NE=0001) |
| Force branch | Replace conditional `B.cond` with unconditional `B` at the same offset |

> **Watch for integrity checks.** Self-hashing binaries (CRC over `.text`) will detect naive patches. Either patch the hash constant to match, patch the comparison after the hash check instead of before it, or perform the bypass purely in the debugger (register/memory patch) rather than on disk.

**In-debugger vs on-disk patching**
- Prototype every patch **in the debugger first** (x64dbg/GDB) — reversible, instant to test, no risk of corrupting the file
- Only write to disk once the debugger session confirms the exact byte sequence produces the desired behavior
- Keep an unpatched backup — `cp target target.orig` — before any on-disk edit

### 6.2 Exporting patched binaries

| Tool | How |
|---|---|
| Ghidra | `File → Export Program → Original File` after using the built-in patch instruction / edit bytes actions — Ghidra writes changes back into a byte-accurate copy of the original container |
| IDA Pro | `Edit → Patch Program → Apply patches to input file`, or `Edit → Patch Program → Assemble` per-instruction, then apply. IDA tracks a patch diff list you can review before committing |
| x64dbg | Right-click the patched region → `Patches` panel → `Patch File`, which writes the in-memory edits directly to a new copy of the on-disk executable |

```bash
# verify a patch didn't break the loader
chmod +x patched_target
file patched_target                 # still a valid ELF/PE?
./patched_target < test_input        # confirm it still runs to completion
diff <(xxd target.orig) <(xxd patched_target) | head    # sanity-check only intended bytes changed
```

---

*Reverse Engineering Fieldbook — reference compiled for CTF and binary-analysis work. Verify every technique against the target's actual platform/version before relying on it live.*
