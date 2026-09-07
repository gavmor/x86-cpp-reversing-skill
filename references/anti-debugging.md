# Recognizing anti-debugging / anti-reversing techniques

*Objective: Robustness · Target: Assembly Code* (see `AGENTS.md`'s
design-rationale section for what these mean here.)

Distinct from `references/obfuscation.md`: obfuscation hides what code
*means*; anti-debugging detects *that you're analyzing it at all* and
changes behavior in response (crash, silently misbehave, or just refuse to
proceed). Both matter for the same reason -- dynamic-capture recipes in
tool-recipes.md sections 7, 10.6, and 11 all assume you can attach a
debugger without the target noticing or caring. If a binary behaves
differently under GDB/WinDbg/tracer than it does standalone, check here
before assuming your instrumentation is broken.

Everything below is drawn from Eilam, *Reversing: Secrets of Reverse
Engineering* (Wiley, 2005), ch. 10, "Antireversing Techniques."

## Named techniques worth recognizing

**`IsDebuggerPresent` and its PEB-level reimplementation.** The API itself
is trivially bypassed (hook it, or patch the call site), which is exactly
why real anti-debug code often reimplements the check directly against the
Process Environment Block instead of calling the API at all:

```
mov  eax, fs:[0x18]     ; TEB (Thread Environment Block)
mov  eax, [eax + 0x30]  ; PEB (Process Environment Block)
cmp  byte ptr [eax + 0x2], 0  ; PEB.BeingDebugged flag
```

If you see a raw `fs:[0x18]`/`fs:[0x30]`-style TEB/PEB walk with no call to
a named debug-check API at all, this is why -- there's nothing to hook,
since it never calls out to anything.

**Kernel-debugger detection.** `ZwQuerySystemInformation` with the
`SystemKernelDebuggerInformation` information class fills in a
`SYSTEM_KERNEL_DEBUGGER_INFORMATION` struct with `DebuggerEnabled`/
`DebuggerNotPresent` fields -- detects a kernel debugger (WinDbg/KD attached
at the kernel level, tool-recipes.md section 11), not just a user-mode one.

**SoftICE-specific detection** (still worth recognizing even though SoftICE
itself is long dead -- the patterns get reused against other debuggers):
opening `\\.\SIWVID` (a device file SoftICE exposes) to check whether it's
loaded, or hijacking `int 1` (SoftICE's own single-step handler) and
checking whether the resulting exception code is something other than
`STATUS_ACCESS_VIOLATION` -- a live debugger's own handler behaves
differently than the OS default one would.

**Trap-flag detection (generic, works against any debugger).** Setting the
trap flag manually and checking whether a single-step exception actually
fires:

```
pushfd
or   dword ptr [esp], 0x100   ; set TF (trap flag)
popfd
; wrapped in a __try/__except (SEH, references/tool-recipes.md section 9
; discusses SEH wrappers in the file-format context -- same mechanism here)
```

No debugger attached -> the single-step exception fires normally and gets
caught. A debugger attached often intercepts the trap silently, so the
expected exception never arrives -- that absence is the detection signal.

**Code checksumming at runtime.** Computing a checksum/hash over the
function's own code bytes and comparing against an expected value --
catches both a software breakpoint (`0xCC` byte patched into the code) and
any other in-memory patch, not just a debugger's presence.

**Anti-debug techniques from a real commercial packer (Safengine),
confirmed bitness-agnostic by the source.** Choi, Chang & Park (*Sensors*,
2024, §3.9/§5.4, building `UnSafengine64`) document these directly against
Safengine 2.4.0 -- their own text notes "the single step is an anti-
reversing technique that can be used in both 32-bit and 64-bit Windows,"
and the rest read the same way (none depend on 64-bit-specific APIs):

- **`NtSetInformationThread` with `ThreadInformationClass=0x11`
  (`ThreadHideFromDebugger`)** silently detaches an attached debugger --
  the target keeps running with no crash or visible error, so "the
  debugger just stopped working" is itself a signal to check for this.
- **Removing write access from a code section** specifically blocks
  `0xCC` software-breakpoint patching (a debugger can't write the
  breakpoint byte in) without touching execution -- a section that's
  unexpectedly read/execute-only where you'd expect read/write/execute is
  worth treating as deliberate.
- **DR0-DR3 checksummed into TLS, monitored continuously by dedicated
  "watchdog" threads** (eight of them, in Safengine's case) -- rather than
  a one-shot check, this catches a hardware breakpoint set *after* the
  program already passed an initial check.
- **`\\.\NTICE` / `SYSERBOOT` driver-presence checks** extend the
  SoftICE-detection pattern above to a differently-named but same-shaped
  check (SoftICE/Syser driver device-file probing).
- **Patching `DbgBreakPoint()`/`DbgUserBreakPoint()`'s first byte to
  `0xEB`** (an unconditional short jump) neuters the OS's own built-in
  breakpoint-trigger functions at their source, before a debugger ever
  gets a chance to intercept them.
- **VM detection via the system-manufacturer registry string** (checking
  for literal substrings like `"VMware, Inc."` or `"VBOX"`) -- simple,
  and worth checking for before assuming a more exotic timing- or
  instruction-based VM-detection technique is in play.

## Debugging past these techniques instead of just recognizing them

Everything above is about *recognizing* a check. When the target actually
uses one of these against you -- section 7/11's GDB/WinDbg recipes will
trip it -- **HyperDbg** (Karvandi et al., arXiv:2207.05676, 2022) is a
real, open-source hypervisor-assisted debugger built specifically to avoid
triggering the checks this file documents, not just to recognize them:

- **No `0xCC` breakpoint patches, no debug registers.** HyperDbg sets
  breakpoints via EPT (Extended Page Table) hooks at the hypervisor level
  instead of patching code or touching DR0-7 -- so the code-checksumming
  and DR-based checks above have nothing to detect. It also emulates
  unlimited "hardware watchpoints" via EPT read/write trapping, without
  the real 4-register limit.
- **RDTSC/RDTSCP timing-detection is specifically countered**, not just
  ignored: HyperDbg intercepts these instructions on VM-exit and emulates
  a plausible non-virtualized timing value (calibrated via `!measure`/
  `!measure default` before enabling stealth) rather than returning the
  real, debugger-slowed timestamp counter.
- **Confirmed on 32-bit PE targets, not just 64-bit malware.** HyperDbg's
  own evaluation (Table 2) includes six 32-bit packers/protectors --
  MEW11, PEcompact, PELock, Petite, TeLock, YodaCrypter -- successfully
  attached and debugged where other tested debuggers were detected or
  errored.
- **Enable stealth mode with `!hide`** once attached; `t` (step-in), `p`
  (step-over), and `i` (an MTF-based instrumentation step guaranteeing
  exactly one instruction executes, even under interrupt storms) are the
  real single-step primitives. `!dr` lets you inspect/disable breakpoints
  the target itself set, useful against the trap-flag/DR-based detection
  above.
- **Named limitation, not a claim of invisibility**: HyperDbg's own paper
  states plainly it doesn't claim full invisibility, and can still be
  detected in already-virtualized environments or via PatchGuard/Driver
  Signature Enforcement absence-checks (mitigated with nested
  virtualization and a valid driver signature, but not eliminated).

Reach for this when a target's anti-debug checks are specifically what's
blocking sections 7/11's more conventional debuggers, not as a default
first choice.

## Disassembler-algorithm-specific evasion

Different tools use different disassembly *algorithms*, and code can be
built to defeat one without defeating the others -- worth knowing which
category your tool falls into:

- **Recursive traversal** (OllyDbg, IDA Pro, and this skill's own
  `objdump`/`r2` recipes when they follow control flow rather than reading
  linearly): follows actual jump/call targets, so it isn't fooled by a
  single junk byte sitting in a never-taken fallthrough path.
- **Linear sweep** (older tools, some debuggers' disassembly views):
  decodes byte-by-byte in address order regardless of control flow, so a
  single deliberately-placed junk byte in an unreachable path desyncs
  everything decoded after it.

Worked example: `jmp After` / `_emit 0x0f` / `After: ...` -- a recursive
traversal tool follows the jump and correctly decodes `After:` onward,
never touching the `0x0f` byte. A linear-sweep tool decodes the `0x0f` byte
as the start of the next instruction regardless, desyncing everything after
it. Same bytes, different tool, different (and for the linear-sweep case,
wrong) result -- if two tools disagree about a function's disassembly right
after a jump, check which algorithm each one uses before assuming either
is buggy.
