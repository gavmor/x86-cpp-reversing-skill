# Recognizing anti-debugging / anti-reversing techniques

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
