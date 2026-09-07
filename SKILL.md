---
name: x86-cpp-reversing
description: Reverse-engineer 32-bit little-endian x86 (IA-32) binaries and disassembly compiled from C++ -- recover class layouts, vtables, virtual dispatch, RTTI/inheritance hierarchies, and demangled symbol names from ELF or PE binaries. Combines radare2/r2pipe, LIEF, GDB, and binutils (objdump/readelf/nm/c++filt) so analysis stays in structured/JSON form and decompiled-level abstraction rather than raw token-heavy asm dumps. Use this whenever the user shares an x86 binary, .exe/.o/.elf/.so file, a disassembly or objdump dump, or asks to analyze, reverse engineer, or decompile a compiled C++ program, recover a class hierarchy or vtable, demangle C++ symbols, identify virtual function dispatch, or explain what a 32-bit binary does -- even if they don't say "reverse engineering" explicitly (e.g. "what does this .exe do", "can you figure out the class structure from this binary", "why does this crash inside a virtual call").
---

# x86 C++ Reverse Engineering

## Why the approach here looks the way it does

For an LLM doing binary analysis, the real bottleneck is context, not
compute: a raw `objdump -d` of anything nontrivial burns tokens fast and
buries the two or three instructions that actually matter. So the order of
preference throughout this skill is: **structured data > prose text**, and
**demangled/decompiled abstraction > raw assembly**. `scripts/recon.py`
exists specifically to front-load the mechanical, well-specified parts (ABI
struct layouts, relocation resolution, symbol demangling) into one JSON blob
so you spend your reasoning on the parts that actually require judgment --
what the recovered classes are *for*, how they relate to the program's
behavior, what looks suspicious.

That said, this skill degrades gracefully. If the fancy tools (radare2,
LIEF, r2pipe) aren't installed and can't be installed in the current
environment, binutils (`objdump`/`readelf`/`nm`/`c++filt`) and GDB are
almost always present on any Linux box and are enough to do this by hand --
`references/tool-recipes.md` covers both paths.

## Workflow

**1. Identify the artifact and triage it.**
Figure out whether you have a binary file, an object file, or already-pasted
disassembly/objdump text. Run `file` and `readelf -h` (or check a PE header)
to confirm the binary is actually **32-bit** and **little-endian** x86
before trusting anything else -- the struct offsets everywhere in this skill
assume 4-byte words. If it's 64-bit or a different architecture, stop and
say so rather than silently misapplying 32-bit offsets.

**1b. No vtables? It may be flat procedural C, not missing C++.** Old game
engines especially often implement a subsystem (audio, save format, level
data) as a static-globals C library with no classes at all -- `recon.py`
correctly finding zero vtables is a valid result, not a failure. If the task
is really "recover a custom file format this binary loads," pivot to
`references/tool-recipes.md` section 9 (tracing from the `open`/`read` call
site to the real validator, which is often hidden one call behind a thin
SEH/error-string wrapper).

**1c. Know a data file has N indexed entries but not which code uses entry
K?** That's resource-binding recovery, not class recovery or file-format
recovery -- a distinct technique (xref-sweep outward from the
resource-access API, not from a vtable or a container-open call). Pivot to
`references/tool-recipes.md` section 10.

**1d. Disassembly looks nonsensical, or a function seems to fix up the stack
right after its own entry point with no matching call?** Before assuming a
disassembler bug or an unusual compiler, check whether the binary is
deliberately obfuscated -- see `references/obfuscation.md` for named,
recognizable patterns (a `call` that never returns to its next instruction,
opaque predicates, junk code built to desync a linear disassembler,
clusters of instructions compilers rarely emit). Recognizing the pattern is
usually enough to stop wasting time trying to make normal sense of code
that was never meant to make sense when read linearly.

**1e. A debugger attached in section 7/10.6/11 behaves differently than the
binary does standalone (crashes, takes a different path, or the target
just exits)?** The binary may be detecting the debugger, not misbehaving --
see `references/anti-debugging.md` for named techniques (PEB `BeingDebugged`
checks, kernel-debugger queries, trap-flag detection, code checksumming)
before spending time debugging your own tooling.

**2. Tell ELF/Itanium apart from PE/MSVC -- the ABI is genuinely different.**
Symbols starting with `_Z` (demangle with `c++filt`) mean Itanium ABI,
almost always an ELF binary from GCC/Clang. Symbols starting with `?` mean
MSVC's ABI, almost always a PE binary. Calling convention, vtable layout,
name mangling, and RTTI structures differ between the two -- read
`references/itanium-abi.md` or `references/msvc-abi.md` accordingly rather
than assuming one applies to the other.

**3. Run the structured recon script (ELF/Itanium binaries).**
```bash
python3 <skill_dir>/scripts/recon.py <binary>
```
This gives you binfo (confirming step 1), every symbol demangled, and --
for ELF binaries -- every `_ZTV*` vtable already walked: offset-to-top,
resolved typeinfo with the full base-class chain (including multiple/virtual
inheritance), and each virtual function slot resolved to a demangled name
where possible. Cross-DSO pointers (e.g. a typeinfo structure whose "kind"
vtable lives in libstdc++) are resolved through the relocation table rather
than misread from placeholder bytes -- see `references/itanium-abi.md` if
you need to understand why a raw pointer field doesn't look like a real
address.

This script does **not** attempt MSVC/PE vtable walking automatically (the
layout is different enough, and there's no way to validate it against a
real MSVC-built binary in most environments, that guessing would produce
confidently wrong answers instead of no answer). For PE binaries, use the
manual recipe in `references/msvc-abi.md` and `references/tool-recipes.md`.

If `recon.py` can't run at all (no LIEF installed and installing it isn't an
option), go straight to the manual recipes in `references/tool-recipes.md`
section 3-4 -- slower, but it gets you the same information.

**4. Reconstruct the class model from what recon.py (or the manual recipe) found.**
Match vtable symbols to class names, use the typeinfo base-class chain to
build the inheritance graph, and note anything that looks like multiple or
virtual inheritance (multiple `marker_or_secondary_header` segments in one
vtable's slots, or `non-virtual thunk to`/`virtual thunk to` in demangled
names). A `marker_or_secondary_header` entry isn't a bug in the output --
it's the ABI-mandated header (offset-to-top + typeinfo pointer) for the next
sub-vtable segment; `references/itanium-abi.md` walks through exactly this
with a worked multiple-inheritance example.

**5. Read specific functions when you need actual logic, not just structure.**
Vtables and RTTI tell you the *shape* of the class hierarchy; you still need
to read constructors (to confirm which vtable belongs to which class and in
what order bases get initialized) and any function whose behavior the user
actually asked about. Use `objdump -d -M intel --disassemble=<name>` or
`r2`'s `pdf`/`pdfj` (see `references/tool-recipes.md` section 5-6) rather
than dumping the whole `.text` section.

**6. Go dynamic when static analysis stalls.**
Stripped binaries, obfuscated control flow, or just wanting to *confirm*
rather than infer a hypothesis are all good reasons to reach for GDB:
breaking at a suspected constructor and watching the store to the object's
first field will show you the vtable pointer(s) actually being written,
including the base-then-derived double-write that's a dead giveaway of
inheritance. See `references/tool-recipes.md` section 7.

## Output format

Produce **both** of the following unless the user clearly only wants one:

1. **A markdown report** covering, at minimum:
   - File info: format, architecture, bitness/endianness, PIE/stripped status
   - Recovered class model: table or list of classes, their vtables, and
     inheritance relationships (with virtual/multiple inheritance called out
     explicitly when present)
   - Key functions: what they do, in terms of the recovered class model, not
     just "this function calls that function"
   - Anything notable or unusual for a reverse engineer to flag (unexpected
     stripping, packed sections, obfuscation, etc.)
2. **An annotated artifact** saved alongside the input: either an annotated
   disassembly listing or a C-like pseudocode reconstruction, with inline
   comments tying instructions back to the class model (e.g. "-- vptr store:
   Dog's vtable, confirms Dog inherits Animal" next to the relevant `mov`).

Keep the report's structural claims traceable to specific evidence (an
address, a symbol name, a relocation) rather than stated as bare assertions
-- that's what makes the report checkable against the binary later.

## Reference files

| File | Read this when... |
|---|---|
| `references/itanium-abi.md` | Working with `_Z`-mangled (GCC/Clang, usually ELF) binaries -- vtable layout, RTTI structure decoding, multiple inheritance thunks, the abstract-class null-slot gotcha, cross-DSO relocation handling. |
| `references/msvc-abi.md` | Working with `?`-mangled (MSVC, PE) binaries -- thiscall convention, vftable/Complete-Object-Locator layout, manual recovery recipe (no automated script backs this ABI). |
| `references/tool-recipes.md` | You need the exact command for a specific job -- triage, symbol dumping, per-function disassembly, radare2/r2pipe JSON queries, GDB dynamic-analysis recipes, compiling your own reference binary for comparison, reversing a custom file-format loader (section 9), mapping a data file's indexed entries to the code that uses them (section 10), or WinDbg/DbgEng dynamic analysis for a native Windows PE binary GDB can't attach to (section 11). |
| `references/obfuscation.md` | Disassembly looks deliberately nonsensical (junk code, calls that never return, stack fixups with no matching call), or a resource/string you're sure exists has zero xrefs -- recognizing common obfuscation and xref-evasion patterns rather than mistaking them for disassembler or compiler bugs. |
| `references/anti-debugging.md` | A debugger behaves differently attached than the binary does standalone -- recognizing named anti-debugging techniques (PEB checks, kernel-debugger queries, trap-flag detection, disassembler-algorithm-specific evasion) before assuming your tooling is broken. |
| `scripts/recon.py` | Run directly (not just read) against ELF binaries for automated binfo + demangled symbols + full vtable/RTTI recovery. `python3 scripts/recon.py <binary>` with no args prints usage. |
| `scripts/backward_slice.py` | Run directly against a 32-bit ELF or PE binary to automate backward-slicing a register at a given address (tool-recipes.md section 10.3) instead of tracing it by hand. Requires a dedicated venv (`pip install triton-library lief`) -- see the script's docstring for why. |
