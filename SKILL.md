---
name: x86-cpp-reversing
description: Reverse-engineer 32-bit little-endian x86 (IA-32) binaries and disassembly compiled from C++ -- recover class layouts, vtables, virtual dispatch, RTTI/inheritance hierarchies, and demangled symbol names from ELF or PE binaries. Combines radare2/r2pipe, LIEF, GDB, WinDbg, and binutils (objdump/readelf/nm/c++filt) so analysis stays in structured/JSON form and decompiled-level abstraction rather than raw token-heavy asm dumps. Use this whenever the user shares an x86 binary, .exe/.o/.elf/.so file, a disassembly dump, or asks to analyze, reverse engineer, or decompile a compiled C++ program, recover a class hierarchy or vtable, demangle C++ symbols, identify virtual function dispatch, or explain what a 32-bit binary does.
---

# x86 C++ Reverse Engineering

## Overview

Reverse-engineers 32-bit little-endian x86 (IA-32) binaries compiled from C++. Front-loads mechanical ABI metadata extraction (vtable layouts, RTTI structures, base-class graphs, and symbol demangling) into structured JSON rather than burning context on raw assembly dumps. Degrades gracefully from automated tooling (`recon.py`, LIEF, radare2, OOAnalyzer) to standard binutils (`objdump`, `readelf`, `nm`, `c++filt`) and debuggers (`gdb`, `windbg`).

## When to Use

- Analyzing 32-bit x86 ELF (`.so`, executables) or PE (`.exe`, `.dll`) binaries.
- Recovering C++ class hierarchies, member layouts, and virtual function tables.
- Identifying and resolving dynamic virtual call sites (`call [eax + slot]`).
- Reconstructing custom file-format loaders or flat procedural data tables.
- Mapping resource indices to code call sites (resource-binding recovery).
- Deciphering obfuscated assembly or anti-debugging mechanisms.

**When NOT to use:**
- 64-bit binaries (x86-64 / AMD64) — 4-byte pointer assumptions and ABI headers do not apply.
- Binaries in non-native languages (e.g. .NET/C#, Java bytecode, Python bytecode).
- Pure assembly without C++ abstractions or data structures where generic triage suffices.

---

## Core Non-Negotiables (Defensive Engineering)

1. **Surface Assumptions Early:** State bitness, endianness, and suspected ABI explicitly before doing deep disassembly. Confirming `ELFCLASS32` or `PE32` little-endian avoids chasing phantom offsets.
2. **Process Over Prose:** Follow the phased workflow with concrete verification gates. Do not generate speculative essays on what code "might" do without instruction-level proof.
3. **Scope Discipline:** Touch and disassemble only the functions and structures requested. Do not dump or decompile adjacent, unrelated subsystems.
4. **Verification is Non-Negotiable:** "Seems right" is never sufficient. Every recovered class, vtable slot, and member displacement must link to an exact opcode, relocation, or memory address.
5. **Structured Data Over Raw Asm:** Prefer structured output (`recon.py` JSON, `r2` JSON, backward slices) over raw text dumps. Raw `objdump -d` of 500-line functions burns context and buries key instructions.

---

## Anti-Rationalization Table

| Common Rationalization / Excuse | Hard Reality & Required Action |
|---|---|
| *"The binary is stripped, so classes and vtables cannot be recovered."* | **False.** Stripped binaries preserve vptr stores (`mov [esi], offset vtable`) in constructors and mangled `.?AV...` ASCII strings in `.rdata`. Follow the stripped `.rdata` recovery algorithm in `references/msvc-abi.md` or data-table attribution in `references/tool-recipes.md` §13. |
| *"This binary was run/analyzed on Linux, so it must use the Itanium ABI."* | **Stop.** Check file format and symbol markers (`_Z` vs `?`). PE binaries running under Wine or analyzed on Linux strictly follow the MSVC ABI (`__thiscall`, `CompleteObjectLocator`). Never apply Itanium vtable offsets to MSVC binaries. |
| *"I can just read pointer values directly out of `.rodata` / `.data` bytes."* | **False for PIE/DSO targets.** Position-independent binaries use dynamic relocations for vtables and RTTI pointers. Raw bytes are often placeholder zeroes. You MUST check the relocation table (`readelf -r` or LIEF). |
| *"I'll dump the whole 500-line function disassembly into context."* | **Context poison.** Use targeted disassembly (`objdump -d --start-address=...`), radare2 JSON (`pdfj`), or backward slicing (`scripts/backward_slice.py`). Focus only on vptr assignments, loop strides, and call setups. |
| *"Static xref sweeps returned 0 hits, so this code or table is dead."* | **Premature.** Check for indirect dispatch via function-pointer tables, `vbtable` adjustments, dynamic registration, or thin SEH wrappers before concluding code is unreferenced. |
| *"The decompiled output looks like a flat C struct, so there is no inheritance."* | **Check calling conventions.** Compilers inline constructors. Look for `thiscall` (`ecx` loaded prior to call), `returnsSelf` (`eax == ecx`), and nested subobject offsets (`lea ecx, [esi + disp]`). |
| *"I don't need to verify against two sources; one textbook/blog said so."* | **Verify primary sources.** Disassembly transcriptions in literature frequently contain errata (e.g. missing `cdOffset` fields or wrong vptr targets). Corroborate against verified schemas in `references/msvc-abi.md`. |

---

## Phased Workflow

```
[Artifact] ──→ Phase 1: Triage ──→ Phase 2: ABI Split ──→ Phase 3: Structural Recon
                                                                 │
[Verified Model] ◄── Phase 6: Verify ◄── Phase 5: Functions ◄── Phase 4: Class Model
```

### Phase 1: Triage & Format Gate
**Gate:** Confirm 32-bit (`ELFCLASS32` or `PE32`) and little-endian (`e_data: 2's complement, little endian`).
- Run `file <binary>` and `readelf -h <binary>`.
- If 64-bit or big-endian, **STOP** — the 4-byte pointer arithmetic throughout this skill will produce invalid offsets.
- **Pivots:**
  - *Flat procedural code (no vtables)?* $\rightarrow$ `references/tool-recipes.md` §9 (custom loaders) or §13 (data-table field attribution).
  - *Indexed resource binding?* $\rightarrow$ `references/tool-recipes.md` §10.
  - *Obfuscated instructions / desynced disasm?* $\rightarrow$ `references/obfuscation.md`.
  - *Debugger detects attachment / crashes?* $\rightarrow$ `references/anti-debugging.md`.

### Phase 2: ABI Disambiguation
- **Itanium C++ ABI (`_Z`-prefixed symbols):** GCC / Clang (typically ELF). `this` passed on stack; vtable header contains offset-to-top and direct RTTI pointer. Pivot to `references/itanium-abi.md`.
- **MSVC ABI (`?`-prefixed symbols or `.?AV` strings):** Visual C++ (typically PE). `__thiscall` convention (`this` in ECX); vtable slot 0 has COL pointer at offset `-4`. Pivot to `references/msvc-abi.md`.

### Phase 3: Structural Reconnaissance
- **ELF/Itanium Binaries:**
  ```bash
  python3 scripts/recon.py <binary>
  ```
  Extracts binfo, demangled symbols, and walks every `_ZTV` vtable and RTTI descriptor into structured JSON.
- **MSVC/PE Binaries:**
  - If OOAnalyzer is installed: `ooanalyzer --json=out.json <binary.exe>` (`references/tool-recipes.md` §12).
  - Manual/Scripted: Scan `.rdata` for `.?AV` strings $\rightarrow$ trace COL pointers $\rightarrow$ find slot 0 at `col_ptr + 4` (`references/msvc-abi.md`).
- **Fallback (binutils only):** `nm -C`, `objdump -s -j .data.rel.ro`, and `references/tool-recipes.md` §3–4.

### Phase 4: Class Model Reconstruction
- Correlate vtables to class names via RTTI descriptors.
- Map base-class inheritance graphs:
  - *Itanium:* Walk `__si_class_type_info` and `__vmi_class_type_info` base arrays.
  - *MSVC:* Traverse `ClassHierarchyDescriptor` $\rightarrow$ `BaseClassArray` $\rightarrow$ `BaseClassDescriptor` (evaluate `_PMD` member displacements).
- Verify primary vftables using the self-referencing circular invariant (`rTTISelfRef`).

### Phase 5: Targeted Function Analysis
- Disassemble constructors: confirm which vtable belongs to which class via `mov [reg], offset vtable` and note base ctor ordering.
- Trace virtual call sites: find `call [reg + slot*4]` and match against the resolved vtable slot addresses.
- Analyze struct fields: use memory displacements (`[esi + disp]`) and loop strides to map struct members (`references/tool-recipes.md` §13).

### Phase 6: Dynamic Verification & Slicing (When Stalled)
- GDB dynamic tracing for ELF/Linux (`references/tool-recipes.md` §7).
- WinDbg dynamic tracing for native PE/Windows (`references/tool-recipes.md` §11).
- Automated register backward slicing via Triton (`scripts/backward_slice.py` / §10.3).

---

## Verification & Hard Exit Criteria

Before declaring the reverse engineering task complete, verify that you have produced concrete evidence satisfying all of the following:

1. **Format Confirmation:** Stated bitness, format, endianness, and ABI classification with supporting triage command output.
2. **Recovered Class / Structure Table:**
   - Class name, size (if determinable), and vftable address.
   - Inheritance relationships (single, multiple, virtual) with exact base offset displacements.
   - Virtual method table mapping: slot index, virtual offset, and target function address/symbol.
3. **Disassembly Ground Truth:**
   - Every claimed vtable or struct field assignment is supported by exact instruction snippets (e.g. `0x00401234: mov dword ptr [esi], 0x00408040`).
4. **Dual Output Deliverables:**
   - **Markdown Report:** Synthesized architecture, class hierarchy, and behavior explanation.
   - **Annotated Artifact:** Pseudocode or assembly listing saved alongside the report with inline comments tying machine instructions back to the recovered model.

---

## Reference Map

| File | Read this when... |
|---|---|
| `references/itanium-abi.md` | Working with `_Z`-mangled (GCC/Clang, ELF) binaries -- vtable layout, RTTI structures, multiple inheritance thunks, cross-DSO relocations. |
| `references/msvc-abi.md` | Working with `?`-mangled (MSVC, PE) binaries -- `__thiscall` convention, complete RTTI struct definitions (COL, CHD, BCD, `_PMD`), circular validation invariant (`rTTISelfRef`), virtual inheritance/`vbtable` mechanics, and stripped `.rdata` scanning algorithm. |
| `references/tool-recipes.md` | Exact commands for: triage, demangling, radare2/r2pipe JSON queries, GDB dynamic recipes, custom file-format loaders (§9), resource-binding recovery (§10), WinDbg dynamic analysis (§11), OOAnalyzer automated class recovery (§12), data-table field attribution and struct recovery (§13), and programmatic binary analysis (§14). |
| `references/obfuscation.md` | Recognizing deliberate obfuscation: junk code, opaque predicates, calls that never return, desynced linear disassembly, and xref-evasion patterns. |
| `references/anti-debugging.md` | Debugger attached behaves differently than standalone: PEB `BeingDebugged` checks, kernel queries, trap flags, and evasion techniques. |
| `scripts/recon.py` | Automated LIEF-based static triage + Itanium ABI vtable/RTTI recovery script. |
| `scripts/backward_slice.py` | Automated Triton-based register backward slicing tool (requires dedicated `.venv`). |
