# Tool recipes

*Objective: Performance (primary), Robustness · Target: spans the full
continuum, Raw Bytes (section 9, 13) through Assembly Code (most sections)
to Decompiled Code (section 14) · Method: mostly tool-invocation/Agent-Based,
section 12 (OOAnalyzer) most explicitly so* -- see `AGENTS.md`'s
design-rationale section for what these tags mean.

Concrete commands, grouped by what you're trying to answer. The guiding
principle: prefer structured output (JSON, or `scripts/recon.py`'s already-
demangled/already-classified output) over raw text dumps -- raw `objdump -d`
output on anything but a tiny function burns a lot of context for not much
signal. Reach for binutils text output when you need to read the actual
instructions of a specific function, not as your first move.

## 1. Triage: what am I even looking at?

```bash
file <binary>                        # format, arch, PIE/static, stripped?
readelf -h <binary>                  # ELF header: EI_CLASS (32/64), EI_DATA (endianness), e_machine
readelf -d <binary>                  # dynamic section: linked libs, hints about libstdc++ presence
readelf -S <binary>                  # section layout -- find .rodata/.data.rel.ro for ELF vtables
```

Confirm **32-bit** (`ELFCLASS32` / `PE32` not `PE32+`) and **little-endian**
(`e_data: 2's complement, little endian` -- true for all ELF x86, and PE x86
is always LE) before trusting anything downstream; if it's actually 64-bit
or big-endian, the offsets in `references/itanium-abi.md` (4-byte fields)
don't apply.

## 2. Structured triage + vtable/RTTI recovery

```bash
python3 scripts/recon.py <binary>
```

This is almost always the right first real step for an ELF/Itanium binary --
it gives you binfo, demangled symbols, and (for ELF) every vtable's slots
and typeinfo/base-class chain already resolved, in one JSON blob. Read
`references/itanium-abi.md` alongside it to interpret `marker_or_secondary_header`
entries (multiple inheritance) and the abstract-class null-slot gotcha.

If LIEF isn't installed and you can't `pip install lief`, fall back to the
manual recipes below -- they get you most of the same information slower.

## 3. Symbols and demangling (manual fallback)

```bash
nm -C <binary>                       # demangled symbol table (nm's -C does c++filt for you)
nm -D -C <binary>                    # dynamic symbol table (for stripped/PIE binaries, imports+exports)
echo '_ZN3Dog5speakEv' | c++filt -n  # demangle one symbol by hand
readelf -r <binary>                  # relocations -- CRITICAL for PIE binaries: a typeinfo/vtable
                                      # pointer field with no matching relocation entry has already-
                                      # correct static content; one WITH a relocation is a placeholder,
                                      # and the real target is the relocation's symbol name, not the
                                      # raw bytes at that address (see itanium-abi.md's cross-DSO note)
```

## 4. Finding vtables/typeinfo by hand (no recon.py)

```bash
nm -C <binary> | grep 'vtable for\|typeinfo for'
objdump -s -j .data.rel.ro <binary>  # raw bytes of the section vtables usually live in (PIE/GOT-using binaries)
objdump -s -j .rodata <binary>       # non-PIE binaries often keep vtables here instead
```

Once you have a vtable's address, dump its words and cross-reference each
one against the symbol table (`nm -C | grep <addr>`) or a disassembly
listing to see if it lands inside a function.

## 5. Reading a specific function's disassembly

```bash
objdump -d --no-show-raw-insn -M intel --disassemble=<mangled_or_demangled_name> <binary>
# or, if you only have an address and no symbol:
objdump -d --no-show-raw-insn -M intel --start-address=0x<addr> --stop-address=0x<addr+len> <binary>
```

`-M intel` matters -- default AT&T syntax (`mov %eax, %ebx`) is harder to
cross-check against the ABI docs above, which are written Intel-order
(`mov ebx, eax`). Constructors are the highest-value targets: look for
`mov [reg], offset <vtable+8>` (Itanium) or `mov [ecx], offset <vtable>`
(MSVC) to identify which class's vtable an object is getting stamped with.

## 6. radare2 (when installed) -- structured, JSON-friendly

```bash
r2 -q -c 'aaa; afl~sym.imp,fcn; iSj; izzj' <binary>   # quick function/import/string triage
r2 -q -c 'aaa; is~ZTV' <binary>                       # list vtable symbols
r2 -q -c 'aaa; pdfj @ <func_addr>' <binary>           # one function's disassembly as JSON (pdf = "print disasm function")
```

Append `j` to almost any r2 command for JSON output -- much easier to parse
programmatically than scraping text, and it's the same philosophy
`scripts/recon.py` follows (structured data in, structured data out).
Via `r2pipe` in Python, you get the same commands scriptably:

```python
import r2pipe
r2 = r2pipe.open("<binary>")
r2.cmd("aaa")
funcs = r2.cmdj("aflj")       # function list as parsed JSON
vtabs = r2.cmdj("isj")        # symbols, filter for _ZTV yourself
```

## 7. Dynamic analysis with GDB

Use this when static analysis stalls -- stripped binaries, obfuscated
control flow, or when you need to *confirm* a hypothesis (e.g. "is this
really a virtual call, and what does it resolve to at runtime?").

```bash
gdb -q <binary>
(gdb) break *0x<addr>                # break at raw address
(gdb) break ClassName::MethodName    # break by (demangled) symbol, if present
(gdb) run
(gdb) info registers                 # eax/ecx/etc at the break point
(gdb) x/8xw $eax                     # dump 8 words starting at whatever's in eax (e.g. `this` or a vtable ptr)
(gdb) x/s $eax                       # dump as a C string (useful for typeinfo name fields)
(gdb) watch *(int*)$eax              # break again when that memory changes -- great for catching vptr overwrites during construction
```

If `pwntools` is installed, wrapping this in a short Python script beats
hand-typing GDB commands for anything you'll do more than once or twice --
`pwnlib.gdb.debug()` gives you a scriptable GDB session driven from Python
instead of pasting commands into an interactive prompt.

## 8. Compiling your own reference binary

When you want ground truth to compare a mystery binary against (e.g. "does
single vs. multiple inheritance really produce this exact pattern?"),
compile a tiny equivalent yourself and diff the vtable structure:

```bash
g++ -m32 -g -O0 test.cpp -o test32     # -O0 keeps the vtable/ctor patterns undisguised by optimization
gdb -q ./test32                        # or objdump/recon.py the result
```

`-g` debug info also lets you cross-reference addresses against source lines
directly (`objdump --dwarf=decodedline`), which is often faster than
reasoning from the assembly alone when you control the source.

**If you compile your reference at a higher `-O` level to match an
optimized target, expect functions to vanish or merge, not just get
harder to read.** REFORGE (Koller & Schmidt, §4.2) measured *why*
binary-to-source alignment degrades at higher optimization: inlining and
code motion fragment the debug-info address ranges that anchor a function
to its source, and their paired analysis (same function tracked across
optimization levels via a source-anchored key, not independent samples)
found no robust evidence that surviving functions get harder to match --
the real effect is that ~40% of the function population stops being
independently identifiable at all (inlined into callers, folded, or
eliminated as dead code). Practical takeaway: if your `-O0` and `-O2`
reference builds don't have a 1:1 function correspondence, that's not a
sign your comparison technique is wrong -- some functions genuinely aren't
separate functions anymore, and hunting for a missing one in the optimized
binary is often a waste of time.

When a function does still correspond and you need to confirm two builds
behave the same way, compare what each writes -- to memory, globals, I/O --
not the raw instruction sequence: PEM (Xu et al., ESEC/FSE 2023) defines a
binary's semantics as exactly this distribution of observable writes
because "observable values are hardly altered by code transformations,"
unlike register-level traces, which optimization reshuffles freely.

## 9. Reversing a custom binary file-format loader (no vtables involved)

Not every 32-bit binary worth reversing has a C++ class hierarchy. Old game
engines in particular often implement subsystems (audio, save files, level
data) as **flat procedural C-style libraries** with a static globals block
instead of objects -- there's no vtable to walk, and `recon.py`'s vtable
recovery will (correctly) find nothing. When you need to recover a *custom
container/file format* the binary loads at runtime, the workflow is
different from class recovery:

| Step | Action | Checkpoint (what proves this step actually worked) |
|---|---|---|
| 1 | Find the load call site: grep strings/imports for the filename/extension (`izzj` in r2, or `strings <binary> \| grep -i <ext>`), then `axt`/`nm`/xref-search to find the `open`/`CreateFileA`/`fopen` caller. **If the format has its own magic number/signature, search for *that* constant instead** and cross-reference it -- often lands you closer to the validator directly. | A specific call site address, not just a string hit. |
| 2 | Disassemble that call site's function. If it's mostly an SEH prologue (`mov eax, fs:[0]` / `push -1` / `push <handler>`) plus a switch translating error codes into strings (`"Can't open sound data file"`), **follow every `call` inside it** before concluding there's no real logic. | You've named the callee that does the actual `open`/`read`, not just the wrapper. |
| 3 | Read the real validator's `open()` → `read()` → `cmp` sequence. Every `cmp eax, <literal>` right after a `read()` is a format-spec assertion, not a guess. | You can write down a field's expected value/size from a `cmp` instruction, not from a single sample file. |
| 4 | If there's a loop walking a table, read the increment as the record stride, and confirm it's linear -- not just true for the entries you happened to read: at the loop header, `R = φ(R_out, R_in)`; if `R_in` expands to `R + α` with `α` loop-invariant (Ketterlin & Clauss, 2014, Fig. 3), then `R = R_out + I*α` holds for the *whole* loop. | You have a proof the stride is constant across all N entries, not an eyeballed sample of two or three. |
| 5 | Before trusting any prior doc/commit message's claim about this format ("these values are monotonic, so..."), re-derive it from the validator yourself. | Your conclusion traces to a specific instruction address, not to someone else's write-up. |
| **Exit** | You can state the format's field layout and stride with each claim backed by a specific instruction address. | Not "seems right" -- a `cmp`/increment instruction address per claim. |

```bash
# generalized recipe used above (radare2):
r2 -q -c "aaa; s <wrapper_addr>; pdf" <binary>       # read the wrapper, find the real callee
r2 -q -c "aaa; s <callee_addr>; pdf" <binary>        # read the real validator
# strip ANSI color codes when saving output for repeated grep/sed passes:
r2 -q -c "aaa; s <addr>; pdf" <binary> | sed 's/\x1b\[[0-9;]*m//g' > /tmp/fn.txt
```

*Anti-rationalization*: "The first few entries incremented by 4 bytes, so the stride is 4" is a sample, not step 4's proof -- confirm `α` is loop-invariant before trusting it past the entries you actually read. Shashidhar & Novak's magic-string entry point (searching for prefetch files' own `"SCCA"` signature in `ntkrnlpa.exe` rather than tracing a file-open API) is the concrete precedent for step 1's alternate route.

## 10. Resource-binding recovery: mapping a data-file's indexed entries to the code that uses them

Section 9 recovers a **container of N indexed entries** (sounds, textures,
sprites, models). Vtable/RTTI work (sections 2-6 of the main workflow)
recovers **a set of classes**. Neither answers the question that's usually
the actual point of reversing a game binary: *which class or subsystem uses
entry #47?* -- "which enemy screams with this sound," "what triggers this
texture load." That's a different technique -- xref sweeping from the
resource-access API outward, not class-hierarchy recovery -- so it gets its
own recipe.

### 10.1 Find the resource-access API

The function that takes an index and does something with it is not always a
clean, directly-called symbol. Diagnose which case you're in from the
symptom, don't guess:

| Symptom | Likely cause | What to do |
|---|---|---|
| A symbol exists, calls into it are visible, but there's little logic in the function body | Thin wrapper (same pattern as section 9) -- an SEH/error-string wrapper sits one call deeper | Follow every call inside it before treating this as "the" API |
| A symbol-based or `axt` xref sweep on a suspected handler comes up **empty** | Function-pointer slot indirection -- the handler is installed at init time (`mov [slot], offset <fn>`), never called by name | Sweep the *slot address*, not the function: find every write (`nm`/`objdump -s`/`r2 axt` on the slot) to enumerate handlers, then find where the slot is *read and called* (`call dword [<slot_addr>]`) -- that instruction is the real fan-in point |
| There is no standalone function to xref *at all* for what should be an access point | Inlined dispatch -- the compiler inlined a small index-dispatch at every use site | Sweep from the underlying data instead: the table's base symbol, or the `lea <reg>, [<index_reg>*<stride> + <table_base>]` computation pattern |
| A resource table/string you're sure exists has **zero** xrefs | Indirect-pointer xref evasion -- `mov eax, offset dummy_anchor` / `add eax, 0x100` reaches the real target, but static tools (including IDA) only show a reference to `dummy_anchor` (Yurichev, ch. 50.2.5) | Check nearby code for an `add`/`lea` off an unrelated anchor symbol before concluding the reference doesn't exist |
| A `push` of what looks like a code address is immediately followed by `ret`, with no `call`/`jmp` anywhere near the real target | Bloated-instruction xref evasion -- `jmp label` as `push label`/`ret`, or `call label` as `push return_addr`/`push label`/`ret` (Yurichev, ch. 50.2.2: "IDA will not show the references to the label") | Treat the `push`+`ret` pair as a disguised `call`/`jmp` and resolve the target by hand |
| `call dword ptr [eax+14h]`-style dispatch, no xref found by any static tool | Virtual-call indirection -- the target is computed fresh per-instance from a vtable pointer, not one fixed global address | See section 10.6's IDA/IDC vtable-xref script, which resolves every real caller of every slot dynamically |

**A verified nuance on that last row, worth not overstating:** "no xref found
by any static tool" is true of the *call site* (confirmed directly: a
register-indirect `call eax` produces zero outgoing xrefs from any static
tool tried, `ghidra-cli` included), but the *vtable's own slots* are a
separate, easier fact -- a vtable slot is just a data word containing a
relocated function pointer, and `ghidra-cli`'s default auto-analysis
resolves that slot-to-implementation mapping for free via its relocation
analysis (`x-ref to <impl_addr>` on a virtual method returns a `DATA` xref
from the vtable slot that holds it, confirmed against both a symbol-bearing
and a fully stripped 32-bit binary). That's real progress -- it tells you
every implementation a vtable *could* dispatch to -- but it is not the same
fact as "this call site dispatches to this implementation" (10.4's actual
problem), since a static slot-to-function link says nothing about which
object's vtable pointer is live at a given call. Don't mistake the free
slot-enumeration win for having solved the harder attribution problem.

### 10.2 Enumerate call sites

```bash
r2 -q -c "aaa; axt @ <api_addr>" <binary>            # who calls/reads this address
r2 -q -c "aaa; axt @ <slot_addr>" <binary>           # for the fn-ptr-slot case: who writes AND who reads the slot
objdump -d -M intel <binary> | grep -B2 'call.*<api>' # binutils fallback: literal push before call
```

If IDA Pro is available, its built-in scripting language (IDC) has a direct
analog to `axt` -- useful since IDA's xref database is often more complete
against MSVC/PE binaries than r2's:

```c
// code xrefs TO an address (direct analog of `axt`):
auto xfAddr, origAddr;
origAddr = ScreenEA();
xfAddr = RfirstB(origAddr);
while (xfAddr != BADADDR) {
    Message("%x to %x, type == %d\n", xfAddr, origAddr, XrefType());
    xfAddr = RnextB(origAddr, xfAddr);
}
// Rfirst/Rnext (xrefs FROM an address), DfirstB/DnextB (data xrefs TO an
// address) mirror the same first/next iteration pattern. XrefType() returns
// the flowtype of the last xref returned (fl_CF/fl_CN/fl_JF/fl_JN/fl_F for
// code, dr_O/dr_W/dr_R/dr_T/dr_I for data) -- IOActive, Reverse Engineering
// Code with IDA Pro, ch. 9, pp.222-224.
```

The IDC snippet above assumes a human pasting it into IDA's interactive
command window (`Shift+F2`) -- not something an agent can drive over a
shell alone. If you have a licensed IDA Pro 9.1+ install with `idalib` and
need this step to be genuinely CLI-drivable, `headless-ida`
(`github.com/http8080/headless-ida`, confirmed via its own README + a
targeted grep for "debugger"/"breakpoint"/"attach" -- none found, it is
static-analysis-only) wraps the same xref database over HTTP/JSON-RPC:

```bash
ida-cli start <binary> --idb-dir <dir>   # analyzes once, caches the .i64
ida-cli wait <id>
ida-cli xrefs <api_addr> --direction to -i <id>   # direct analog of axt/RfirstB
ida-cli stop <id>
```

This covers the *static* half of IDA usage in this section cleanly (it's
the same underlying xref database `axt`/IDC read, just queried without a
GUI). It does not extend to 10.6 below: `headless-ida` has no debugger or
breakpoint capability at all, so the dynamic vtable-xref technique there
still needs an interactive IDA session or one of the CLI-scriptable
GDB/Pin/tracer alternatives documented in that section.

**`ghidra-cli` (`github.com/akiselev/ghidra-cli` -- verified end-to-end
this session, not just from docs) is the same idea with no license
requirement at all.** It wraps Ghidra's own headless analyzer behind a
`ghidra` binary and a persistent analysis "bridge," so there's no GUI step
anywhere in the loop:

```bash
ghidra setup --java-home <jdk21+>       # one-time: auto-downloads Ghidra itself
ghidra import <binary> --project <name> # imports AND runs full auto-analysis
ghidra --project <name> --program <prog> x-ref to <addr>    # analog of axt/RfirstB
ghidra --project <name> --program <prog> x-ref from <addr>  # analog of Rfirst/RnextB
ghidra --project <name> --program <prog> decompile <addr|name>
```

Requires a full JDK 21+ (a JRE won't work -- `ghidra doctor` checks this and
says so directly). Confirmed against a real 32-bit x86 PIE ELF, both with
and without debug symbols: `import` correctly recovers function boundaries,
`decompile` on a virtual-dispatch call site renders the indirect call *and*
the table-index arithmetic in one shot (`(**(code **)*param_1)(param_1,
*(undefined4 *)(&DAT_00014008 + param_2 * 4))` for a stripped binary --
directly confirms 10.3 item 4's table-sourced-index case and 10.1's
virtual-call-indirection case from decompiler output alone, no
disassembly-by-hand needed).

**Confirmed gotcha: importing a second, different binary into a project
that already has one open can return a stale/wrong function list on a
later query** (observed directly: a project that had two binaries imported
returned 12 functions for a binary whose fresh, single-binary project
correctly showed 37) -- import each binary into its own project, or verify
a query's addresses actually fall inside the target binary's own sections
(`ghidra ... memory map`) before trusting a suspiciously short result.

### 10.3 Recover the index argument at each call site

Ordered easiest to hardest -- try each in order before assuming you need the
next one:

1. **Literal immediate.** `push 0x2f` (or `mov eax, 0x2f` under thiscall)
   immediately before the `call`. Read it directly; no further work needed.
2. **Runtime-computed value.** Backward-slice the argument register/stack
   slot within the enclosing function -- walk backward from the `push`/`mov`
   to whatever instruction last wrote that register (`pdf` in r2, or read the
   `objdump` listing by hand) until it bottoms out at either a literal or a
   memory load. When the slice spans a loop or several basic blocks and doing
   this by hand gets error-prone, use `scripts/backward_slice.py` (wraps
   `triton-library`, the same technique as Andriesse's *Practical Binary
   Analysis* ch. 13.3) instead of slicing by hand:

   ```bash
   python3 -m venv <skill_dir>/.venv                      # one-time setup
   <skill_dir>/.venv/bin/pip install triton-library lief   # MUST be an isolated venv --
                                                            # see the script's docstring
   <skill_dir>/.venv/bin/python3 <skill_dir>/scripts/backward_slice.py \
       <binary> <entry_addr> <slice_addr> <reg>
   ```

   Confirmed working end-to-end against a real 32-bit ELF (Triton emulates
   real instruction semantics -- `ARCH.X86`/32-bit is directly supported, not
   just x86-64 -- and genuinely follows calls/jumps/rets via the concrete
   `eip` it maintains, not a naive linear disassembly walk). Emits the
   contributing instructions as JSON, ordered by address. Requires a
   **dedicated venv**: this machine (and possibly others) already has
   OpenAI's unrelated GPU-kernel-compiler package also importable as
   `triton` (a common transitive PyTorch dependency) -- installing
   `triton-library` into the ambient interpreter can leave `import triton`
   resolving to the wrong package entirely, failing with a confusing error
   unrelated to anything in this recipe. The script detects and reports this
   case rather than silently misbehaving, but avoiding it with a venv is
   simpler than debugging it.

   **If you already know upfront that you need automatic path exploration
   across branches, not one concrete path** -- that's a tool-choice decision,
   not a diagnosis, and it's made before you run anything: go straight to
   `angr` (a real, installable symbolic-execution engine; REMaQE, Udeshi et
   al., builds its equation-recovery pipeline on it -- cite `angr` itself,
   REMaQE has no public release), skipping `backward_slice.py` entirely.

   **If instead you started with `backward_slice.py` and it hangs or its
   state count explodes**, that *is* a genuine symptom -- diagnose the cause
   before reaching for a bigger tool:

   | Symptom | Diagnosis | Fix |
   |---|---|---|
   | Slice/trace hangs or state count explodes, and the code has a function pointer, recursion, or obfuscated control flow (`references/obfuscation.md`) | Path explosion -- named directly by REMaQE as the failure mode for exactly these three shapes | Confirm this is the actual cause (check the disassembly for the three shapes above) before escalating further |
   | Path explosion confirmed, and it's specifically a memory-corruption vulnerability (heap/stack overflow, UAF, double-free) | Whole-program symbolic execution is exploring far more state than the bug needs | `UbSym` (`github.com/SoftwareSecurityLab/UbSym`, confirmed real, a working `angr` plugin) -- statically scopes symbolic execution to a "unit" (the function containing the candidate vulnerability, found via VEX-IR pattern rules per class) instead of the whole program |

   UbSym's own benchmark against MACKE/Driller on NIST SARD programs: 1.00
   accuracy/precision/recall on all four vulnerability classes (MACKE's
   recall was as low as 0.21 on use-after-free; Driller couldn't detect
   use-after-free at all -- "only detects vulnerabilities making the
   program crash") and 3-15x faster. **Named limitations, not just
   strengths**: no pruning yet for extremely large units (may fail to
   build the unit tree at all), and stack-overflow detection is unsound by
   construction -- it only catches overflows that corrupt the saved frame
   pointer, not ones that corrupt only local variables without reaching it.
3. **`this`-relative / thiscall argument.** Under MSVC thiscall (see
   `references/msvc-abi.md`), the index may come from the object itself:
   `mov eax, [ecx+<off>]` followed by `push eax` means the *field offset*
   `<off>` within the object is the real target of interest, not a single
   fixed index -- every instance of that class supplies its own index through
   that field.
4. **Table-sourced index.** If the backward slice bottoms out at a memory
   load rather than a literal, the xref sweep has only found *the table
   reader* -- the real per-entity mapping lives in the table's row layout,
   not in code. This is now a data-table problem, structurally identical to
   section 9's file-format work: find the table's base address and stride
   (a loop incrementing by a fixed size, or a `[reg*N + base]` addressing
   pattern gives you the stride directly, same as section 9.4), then work
   out which field offset within each record holds the id. The call site you
   started from tells you almost nothing further; the table's layout does.
   **Dump the table's actual bytes before naming what it holds** (10.8) —
   a single `cmp`/`je` against a table slot cannot distinguish a pointer
   table from a flag mask from a kind enum, but the data can. And check for
   a parallel per-entry metadata table while you are there (10.9).

   **Why a bounds check next to a `[reg*scale + disp]` access is decisive,
   not just suggestive:** a single textual xref to `disp` combined with a
   preceding `cmp reg, N` / `jae`/`jl` bound is the exact signature Value-Set
   Analysis (Balakrishnan & Reps, *WYSINWYX: What You See Is Not What You
   eXecute*, PLDI 2004 / TOPLAS 2010) formalizes for proving a memory access
   is a finite global array rather than an unbounded pointer -- the bound
   establishes the register's value set, and the access pattern establishes
   the array's element size and base. `DIVINE: DIscovering Variables IN
   Executables` (Balakrishnan & Reps, VMCAI 2007) extends the same VSA
   machinery specifically to aggregate/struct recovery. You're doing the
   same proof by hand: the bound is what lets you trust `disp` is a table
   base and not, say, an unrelated constant that happens to share a
   displacement with something else nearby.

   **Watch for padding when computing a field's real size.** MSVC (and GCC)
   default to aligning every struct field to its natural boundary (a
   `char`/`short` field still occupies a full 4-byte-aligned slot, with the
   unused bytes left as uninitialized garbage -- confirmed via a real
   compiled example in Yurichev, *Reverse Engineering for Beginners*, ch.
   21.4). The tell is in how the field is *read*: `movsx`/`movzx` on a
   sub-dword width means the real field is smaller than its apparent slot,
   and the remaining bytes in that slot are padding, not part of the value
   -- don't mistake them for a second field. Wire-format structs (the kind
   section 9 recovers from a file loader) are the opposite case: they're
   usually declared with `#pragma pack(1)` or `pshpack1.h` specifically to
   avoid this padding, since the loader needs a byte-for-byte match with the
   file's layout, and the *disassembly of the packed and unpacked versions
   is otherwise indistinguishable* (same source) -- you can't tell a struct
   is packed from the code alone, only from the field offsets/strides
   actually observed. Same skill, opposite default: expect padding when
   recovering an in-memory C++ object's fields (this section), expect none
   when recovering a file-format struct (section 9).

### 10.4 Attribute the call site to an owner

- **RTTI/vtable path (when available).** If the call site is inside a member
  function, the demangled enclosing function name gives you the owning class
  directly -- cross-check against `references/itanium-abi.md` or
  `references/msvc-abi.md`. This is the common case and needs no further
  technique.
- **Static alternative to section 10.6's IDC vtable-xref script (VPS).**
  If you don't have IDA, or want a static answer without running the
  target, VPS (Pawlowski et al., ACSAC 2019, §4.3.2) gives a three-stage
  procedure for tracing a virtual call's `vtblptr` back to the constructor
  that wrote it, without executing anything:

  | Step | Action | Checkpoint |
  |---|---|---|
  | 1 | Backward data-flow graph from *every* vtable-referencing instruction (creates a `vtblptr`) AND *every* virtual-call candidate (uses one) -- interprocedurally, through argument/return registers, in SSA form | A write site and a call site share the same ultimate data source (candidate match, not yet proven) |
  | 2 | Translate that shared-data-source claim into an actual CFG path between the two instructions | A real path exists -- shared ancestry alone is not proof |
  | 3 | Symbolically execute along the verified path with the `vtblptr` marked symbolic at the write site (skip into unrelated calls rather than exploring them) | The symbolic value is what's actually consumed at the call site |
  | **Exit** | Confirmed match, or a documented non-match | Not "probably the same object" |

  Reach for the IDC script (section 10.6) when you can run the target and
  want an immediate, concrete answer; reach for this when you can't run it,
  or when you want to verify a match rather than just observe one.
- **Stripped MSVC fallback (no RTTI).** When the enclosing function's own
  name is unavailable:
  - Nearby string literals in the same function (level names, debug
    asserts, `"You die."`-style text) are often the fastest attribution --
    weaker evidence than a symbol, so mark it inferred.
  - The function's *other* behavior (what other globals/subsystems it
    touches) as a smell test for which subsystem owns it -- also inferred,
    not confirmed.
  - Dynamic capture of `this`: break at the call site, dump `ecx`
    (`x/8xw $ecx`), and check offset 0 for a vptr even if the binary exports
    no RTTI -- many MSVC classes still carry a vptr for virtual dispatch
    without exported type descriptors. Diff that vtable's address against
    vtables you've already identified via `mov [ecx], offset <vtable>` in
    constructors (`references/msvc-abi.md` section on vftable identification)
    to name the type even without a demangled symbol.
  - **Method-visibility heuristic**, once you have real callers for a set of
    vtable slots (e.g. from section 10.6's IDC vtable-xref script): a target
    function called from *outside* any vtable is public; one called only
    from other methods within its own vtable is private; one called only
    from methods in *other* vtables is protected. Doesn't replace RTTI, but
    is a concrete, low-cost signal for classifying a resolved call site's
    role when RTTI isn't available (IOActive, ch. 9, p.220).

### 10.5 Present the result

A table, not prose: `index | evidence (address / log line / table offset) |
owner (class/subsystem) | confidence (confirmed/inferred) | note`. Keep
confirmed rows (a literal push, a captured runtime log, a direct RTTI match)
visually distinct from inferred ones (nearby strings, behavioral smell test)
-- the whole point of this deliverable is that a later reader can tell which
rows to trust without re-deriving them.

**Prefer naming the specific reason over a bare confirmed/inferred flag
when you can.** REFORGE's benchmark methodology (Table 1) grades binary-
to-source alignment through eight named gates rather than one pass/fail
bit -- each failure is attributed to a specific cause ("ambiguous or failed
binary-to-source mapping," "unresolved indirect jumps in control flow",
etc.), not just "low confidence." Do the same in the `note` column: not
"inferred" alone, but *which* of section 10.4's fallback techniques
produced the row (e.g. "nearby string only," "behavioral smell test,"
"single indirect xref, unresolved") -- a future reader deciding whether to
trust a row needs to know why it's uncertain, not just that it is.

### 10.6 Dynamic capture -- often higher-yield than static slicing

When call sites are numerous, the index is table-sourced, or static
confidence is just low, prefer *observing* over inferring:

```
(gdb) break *0x<api_addr>
(gdb) commands
  > silent
  > printf "idx=%d retaddr=%p ecx=%p\n", <idx_reg>, $ra, $ecx
  > continue
> end
(gdb) run
```
Play the game (or drive whatever triggers the call) and correlate observed
behavior with logged indices in real time -- "walk into water, see `idx=47`
logged" turns an inference problem into an observation problem. This extends
section 7's GDB techniques with a non-stopping logging breakpoint instead of
a one-shot break.

For a long play session where an attached interactive debugger is too
disruptive, log the same tuple without stopping execution instead:

- **Pin (preferred -- confirmed 32-bit and Windows capable).** Intel Pin
  ("currently supports Intel CPU architectures including x86 and x64 and is
  available for Linux, Windows, and macOS" -- Andriesse ch. 9.3.2) is a
  dynamic binary instrumentation engine built for exactly this: instrument
  the call site with `INS_IsCall(ins)` to find it, then
  `INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_fn, IARG_INST_PTR,
  IARG_BRANCH_TARGET_ADDR, IARG_END)` (Andriesse ch. 9.4.4, Listing 9-4) to
  register an analysis callback that fires every time, logs, and lets
  execution continue -- no attached interactive debugger, works against the
  running game the same as it would against `/bin/true` in the book's
  example. Add `IARG_REG_VALUE` for the index/`this` register itself (Pin's
  own API reference, not shown in the book's excerpted listing) to capture
  the index alongside the call site.
- **Inline-hook toolkits (pattern only, verify architecture first).**
  Game-modding toolkits built around AOB (array-of-bytes) signature scanning
  plus inline hooking follow the same idea from outside an official DBI
  framework: scan for the call site's byte signature, install a hook that
  logs and calls through, then play normally. `tkhquang/DetourModKit` is a
  real, working example of this pattern (`StringXref`/`xref_broad_match` for
  anchor-based call-site discovery, `mid_at()` for the logging-then-
  continuing hook) but is **Windows x64 only** -- useful as a reference for
  the technique, not a tool to run directly against a 32-bit target. Always
  confirm a given toolkit's architecture support before adopting it, rather
  than assuming a modding library that looks applicable actually targets
  your bitness.
- **`tracer` (Windows, lightweight, IDA-integrated).** Dennis Yurichev's
  `tracer.exe` is a simpler alternative to Pin/WinDbg scripting for this
  exact job on Windows. A non-stopping logging breakpoint is one line:

  ```
  tracer.exe -l:target.exe bpf=target.exe!0x<addr>
  ```

  which dumps register state at every hit without stopping (*Reverse
  Engineering for Beginners*, ch. 23.1.2). More useful for section 10.3's
  backward-slicing case: `bpf=target.exe!0x<addr>,trace:cc` produces an IDC
  script that, loaded into IDA, annotates the disassembly *inline* with
  every concretely observed register value at that instruction across the
  run, and visibly grays out instructions that were never executed (ch.
  23.1.3) -- a distinct payoff from GDB/WinDbg/Pin's plain log files: you
  get traced values directly in the disassembly view you're already reading
  the resource-access API in.

**IDA/IDC vtable-xref script (resolves the 10.1 virtual-call-indirection
case) -- requires a human at an interactive IDA GUI, not agent/CLI-drivable.**
Every step below (selecting a range in the IDA view, hitting a hotkey,
"driving the target normally") assumes a person operating IDA and the
target simultaneously; there's no shell equivalent of "play the game" for an
agent to issue. `headless-ida` doesn't close this gap either -- it has no
debugger or breakpoint capability (confirmed via its README and a grep for
"debugger"/"breakpoint"/"attach": zero matches), so it can't install the
conditional breakpoints this technique depends on. **In a pure-agent
workflow, reach for the already-CLI-scriptable GDB logging-breakpoint, Pin,
or `tracer.exe` techniques documented earlier in this section instead** --
they get you the same real-caller-per-slot result without a human at the
keyboard. Use the script below only when a human collaborator with IDA
access is doing this part of the work:

| Step | Action | Checkpoint |
|---|---|---|
| 1 | Select the vtable's address range in the IDA view | Selection spans a whole number of 4-byte slots |
| 2 | Load the script below (`File > IDC File...`, or paste into the IDC command window with `Shift+F2`) | Script loads with no syntax errors |
| 3 | Hit `Alt-F9` | Breakpoints installed on every slot's target, none of them stop execution |
| 4 | Drive the target normally (play the game, exercise the feature) | Execution proceeds without pausing at any of the new breakpoints |
| **Exit** | Every indirect call through any slot in the range is now a real, permanent cross-reference | Check `AddCodeXref`'s effect directly -- the source binary this was verified against went from 0 visible xrefs to 26 real call sites |

```c
#include <idc.idc>
static breakpointHandler()
{
    auto caller;
    caller = PrevHead(Dword(ESP), (Dword(ESP) - 10));
    AddCodeXref(caller, EIP, XREF_USER | fl_CN);
    return 0; // don't stop on breakpoint
}
static setBPs()
{
    auto currAddr;
    auto vStart;
    auto vEnd;
    auto virFunc;
    vStart = SelStart();
    vEnd = SelEnd();
    if ((vStart == BADADDR) || (vEnd == BADADDR)) { return; }
    if ((vStart - vEnd) % 4 != 0) { return; } // not DWORD aligned
    for (currAddr = vStart; currAddr < vEnd; currAddr = currAddr + 4)
    {
        virFunc = Dword(currAddr);
        if (GetBptAttr(virFunc, BPTATTR_EA) == -1) // no bpt there yet
        {
            if (!AddBptEx(virFunc, 0, BPT_SOFT)) { return; }
            if (!SetBptCnd(virFunc, "breakpointHandler()")) { return; }
        }
    }
}
static main()
{
    AddHotkey("Alt-f9", "setBPs");
}
```

Mechanism, if step 3 or 4 doesn't behave as expected: `setBPs` reads each
slot's target with `Dword(currAddr)` and installs a breakpoint conditional
on `breakpointHandler()` -- returning `0` from a conditional-breakpoint
handler means "don't stop," so it only *runs code* on every hit, never
interrupts. `breakpointHandler` finds the real caller by searching backward
from the return address on the stack (`PrevHead(Dword(ESP), Dword(ESP)-10)`
-- an indirect call through a register is only 3 bytes, so 10 bytes back is
enough to land on the actual `call`). (IOActive, *Reverse Engineering Code
with IDA Pro*, ch. 9, pp.213-220, "VTable xref Script," Figure 9.10.)

**Differential technique:** trigger one in-game event repeatedly (open the
same door, walk into the same water tile) and diff the captured index sets
across runs -- the index specific to that event is the one that shows up
every time, separable from ambient/background triggers that don't correlate
with the action.

**Capturing every entry of a large table dynamically gets expensive fast --
"program skeletonization" (Ketterlin & Clauss, 2014, §4.2) is a portable
way to cut that cost.** Rather than logging every iteration of a loop over
N table entries, instrument only the loop's *leaf* registers (the values
that don't depend on anything else already known -- initial pointers,
input-derived values) and each memory access's computed address, once;
then replay the *static* address-expression (recovered as above) through
those few logged values to reconstruct the full per-entry trace without
re-executing or re-logging each iteration. Reported reduction: "a factor
of 3 to 4" fewer instrumentation points on floating-point-heavy code,
~20% on integer-heavy code, and up to 25-fold on deeply-nested loops.
Directly applicable here: if you already have the table's stride and base
(section 9.4/10.3), you don't need a GDB/WinDbg/`tracer` breakpoint to
fire on every one of N entries -- log the loop's few leaf inputs once and
compute the rest.

### 10.7 Don't trust inherited "X calls Y" claims

A documented claim that gameplay code calls a specific low-level function or
writes a specific global directly is frequently really "gameplay calls a
wrapper that eventually reaches it" -- especially across a subsystem
boundary (gameplay -> audio, gameplay -> renderer) you haven't fully mapped
yet. Re-derive the xref chain yourself (`axt` from the actual global/function,
not from where a prior doc said the call originates) before building
attribution on top of it; a doc written before a later fix can describe a
call path, table layout, or field offset that was true once and silently
went stale.

This isn't specific to this skill's own history -- Shashidhar & Novak
(2015) found the same failure mode independently while reversing Windows
prefetch files, describing an earlier widely-cited writeup as one that
"lacks academic scrutiny and seems to be composed using commercial
software documentation, blogs, and Wikipedia," and that this "inadvertently
introduces misconceptions" as a direct result. Same lesson, unrelated
binary, unrelated researchers -- treat it as confirmation this is a
general failure mode of secondhand technical writeups, not a one-off.

### 10.8 Read the table's bytes before inferring what the table *is*

Everything above walks *instructions*. The decisive evidence for what an
indexed table actually holds is usually the **static data itself**, and the
single most common failure in this whole workflow is naming a table's
semantics from the one instruction that touches it.

Concretely: `cmp DWORD PTR [edi*4+0x532148], ebx` / `je bail` reads exactly
like a "look up the pointer for this id, bail if it isn't loaded" — a
null-check on a runtime pointer table. It is equally consistent with a static
`int[N]` of 0/1 flags, a table of small enum kinds, or an array of indices
into a *different* table. The instruction cannot distinguish these. The bytes
can, instantly:

```bash
# resolve the table's file offset from its VMA, then dump N dwords
objdump -h <binary> | grep -A1 '\.data'          # VMA vs File off for the section
python3 -c "
import sys
vma,secva,secoff,n = 0x532148, 0x51e000, 0x11bc00, 271
data = open(sys.argv[1],'rb').read()
off  = vma - secva + secoff
vals = [int.from_bytes(data[off+4*i:off+4*i+4],'little') for i in range(n)]
print('distinct values:', sorted(set(vals))[:12])
print('nonzero count :', sum(1 for v in vals if v))
" <binary>
# r2 equivalent: px 1084 @ 0x532148   (or  pxw 271*4 @ 0x532148)
```

If the distinct values are `{0, 1}` it is a flag mask, not pointers. If they
are plausible code/data addresses it really is a pointer table. If they are
small integers with runs, it is a kind/type table (see 10.9). A table that is
**never written at runtime** — no fill loop anywhere, and its only xref is the
read you started from — is by definition static content shipped in the image,
so read it out of the image. "Only one xref" is evidence *for* a static table,
not proof of a hidden populating loop.

Do this *before* writing down what the table means. An inferred semantic that
gets recorded as a fact will be built on by everything downstream, and the
whole point of the confidence column in 10.5 is defeated if the confirmed rows
were never actually confirmed.

### 10.9 Look for a parallel per-entry metadata table

When a binary loads a container of **N** indexed entries (section 9), look for
a second, **N-entry** table describing them — kind/type, flags, priority,
group id. These are extremely common in game and asset formats, and finding
one converts "I have N opaque blobs" into "I know what each blob is for"
faster than any amount of analysis of the blobs themselves.

How to spot one:

- Size is the giveaway: a table whose length is exactly `N`, `N*2` or `N*4`
  bytes for the same N the container header declares. If the container says
  1101 entries, grep the data section for a 1101-byte run of small values.
- It is usually read right next to the container load, and its base pointer
  cached into a global (`mov [<global>], offset <table>`) during init.
- It typically feeds a `switch` — the per-entry kind selects a playback /
  render / parse path, so the table's consumer is a jump table.
- **Run-length structure is meaningful.** Contiguous runs of one kind are
  banks/sections of the container, and an alternating pattern (`1,3,1,3,…`)
  across a range means entries are **paired** — two halves of one logical
  asset (intro + continuation, header + payload, base + overlay), not N
  independent items. This is the kind of structure that is nearly impossible
  to infer correctly from the decoded asset data alone, and trivial to read
  off the table.

Decode the consumer's jump tables to name the kinds (`objdump`/`r2` at the
`jmp dword [reg*4 + <tbl>]` target, then walk each case). The cases are the
engine's own behaviour spec for that asset type — variation, looping, and
delay logic recovered this way is authoritative in a way that guessing from
the asset payload never is.

**Worked example (Esoteria, 1998).** A 1101-entry audio container yielded 785
extracted segments whose even/odd alternation was "explained" by duration and
amplitude statistics as loop-bodies vs. transitions. Wrong. A 1101-byte kind
table sitting parallel to the container (base cached to a global at init, fed
to two jump tables) showed the real structure: ids 0-270 one-shot SFX,
300-699 alternating intro(even)/continuation(odd) **pairs**, 750-802 a second
SFX bank. Signal analysis of the payload had produced a confident, plausible,
### 10.10 Headless PE static analysis when dynamic debuggers fail (ptrace-restricted sandboxes)

Dynamic logging breakpoints (section 10.6 under Wine/GDB or section 11 under WinDbg) are ideal, but in containerized agent sandboxes, cloud CI, or unprivileged Linux environments, `SYS_PTRACE` is frequently denied (`ptrace: Operation not permitted` or `Inappropriate ioctl for device`). Dynamic tracing fails before the process spawns.

When dynamic debugging is unavailable:
1. **Never calculate PE file offsets naively.** In PE32 files, section `PointerToRawData` frequently differs from `VirtualAddress` (e.g. `.text` VA `0x1000` but file raw offset `0x400`). Slicing by `va - ImageBase` produces misaligned instruction streams. Always use `pefile.get_offset_from_rva()` or section `PointerToRawData`.
2. **Correlate with container payloads directly.** If an API parameter is read off an instance field (e.g. `[esi + 0x188]`), trace that field back to its constructor or deserializer (`IStream::Read` / `LoadObject`). If it is deserialized from shipped data containers, write a 15-line script to unpack all container entries and inspect the distribution statically rather than waiting on a debugger.

**Standard 10-line Python recipe for targeted PE disassembly and xref scanning:**

```python
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

pe = pefile.PE("TARGET.EXE")
md = Cs(CS_ARCH_X86, CS_MODE_32)

def disasm_vma(vma: int, size: int = 64):
    rva = vma - pe.OPTIONAL_HEADER.ImageBase
    raw_offset = pe.get_offset_from_rva(rva)
    code = pe.__data__[raw_offset : raw_offset + size]
    for insn in md.disasm(code, vma):
        hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes)
        print(f"0x{insn.address:08x}:  {hex_bytes:<20} {insn.mnemonic} {insn.op_str}")

# Find all 32-bit immediate or absolute address references across .text:
def find_dword_refs(val: int):
    target = val.to_bytes(4, "little")
    for sec in pe.sections:
        data = sec.get_data()
        pos, base = 0, pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
        while (pos := data.find(target, pos)) != -1:
            print(f"Ref to {hex(val)} at 0x{base + pos:08x} ({sec.Name.decode().strip(chr(0))})")
            pos += 1
```

## 11. WinDbg: dynamic analysis for native Windows PE binaries


Sections 7 and 10.6 use GDB throughout, but GDB only applies if the PE
target is running under something GDB can actually attach to (Wine, or a
Linux PE loader). A real Windows process needs a native Windows debugger --
WinDbg, CDB, NTSD, and KD all share the same underlying engine (DbgEng) and
the same command syntax, so the recipes below apply regardless of which
front end you're using. ("Debugging Tools for Windows" is the package name;
these are not part of Visual Studio.)

If the target detects and evades WinDbg/CDB specifically (via one of the
techniques in `references/anti-debugging.md`), see that file's "Debugging
past these techniques instead of just recognizing them" section for
HyperDbg -- a hypervisor-assisted debugger built to avoid triggering those
checks in the first place, confirmed applicable to 32-bit PE targets.

**Static PE inspection without running it.** `cdb -z c:\path\to\file.exe`
maps a PE/DLL into the debugger the same way a crash dump would -- useful
for offline triage without ever executing the target, the WinDbg analog of
just loading a binary into r2/objdump without running it.

**Logging breakpoint without stopping (the WinDbg analog of GDB's
`commands`/`continue` pattern used in section 10.6):**

```
bp kernel32!CreateFileW "!process @$proc 0;.printf \"%mu\n\",poi(@esp+4);gc;"
```

`.printf` logs, and `gc` ("go from conditional breakpoint") resumes
execution automatically -- this is the same non-stopping logging-breakpoint
technique section 10.6 describes for capturing `(index, retaddr, this)`
tuples while playing a game normally, just with WinDbg's syntax instead of
GDB's.

**Conditional breakpoint on the return address** (directly useful for
section 10's call-site attribution -- break only when a specific caller
hits a shared function): `$ra` is a real pseudo-register holding the
current return address.

```
bp user32!MessageBoxA "j (@$ra=0x401058) '';'gc;'"
```

**Conditional breakpoint on a register value**, the general form section
10's fn-ptr-slot/table-sourced-index cases need (break only when a specific
index/argument value is seen):

```
bp 7661d0df ".if @eax!=5 { gc; }"
```

**Hardware watchpoint** (direct analog of GDB's `watch`, for catching a
vptr or field write -- msvc-abi.md's dynamic-confirmation step 4):
the `ba` command takes an address, access type (`r`/`w`/`e`), and size.

**Struct/type inspection once symbols are available:**
`dt _UNICODE_STRING 0x18fef4` -- dumps a typed struct at an address; useful
once you have a PDB, less useful against the stripped/no-PDB binaries this
skill mostly targets.

**Scripted automation beyond WinDbg's own command language.** DbgEng is a
COM object with a real SDK if you need something more structured than
typed WinDbg commands -- `IDebugControl4` (process control),
`IDebugDataSpaces4` (`ReadVirtual`/`WritePhysical`), `IDebugRegisters2`,
`IDebugSymbols3`, `IDebugClient5` -- the WinDbg equivalent of driving GDB
from a Python script via `pwntools`' `gdb.debug()` (section 7).

## 12. Automated C++ class recovery with OOAnalyzer (CMU SEI / Pharos)

For 32-bit x86 Windows PE binaries compiled by MSVC, the Pharos framework's
`ooanalyzer` (`github.com/cmu-sei/pharos`) automates what would otherwise
take days of manual assembly tracing. It extracts ground facts using ROSE
and evaluates them using a SWI-Prolog reasoning engine
(`share/prolog/oorules/*.pl` -- 28 files, confirmed against the real repo).

### Capabilities (per `ooanalyzer.pod`)
- Reconstructs complete C++ class hierarchies, inheritance trees, and member layouts.
- Identifies constructors, destructors, and method associations.
- **Virtual Call Resolution:** Resolves indirect virtual calls (`call [eax + slot]`)
  to concrete function addresses by tracking object types and vftable assignments.
- Resolves RTTI metadata even when obfuscated or stripped of symbols.

### Usage Recipe

```bash
# Run OOAnalyzer and export JSON results:
ooanalyzer --json=recovered_classes.json <binary.exe>

# Also export intermediate Prolog facts for manual queries:
ooanalyzer --json=out.json --prolog-facts=facts.pl --prolog-results=results.pl <binary.exe>
```

### Inspecting Results (`jq`) -- confirmed against `share/prolog/oorules/oojson.pl`

The real top-level shape (`root{'structures':.., 'vcalls':.., 'version':..,
'filemd5':.., 'filename':..}`) is built by `oojson.pl`'s
`makeAllStructuresJson`/`makeOneVcallUsageJson`. Two things that don't match
a naive guess: **`structures` is an object keyed by class name, not an
array** (`dict_create(Json, structures, KVPairs)` over `NameKey:ClsJson`
pairs), and virtual calls live under **`vcalls`**, not `calls`, as an
instruction-address-to-target mapping rather than a flat list of records.
Each class entry is `classes{'name', 'demangled_name', 'size', 'members',
'methods', 'vftables'}`.

```bash
# List all recovered classes with their size and vftables:
jq -r '.structures | to_entries[] | "\(.value.name): size=\(.value.size) vftables=\(.value.vftables)"' recovered_classes.json

# Dump the virtual-call-site -> target mapping:
jq '.vcalls' recovered_classes.json
```

### Querying the Prolog facts/results directly (per `ooprolog.pod`)

There is no documented recipe for hand-loading `facts.pl`/`results.pl` into
a bare `swipl` session -- don't invent one. The real, documented workflow is
OOAnalyzer's own `--halt=false` flag, which drops you into an interactive
SWI-Prolog shell with everything already loaded, right after the analysis
phase completes:

```bash
ooanalyzer --halt=false <binary.exe>
# ... analysis runs, then you're left at a `?-` prompt with all facts/rules loaded
```

From there, two confirmed real predicates worth querying directly (both
verified against the actual `oorules/*.pl` source, not guessed):

```prolog
?- rTTICompleteObjectLocator(Pointer, Address, TDAddress, CHDAddress, Offset, CDOffset).
% facts.pl -- Pointer is the vftable-4 slot; Address is the COL's own location;
% TDAddress/CHDAddress are the TypeDescriptor/ClassHierarchyDescriptor addresses;
% Offset/CDOffset match this skill's msvc-abi.md CompleteObjectLocator fields.

?- finalClass(ClassID, VFTable, MinSize, MaxSize, RealDestructor, MethodList).
% results.pl -- the actual resolved-class predicate; MinSize/MaxSize because
% OOAnalyzer reasons in bounds, not always an exact size.

?- finalVFTable(VFTable, CertainSize, LikelySize, RTTIAddress, RTTIName).
% results.pl -- CertainSize vs LikelySize is the same bounded-reasoning idea
% applied to a single vftable rather than the whole class.
```

Four more, confirmed real in `final.pl`/`forward.pl`/`rules.pl` (not in
`facts.pl`/`results.pl` -- these are the raw reasoning-layer predicates the
`final*` ones above are derived from, not the top-level answers):

```prolog
?- factConstructor(Method).
% final.pl/forward.pl/rules.pl -- Method (an address) is confirmed as a constructor.

?- factDerivedClass(DerivedClass, BaseClass, ObjectOffset).
% final.pl/forward.pl/rules.pl -- "In the Derived class at the specified offset
% is an object instance of the type specified by Base" (final.pl's own comment).
% ObjectOffset is the base subobject's byte offset within the derived class.

?- factClassSizeGTE(Class, KnownSize).
?- factClassSizeLTE(Class, KnownSize).
% rules.pl only -- Class's size is known to be at least/at most KnownSize.
% OOAnalyzer reasons about size as a bounded range, not a single number, which
% is why finalClass above has separate MinSize/MaxSize fields rather than one.
```

### IDA Pro / Ghidra Integration
OOAnalyzer includes plugins to annotate disassemblers with the recovered types:
- **IDA Pro:** `tools/ooanalyzer/ida/OOAnalyzer.py` loads the JSON file and applies
  struct definitions, class names, method signatures, and virtual call comments.
- **Ghidra:** The Ghidra plugin (under `tools/ooanalyzer/ghidra`) imports the JSON
  to create matching data types and namespace symbols.

---

## 13. Data-table field attribution and struct recovery (Dang et al. / REWARDS / TIE)

Stripped binaries with procedural code, game subsystems, or internal tables
often store complex data without vtables or symbols. Reconstructing structs
manually from assembly requires observing pointer arithmetic and memory access
envelopes.

### 13.1 Manual Assembly-Level Struct Reconstruction (Dang et al., ch. 1)

1. **Base Pointer Tracking:**
   Identify registers holding object pointers (e.g. `esi` maintained across loops,
   or `ecx` in `__thiscall` methods).
2. **Displacement Mapping:**
   Record every `[base + disp]` offset. Each distinct displacement indicates a
   struct member boundary:
   - `mov [esi + 0x00], eax` $\rightarrow$ member at offset `0x00` (4 bytes).
   - `mov word ptr [esi + 0x04], cx` $\rightarrow$ member at offset `0x04` (2 bytes).
   - `mov byte ptr [esi + 0x06], dl` $\rightarrow$ member at offset `0x06` (1 byte).
   - `mov [esi + 0x08], ebx` $\rightarrow$ member at offset `0x08` (4 bytes).
3. **Subobject Composition vs. Inheritance:**
   If a function passes `[esi + offset]` as `this` (`lea ecx, [esi + 0x20]; call ctor`),
   the parent object has an embedded composite object or non-virtual base
   subobject located at offset `0x20`.

### 13.2 Formalizing Record Bounds and Field Types (REWARDS & TIE)

Formalized by Lin et al. (*REWARDS*, NDSS 2010) and Lee et al. (*TIE*, NDSS 2011):

1. **Record Boundary & Stride Analysis:**
   - In table iteration loops, the increment applied to the index pointer in each
     iteration is the **record stride** $S$:
     ```asm
     loc_loop:
         ...
         add  esi, 0x28       ; Record size is definitively 0x28 (40 bytes)
         cmp  esi, edi
         jne  loc_loop
     ```
   - **Displacement Envelope:** The minimum struct size is bounded by:
     $$\text{Size} \ge \max(\text{displacement}) + \text{sizeof}(\text{access})$$
2. **Instruction Type Constraints:**
   The instruction opcode accessing `[base + offset]` strictly bounds the semantic
   field type:
   | Assembly Pattern | Semantic Type Inferred |
   |---|---|
   | `movzx eax, byte ptr [...]` / `cmp byte ptr [...], 1` | `bool` or `uint8_t` |
   | `movsx eax, word ptr [...]` | `int16_t` |
   | `fld dword ptr [...]` / `movss xmm0, [...]` | `float` (IEEE 754 single precision) |
   | `fld qword ptr [...]` / `movsd xmm0, [...]` | `double` (IEEE 754 double precision) |
   | `mov eax, [...]` followed by `test eax, eax` / `jz` | Pointer or opaque handle |
   | `cmp dword ptr [...], 0x10` / `ja default_case` | Enumeration or bounded state tag |
   | `lea eax, [...]` passed to string APIs (`strlen`/`printf`) | Embedded character array (`char[]`) |

---

## 14. Programmatic binary analysis recipes (Andriesse, *Practical Binary Analysis*)

When interactive tools are impractical or batch processing is required, custom
scripts using Python (`lief`, `capstone`) automate cross-reference sweeping,
function boundary identification, and control-flow tracing.

### 14.1 Programmatic Immediate Xref Sweeper (Python + Capstone + LIEF)

To find all instructions referencing a target memory address (immediate data
pointer or table offset) across `.text`:

```python
#!/usr/bin/env python3
import sys
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, x86

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <binary> <hex_target_addr>")
    sys.exit(1)

binary_path = sys.argv[1]
target_addr = int(sys.argv[2], 16)

binary = lief.parse(binary_path)
text_sec = binary.get_section(".text")
code = bytes(text_sec.content)
base_addr = text_sec.virtual_address

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

print(f"[*] Sweeping for xrefs to 0x{target_addr:08x} in .text (0x{base_addr:08x})...")
for insn in md.disasm(code, base_addr):
    for op in insn.operands:
        # Check immediate operands (push offset, mov reg, offset)
        if op.type == x86.X86_OP_IMM and op.imm == target_addr:
            print(f"  [IMM XREF] 0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
        # Check memory displacements ([disp], [base + disp])
        elif op.type == x86.X86_OP_MEM and op.mem.disp == target_addr:
            print(f"  [MEM XREF] 0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
```

### 14.2 Recursive Disassembly & Function Boundary Detection

Linear sweep disassembly can be derailed by inline data, alignment padding
(`0x90` / `0xCC`), and jump tables. A recursive traversal algorithm traces
reachable instructions following branch targets:

1. **Seed Queue:** Initialize a work queue with known entry points:
   - File entry point (`AddressOfEntryPoint`).
   - Exported function addresses (EAT).
   - Targets of all direct `call rel32` instructions.
   - Pointers discovered in vftables (slot 0, slot 1, ...).
2. **Basic Block Traversal:**
   Disassemble sequentially from current entry:
   - On unconditional jump (`jmp target`): add `target` to queue; terminate current block.
   - On conditional branch (`jz`, `jnz`): add both branch target and fallthrough address to queue.
   - On `call target`: record `target` as a new function entry point; continue fallthrough.
   - On `ret` / `ret N`: terminate basic block and function.
3. **Boundary Calculation:**
   A function's extent is the span from its lowest basic block address to the
   highest return block, bounded by adjacent function entries.
