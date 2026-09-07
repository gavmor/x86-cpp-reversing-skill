# Tool recipes

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

## 9. Reversing a custom binary file-format loader (no vtables involved)

Not every 32-bit binary worth reversing has a C++ class hierarchy. Old game
engines in particular often implement subsystems (audio, save files, level
data) as **flat procedural C-style libraries** with a static globals block
instead of objects -- there's no vtable to walk, and `recon.py`'s vtable
recovery will (correctly) find nothing. When you need to recover a *custom
container/file format* the binary loads at runtime, the workflow is
different from class recovery:

1. **Find the load call site.** Grep strings/imports for the filename or
   extension (`izzj` in r2, or `strings <binary> | grep -i <ext>`), then
   `axt` (r2) or `nm`/xref-search the address to find what calls `open`/
   `CreateFileA`/`fopen` with that string.
2. **Watch for a thin wrapper hiding the real logic one call deeper.** MSVC
   binaries commonly wrap the interesting function in an SEH prologue
   (`mov eax, fs:[0]` / `push -1` / `push <exception handler addr>`) whose
   body is mostly a switch/jump-table translating an internal error code
   into user-facing strings (`"Can't open sound data file"`,
   `"Sound data file is corrupt"`, etc.) — the actual `open`/`read`/format
   validation happens in a callee this wrapper invokes once, near the top.
   Disassembling only the outer function and concluding "there's no real
   parsing logic here" is a common false negative; follow every `call` in a
   short wrapper before giving up on it.
3. **Read the validator like a spec, not just a function.** The real payoff
   function typically does, in order: `open()`, a small fixed-size `read()`
   for a magic/header, then comparisons against **hard-coded constants**
   (`cmp eax, 0x44d`) rather than trusting whatever the file says. Those
   constants ARE the format spec — a `cmp` against a literal right after a
   `read()` tells you a field's expected value and size far more reliably
   than inferring it from one sample file.
4. **A validation loop over a table tells you the table's true shape.**
   If you see a loop incrementing a pointer by a fixed stride and comparing
   `entry vs previous_entry` (monotonicity) or `entry & mask` (alignment),
   that loop's stride *is* the true per-entry size — which settles disputes
   a data-only inspection can't. E.g. a loop advancing by 4 bytes per
   iteration over what you assumed was an `{offset,size}` pair table (8
   bytes/entry) proves the assumption wrong: it's a flat single-`u32`-per-entry
   table, and the "size" you thought you saw was actually the next entry's
   offset.
5. **Re-verify data-driven hypotheses against the loader, don't just trust
   the last write-up.** If a bug was fixed based on an *empirical* pattern
   in the data (e.g. "these values are monotonic, so it must be a flat
   offset table") without re-disassembling the actual loader, treat that as
   a hypothesis, not ground truth, until you've traced it back to the
   validator itself — docs and commit messages claiming "confirmed against
   the binary" can be aspirational and go stale the moment nobody re-checks
   them against a later fix.

```bash
# generalized recipe used above (radare2):
r2 -q -c "aaa; s <wrapper_addr>; pdf" <binary>       # read the wrapper, find the real callee
r2 -q -c "aaa; s <callee_addr>; pdf" <binary>        # read the real validator
# strip ANSI color codes when saving output for repeated grep/sed passes:
r2 -q -c "aaa; s <addr>; pdf" <binary> | sed 's/\x1b\[[0-9;]*m//g' > /tmp/fn.txt
```

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
clean, directly-called symbol:

- **Thin wrapper.** Same pattern as section 9 -- an SEH/error-string wrapper
  may sit between the call sites you can find and the real access logic one
  call deeper. Follow every call in a short wrapper before treating it as
  "the" API.
- **Function-pointer slot indirection.** The real handler may be installed
  into a global fn-ptr slot at init time (`mov [slot], offset <fn>`) rather
  than called by name. If a symbol-based or `axt` xref sweep on the handler
  itself comes up empty, that's the tell: find every write to the slot first
  (`nm`/`objdump -s`/`r2 axt` on the slot address itself, not the function)
  to enumerate every handler ever installed there, then find where the slot
  is *read and called* (`call dword [<slot_addr>]`) -- that call instruction,
  not any function symbol, is the real fan-in point to sweep.
- **Inlined dispatch.** If the compiler inlined a small index-dispatch at
  every use site, there is no single "the API" function to xref. Sweep from
  the underlying data instead -- the table's base symbol or the offset
  computation pattern (`lea <reg>, [<index_reg>*<stride> + <table_base>]`) --
  rather than from a function that doesn't exist as a standalone symbol.
- **Indirect-pointer xref evasion (deliberate or not).** An xref sweep can
  come up empty even for a real, statically-computable target if the
  reference isn't a direct pointer: `mov eax, offset dummy_anchor` followed
  by `add eax, 0x100` reaches the real data, but a static xref tool
  (including IDA, not just this skill's usual tools) shows a reference only
  to `dummy_anchor`, never to the real target address (Yurichev, *Reverse
  Engineering for Beginners*, ch. 50.2.5). If a resource table or string you
  expect to be referenced has zero xrefs, check nearby code for an `add`/
  `lea` applied to an unrelated anchor symbol before concluding the
  reference doesn't exist in code at all.
- **Bloated-instruction xref evasion.** A direct `call`/`jmp` to a symbol is
  what static xref sweeps actually detect; substituting equivalent
  instruction sequences defeats this specifically: `jmp label` as
  `push label` / `ret`, or `call label` as `push return_addr` / `push
  label` / `ret` -- same runtime effect, but "IDA will not show the
  references to the label" (same source, ch. 50.2.2) because there's no
  `call`/`jmp` opcode pointing at it to find. If you see a `push` of what
  looks like a code address immediately followed by `ret`, treat it as a
  disguised `call`/`jmp` and resolve the target manually rather than relying
  on the xref sweep to have found it.
- **Virtual-call indirection (vtable dispatch).** Harder than the fixed
  fn-ptr-slot case above: a call like `call dword ptr [eax+14h]` dispatches
  through a *per-instance* vtable pointer, not one fixed global address --
  there's no single slot to sweep statically, since the target address is
  computed fresh from whatever object `eax` happens to be at runtime. Static
  disassemblers (including IDA, not just this skill's usual tools) generally
  do **not** create a cross-reference for this kind of call at all. See
  section 10.6's IDA/IDC vtable-xref script for a dynamic technique that
  resolves every real caller of every slot in a given vtable automatically.

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
case).** If you have IDA Pro, this fully automates recovering real callers
for every slot in a vtable, without writing a plugin. Select the vtable's
address range in the IDA view, run the script below (`File > IDC File...`,
or paste into the IDC command window with `Shift+F2`), then hit `Alt-F9`
and drive the target normally (play the game, exercise the feature) --
every indirect call through any slot in that range gets converted into a
real, permanent cross-reference:

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

How it works: `setBPs` walks the selected range in 4-byte steps (one vtable
slot per step), reading each slot's target function pointer with
`Dword(currAddr)`, and installs a software breakpoint on each target that's
conditional on `breakpointHandler()` -- returning `0` from a conditional
breakpoint handler means "don't actually stop," so this never interrupts
execution, it only runs code on every hit. `breakpointHandler` finds the
real caller by searching backward from the return address on the stack
(`PrevHead(Dword(ESP), Dword(ESP)-10)` -- an indirect call through a
register is only 3 bytes, so searching back 10 bytes is enough to land on
the actual `call` instruction) and calls `AddCodeXref` to record it as a
permanent, user-added cross-reference. Verified against a real MSVC binary
in the source: 26 real call sites recovered for a function that had zero
visible xrefs beforehand. (IOActive, *Reverse Engineering Code with IDA
Pro*, ch. 9, pp.213-220, "VTable xref Script," Figure 9.10.)

**Differential technique:** trigger one in-game event repeatedly (open the
same door, walk into the same water tile) and diff the captured index sets
across runs -- the index specific to that event is the one that shows up
every time, separable from ambient/background triggers that don't correlate
with the action.

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

## 11. WinDbg: dynamic analysis for native Windows PE binaries

Sections 7 and 10.6 use GDB throughout, but GDB only applies if the PE
target is running under something GDB can actually attach to (Wine, or a
Linux PE loader). A real Windows process needs a native Windows debugger --
WinDbg, CDB, NTSD, and KD all share the same underlying engine (DbgEng) and
the same command syntax, so the recipes below apply regardless of which
front end you're using. ("Debugging Tools for Windows" is the package name;
these are not part of Visual Studio.)

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
