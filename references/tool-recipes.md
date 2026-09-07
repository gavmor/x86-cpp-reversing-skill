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

### 10.2 Enumerate call sites

```bash
r2 -q -c "aaa; axt @ <api_addr>" <binary>            # who calls/reads this address
r2 -q -c "aaa; axt @ <slot_addr>" <binary>           # for the fn-ptr-slot case: who writes AND who reads the slot
objdump -d -M intel <binary> | grep -B2 'call.*<api>' # binutils fallback: literal push before call
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
   memory load.
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
disruptive, an inline hook that logs the same tuple to a file without
stopping execution is a viable lower-overhead alternative -- game-modding
toolkits built around AOB (array-of-bytes) signature scanning plus inline
hooking exist specifically for this pattern: scan for the call site's byte
signature, install a hook that logs and calls through, then play normally.
(`tkhquang/DetourModKit` implements this well -- `StringXref`/
`xref_broad_match` for anchor-based call-site discovery, `mid_at()` for a
logging-then-continuing mid-function hook -- but it's a **Windows x64**
toolkit; treat it as a reference for the pattern, not a tool to run directly
against a 32-bit target. Port the AOB-scan-plus-mid-hook idea rather than the
library itself.)

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
