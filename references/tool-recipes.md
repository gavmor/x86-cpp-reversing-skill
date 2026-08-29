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
