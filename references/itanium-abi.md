# Itanium C++ ABI on 32-bit x86 (GCC/Clang, Linux/BSD/etc, `_Z`-mangled)

*Objective: Performance, Robustness · Target: Assembly Code* (Hu et al.,
*SoK: Potentials and Challenges of LLMs for Reverse Engineering*, taxonomy
-- see `AGENTS.md`'s design-rationale section for what these mean here.)

This is the ABI you're dealing with any time symbols demangle with `c++filt`
and start with `_Z` (e.g. `_ZN3Dog5speakEv`). `scripts/recon.py` automates
most of what's below -- read this when you need to sanity-check its output,
go past what it reports, or work by hand because it isn't available.

## Calling convention

Member functions are plain `cdecl`: `this` is passed as an implicit **first
stack argument**, pushed last (right-to-left along with everything else).
There is no register-based "thiscall" on Linux x86-32 the way there is on
Windows -- if you see `this` show up in a register instead of on the stack,
you're either looking at an optimized build that promoted it, or you're
actually looking at an MSVC binary (see `msvc-abi.md`).

## Name mangling cheat sheet

Don't hand-decode these -- run `c++filt -n <symbol>` or the mangled name
through `scripts/recon.py`. But knowing the prefixes tells you what a symbol
*is* before you demangle it:

| Prefix | Meaning |
|---|---|
| `_ZN...C1Ev` | Complete-object constructor |
| `_ZN...C2Ev` | Base-object constructor (used when this class is itself a base) |
| `_ZN...D1Ev` | Complete-object destructor (called via `delete obj` when `obj`'s static type matches) |
| `_ZN...D0Ev` | Deleting destructor (destructor + `operator delete`; this is what's actually in the vtable for polymorphic deletes through a base pointer) |
| `_ZN...D2Ev` | Base-object destructor (no delete, used as a sub-object) |
| `_ZTV<name>` | Vtable (or vtable *group*, for MI -- see below) |
| `_ZTI<name>` | typeinfo structure |
| `_ZTS<name>` | typeinfo name string (raw mangled class name, no length prefix issues) |
| `_ZTT<name>` | VTT (construction vtable table) -- only appears with virtual inheritance |
| demangled `non-virtual thunk to X` | Adjusts `this` by a fixed offset before jumping to `X` -- see MI section |
| demangled `virtual thunk to X` | Adjusts `this` using a *vcall offset* read from the vtable at runtime -- appears with virtual inheritance |

## Vtable layout (single inheritance, the simple case)

The **exported symbol** `_ZTV<Class>` points to the start of a small header,
not directly at the function pointers:

```
sym.value + 0   offset-to-top      (ptrdiff_t, usually 0 for single inheritance)
sym.value + 4   pointer to typeinfo structure for this class
sym.value + 8   vfunc slot 0   <-- this address is what actually gets
sym.value + 12  vfunc slot 1       written into an object's vptr field
sym.value + 16  vfunc slot 2
...
```

So when you're looking at a constructor and see `mov [eax], offset X`
storing a vtable pointer into the object, `X` will be `sym.value + 8`, not
`sym.value`. This trips people up when they go looking for `X` in the symbol
table and don't find an exact match -- it's `_ZTV<Class>` plus 8.

`sym.size` (the ELF symbol's `st_size`) is normally accurate and tells you
exactly how many bytes the whole vtable group occupies -- trust it over
guessing where the slots end.

## Multiple inheritance: the vtable is a *group* of sub-vtables

When a class has more than one base with virtual functions (like `Duck :
public Flyer, public Swimmer`), the compiler doesn't emit two separate
`_ZTV` symbols for the derived class -- it emits **one symbol** whose data
is actually several `[offset-to-top][typeinfo][vfuncs...]` segments placed
back to back: one primary segment (for the first base / most-derived
combined view) and one secondary segment per additional base.

`scripts/recon.py` reports every word after the primary slots and classifies
each as either a resolved function pointer (`kind: "vfunc"`) or a
`marker_or_secondary_header` when the word isn't a code address -- that's
your cue that you've hit the next segment's offset-to-top/typeinfo pair.
Concretely, for `Duck` (`Flyer` primary, `Swimmer` secondary at object
offset +4), the tool reports something like:

```
offset 0-8:   Duck::fly, Duck::~Duck, Duck::~Duck        <- primary segment (Flyer view)
offset 16:    marker (raw -4)                             <- secondary offset-to-top
offset 20:    marker (typeinfo ptr)                       <- secondary typeinfo
offset 24-32: non-virtual thunk to Duck::swim/~Duck/~Duck  <- secondary segment (Swimmer view)
```

The **secondary offset-to-top being -4** means: if you have a `Swimmer*`
that actually points at (this_addr) inside a `Duck`, subtracting 4 gets you
back to the real `Duck*`. That's exactly what the `non-virtual thunk to
Duck::swim()` does at the assembly level -- `sub $4, this; jmp Duck::swim`.
If you see a thunk like this, you're looking at multiple inheritance and the
adjustment constant tells you the sub-object's offset within the derived
class layout.

## Virtual inheritance: extra words before offset-to-top, and `virtual thunk to`

Everything above assumes no virtual bases anywhere in the hierarchy. The
moment one shows up -- even transitively, like `class Joined : public Left,
public Right` where `Left`/`Right` each do `class Left : public virtual
Base`, so `Joined` itself never writes the word "virtual" but still shares
one `Base` sub-object with `Right` -- two things change:

1. **The primary segment's `[offset-to-top][typeinfo]` pair is no longer
   necessarily at `sym.value`/`sym.value+4`.** One or more *vbase-offset*
   words get prepended first (one per virtual base reachable from this
   vtable). `scripts/recon.py` handles this by scanning forward for the
   word that resolves to this class's own `_ZTI` symbol -- the word right
   before it is always offset-to-top, by ABI invariant, regardless of how
   many prefix words came first. Those prefix words are reported verbatim
   as `prefix_words` in the JSON; treat them as evidence virtual inheritance
   is present rather than trying to hand-decode their exact values.
2. **A base marked `is_virtual: true` in the RTTI base list does NOT carry
   its object byte-offset the way a non-virtual base does.** The packed
   value (`vbase_offset_field` in `scripts/recon.py`'s output) is instead an
   offset *into the derived class's own vtable* -- you'd add it to that
   vtable's address and read a word there to get the actual offset, which
   can differ per most-derived type. Don't treat it as a direct offset.

You'll also see a third dispatch mechanism alongside plain function pointers
and `non-virtual thunk to X`: **`virtual thunk to X`**, which (unlike the
fixed-constant non-virtual thunk) reads its `this`-adjustment out of a vcall
offset stored in the vtable at runtime instead of hard-coding it -- necessary
because, with a shared virtual base, the right adjustment can vary depending
on the complete object's actual layout, not just on which class you're
starting from. If both `non-virtual thunk to` and `virtual thunk to` entries
point at the same underlying function, you're looking at a diamond-shaped
hierarchy (a shared virtual base being reached two different ways).

## RTTI structures (what `_ZTI<Class>` points to)

Three possible layouts, distinguished by which ABI vtable the structure's
own first field points to (this is exactly what `scripts/recon.py`'s
`classify_typeinfo_kind` does for you):

- **`__class_type_info`** (no bases) -- just `{vtable_ptr, name_ptr}`. Used
  for classes with no base classes at all (or that don't need bases
  reflected, rare).
- **`__si_class_type_info`** (single, public, non-virtual base) --
  `{vtable_ptr, name_ptr, base_type_info_ptr}`. The common case for simple
  `class Derived : public Base`.
- **`__vmi_class_type_info`** (multiple bases, or a virtual/non-public base)
  -- `{vtable_ptr, name_ptr, flags, base_count, [{base_type_info_ptr,
  offset_flags}, ...]}`. `offset_flags` packs the base's offset in the
  upper bits and two flag bits at the bottom: bit 0 = base is virtual, bit 1
  = base is public. `scripts/recon.py` decodes this for you (`is_virtual`,
  `is_public`, `offset` fields).

**Cross-DSO pointers**: `__class_type_info`/`__si_class_type_info`/
`__vmi_class_type_info` themselves live in `libstdc++`, not your binary. In
a dynamically-linked (especially PIE) binary, the raw bytes at those pointer
fields are *not* usable addresses -- they're relocation placeholders. You
must resolve them via the relocation table (`readelf -r`, or
`lief`'s `binary.relocations`), not by reading memory directly.
`scripts/recon.py`'s `resolve_pointer()` already does this; if you're doing
it by hand, don't be fooled by a typeinfo pointer field that reads as `0x8`
or some other tiny value -- that's the addend (`+8`, the same "vptr is 8
bytes into the vtable group" convention applied to the ABI's own vtable),
and the real target comes from the relocation's symbol name.

## Gotcha: abstract classes can have null vtable slots

If a class has a pure virtual function (`virtual void f() = 0;`), its own
vtable's slot for `f` legitimately points at `__cxa_pure_virtual` (a stub
that aborts if ever called). But slots for a *virtual destructor* in an
**abstract** class's own vtable can be emitted as literal null (no pointer,
no relocation) even though the destructor function exists and has a real
address elsewhere in `.text` -- because you can never construct that exact
type, so the compiler considers that vtable slot theoretically unreachable
and doesn't bother filling it in. Don't read a null slot in an abstract
base's vtable as "corrupted binary" or "missing destructor" -- check whether
the class has a pure virtual member before assuming something's wrong.

## A more rigorous vtable-identification rule set (VPS)

`scripts/recon.py` and the manual `nm`/`objdump` recipes in
`references/tool-recipes.md` find vtables the common-case way (symbol names,
or scanning `.rodata`/`.data.rel.ro`). VPS (Pawlowski et al., ACSAC 2019,
§4.1) built a more exhaustive rule set for the same problem as part of a
binary-level CFI defense, and it's worth knowing the edge cases it names
even when you're doing this by hand rather than running their tool:

- **Vtables aren't always in the main binary's own sections.** If a base
  class lives in another module, the loader **copy-relocates** the vtable
  data into `.bss`; if referenced through position-independent code, the
  reference may go through the **GOT** instead of pointing at the vtable
  directly. Grepping only `.rodata`/`.data.rel.ro` will silently miss both
  cases.
- **The vtable reference doesn't always point at slot 0.** Some compiled
  code references the *metadata* field at `vtable - 0x10` (or `-0x18` under
  virtual inheritance) instead of the first function entry -- common in PIC
  -- and then adds `0x10`/`0x18` back before use. If a "vtable pointer"
  candidate is 0x10 or 0x18 bytes off from where you expect slot 0, check
  for this adjustment before concluding it's the wrong address.
- **Offset-to-top has a validated sane range: `[-0xFFFFFF, 0xFFFFFF]`.** A
  candidate header value outside that range is not a real offset-to-top
  field -- useful as a concrete sanity check when you're not sure a
  candidate address is actually a vtable header.
- **The RTTI pointer field is optional, not always present.** It's usually
  omitted by the compiler; when present for a class inheriting from another
  module, it may be a relocation entry rather than a direct pointer into
  `.data`.
- **Copy relocation + multiple inheritance is a real edge case worth
  knowing about, not just a theoretical one.** The loader's copy relocation
  only records where the copied chunk *starts* and how long it is -- it
  doesn't separately mark each sub-vtable's boundary within that chunk. If
  you know the chunk is `N` bytes copied to address `A`, every 8-byte-aligned
  address (4-byte-aligned on 32-bit x86, per VPS's own note on porting to
  that architecture) from `A` to `A+N` is a *candidate* vtable/sub-vtable --
  over-approximating and then discarding the ones that don't validate is
  the correct approach, not assuming only `A` itself matters.

If symbols are stripped, break at a suspected constructor and watch what
gets written to `[this]`:

```
(gdb) break *0x<ctor_addr>
(gdb) run
(gdb) watch *(int*)$eax   # or whichever register holds `this`
(gdb) continue            # stops right after the vptr store
(gdb) x/1xw $eax          # the stored vptr value == vtable_addr + 8
(gdb) x/8xw <that value>-8   # dump the vtable group: offset-to-top, typeinfo, slots...
```

If a derived class's constructor runs after a base's, you'll see the vptr
written **twice** for the same object -- once by the base ctor (pointing at
the base's vtable) and then overwritten by the derived ctor (pointing at the
derived vtable). That double-write is itself strong static/dynamic evidence
of an inheritance relationship even before you've found the vtables.
