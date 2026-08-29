# MSVC C++ ABI on 32-bit x86 (PE/COFF, `?`-mangled)

This is the ABI for binaries built by MSVC (`cl.exe`) -- symbols start with
`?` instead of `_Z`, and the binary is PE, not ELF. **`scripts/recon.py`
does not walk vtables/RTTI automatically for this ABI** -- the layout below
is accurate per public documentation, but unlike the Itanium path (which was
built against binaries we compiled and inspected byte-for-byte in this
environment), there's no MSVC toolchain available here to validate against.
Treat the offsets below as a strong starting hypothesis, not gospel -- verify
against the actual binary in front of you (e.g. by finding a known
non-virtual call, or by matching a vftable's slot count against how many
virtual functions the class visibly needs).

## Calling convention: `__thiscall`

Unlike Itanium's cdecl-with-`this`-on-the-stack, MSVC member functions
default to `__thiscall`: **`this` is passed in ECX**, remaining arguments go
on the stack (caller-cleans-up like cdecl, except the callee pops `this`
implicitly by virtue of it never having been pushed). So a call site for a
non-virtual member function typically looks like:

```
mov  ecx, <this>
push <arg2>
push <arg1>
call <ClassName::Method>
```

A **virtual** call additionally dereferences the vftable:

```
mov  ecx, <this>
mov  eax, [ecx]          ; load vptr
call [eax+<slot*4>]      ; dispatch through the vftable
```

If you see `ecx` loaded right before a call (direct or indirect), treat that
as a strong signal you're looking at a C++ member function call -- this is
the single most useful pattern-match for finding class boundaries in a
stripped MSVC binary.

## Name mangling

MSVC mangled names are much denser and less immediately readable than
Itanium's. Key markers to recognize without fully decoding:

| Marker | Meaning |
|---|---|
| `??0ClassName@@...` | Constructor |
| `??1ClassName@@...` | Destructor |
| `??_7ClassName@@6B@` | vftable (primary) |
| `??_8ClassName@@7B@` | vbtable (virtual base table, only with virtual inheritance) |
| `??_R0` | Type Descriptor (roughly analogous to Itanium's `_ZTS`+part of `_ZTI`) |
| `??_R1` | Base Class Descriptor |
| `??_R2` | Base Class Array |
| `??_R3` | Class Hierarchy Descriptor |
| `??_R4ClassName@@6B@` | Complete Object Locator |

There's no single universal demangler as reliable as `c++filt` here. If
`llvm-cxxfilt` or `msvc-demangler`-style tooling isn't available, radare2's
`rz-bin`/`r2 -B` and IDA/Ghidra both understand MSVC mangling; failing that,
work from the marker table above and treat the rest of the mangled string as
an opaque identifier while you build the class model from structure alone.

## Vftable layout

Simpler than Itanium in one respect: **no offset-to-top header word for the
primary vftable** -- the exported `??_7ClassName@@6B@` symbol points
directly at slot 0:

```
sym.value + 0   vfunc slot 0   <-- this IS what's stored in the object's vptr,
sym.value + 4   vfunc slot 1       no +8 adjustment like Itanium
sym.value + 8   vfunc slot 2
...
```

Immediately **before** the vftable (at `sym.value - 4`), when RTTI is
enabled (`/GR`, the default), sits a pointer to a **Complete Object
Locator** (`??_R4...`) rather than directly to a type_info -- this is one
level more indirect than Itanium:

```
CompleteObjectLocator {
    DWORD signature;             // 0 on x86 (non-zero encodes image-relative on x64, doesn't apply to 32-bit)
    DWORD offset;                // this vftable's offset within the complete object
    DWORD cdOffset;
    TypeDescriptor* pTypeDescriptor;        // -> the RTTI type name, analogous to _ZTI's name field
    ClassHierarchyDescriptor* pClassDescriptor;  // -> base class graph, analogous to __vmi_class_type_info's base array
}
```

`ClassHierarchyDescriptor` has a `numBaseClasses` count and a pointer to an
array of `BaseClassDescriptor`, each carrying an offset and attribute flags
(virtual/non-virtual, similar spirit to Itanium's `offset_flags` but a
different bit layout) -- this is the part to treat as "verify by hand"
before relying on any specific decoded offset value.

## Multiple/virtual inheritance

Same high-level idea as Itanium (a derived class can have multiple vftables,
one per base with virtual functions, each reached through a different
"this adjustment"), but MSVC represents the adjustment differently: for
**virtual inheritance**, objects carry a **vbtable pointer** in addition to
the vftable pointer, and accessing a virtual base requires an extra
indirection through the vbtable to find that base's offset (which can vary
per most-derived type, unlike Itanium's fixed non-virtual thunks). If you
see a load through something that looks like a second vtable-like pointer
before reaching a base member, that's the vbtable pattern -- don't assume
it's a second vftable.

## Manual recipe (no automated tooling here)

1. `objdump -d --no-show-raw-insn -M intel <file>.exe` for disassembly, or
   load into radare2 (`r2 -A <file>.exe`) if you want function boundaries
   and xrefs for free.
2. `objdump -x <file>.exe | grep -i '??_7\|??_R4'` (or equivalent PE symbol
   dump) to enumerate vftables and complete object locators, if the binary
   isn't stripped. Stripped release PE binaries are common -- if there's no
   symbol table, you're identifying vftables purely by the "array of
   in-`.text`-pointers referenced by a constructor's `mov [ecx], offset X`"
   pattern instead, the same way you would for a stripped Itanium binary.
3. Use `mov [ecx], offset <addr>` in constructors (the direct MSVC analog of
   the Itanium vptr-store pattern) to identify which vftable belongs to
   which constructor, and thus which class.
4. Confirm with GDB dynamically if static confidence is low: break at the
   constructor, watch the store to `[ecx]`, and dump the resulting vftable's
   slots the same way described in `itanium-abi.md`'s dynamic section --
   the technique transfers directly, only the offsets differ.
