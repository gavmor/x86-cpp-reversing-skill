# MSVC C++ ABI Reference (32-bit x86, PE format)

Targeting 32-bit x86 Windows binaries compiled by Microsoft Visual C++.
Ground truth synthesized from:
- Paul Sabanal and Mark Yason, *"Reversing C++"* (Black Hat DC 2007)
- CMU SEI Pharos / OOAnalyzer (`libpharos/datatypes.hpp`, `share/prolog/oorules/rtti.pl`)
- Bruce Dang, Alexandre Gazet, Elias Bachaalany, Sebastien Josse, *Practical Reverse Engineering* (Wiley 2014)
- Dennis Yurichev, *Reverse Engineering for Beginners* (ch. 51.1.1)

## Calling convention: `__thiscall`

Unlike Itanium's cdecl-with-`this`-on-the-stack, MSVC member functions
default to `__thiscall`: **`this` is passed in ECX**, remaining arguments go
on the stack pushed right-to-left. The callee cleans up stack arguments via
`ret N`, while `this` in ECX is implicitly popped because it was never pushed.

A non-virtual member call:
```asm
mov  ecx, <this>
push <arg2>
push <arg1>
call <ClassName::Method>
```

A **virtual** call dereferences the vftable:
```asm
mov  ecx, <this>
mov  eax, [ecx]          ; load vptr (at offset 0 of object)
call [eax + <slot*4>]    ; dispatch through vftable slot
```

**Key Constructor / Destructor Identifiers:**
- **Constructors return `this` in EAX:** A standard MSVC constructor ends with
  `mov eax, ecx` (or `mov eax, [ebp-X]` where `this` was spilled). In OOAnalyzer
  terms, this fact is `returnsSelf(Method)`.
- **Top-of-function vptr store:** Constructors stamp the object's vptr immediately
  after base construction: `mov dword ptr [esi], offset ??_7ClassName@@6B@`.
- **Order of execution:** Base constructors run before derived constructors;
  derived destructors run before base destructors.

## Name mangling

MSVC mangled names start with `?`. Key markers to recognize without a demangler:

| Marker | Meaning |
|---|---|
| `??0ClassName@@...` | Constructor |
| `??1ClassName@@...` | Destructor |
| `??_7ClassName@@6B@` | vftable (primary) |
| `??_8ClassName@@7B@` | vbtable (virtual base table, used with virtual inheritance) |
| `??_R0` | Type Descriptor (`type_info` equivalent, starts with `.?AV...`) |
| `??_R1` | Base Class Descriptor |
| `??_R2` | Base Class Array |
| `??_R3` | Class Hierarchy Descriptor |
| `??_R4ClassName@@6B@` | Complete Object Locator |

Demangling tools: `undname` (Visual Studio), `llvm-cxxfilt`, or radare2 (`rz-bin -B`).
In stripped binaries without symbols, you recover the names directly from the
ASCII strings embedded inside `TypeDescriptor` (see below).

## Vftable layout & Complete Object Locator (COL)

The exported `??_7ClassName@@6B@` symbol points directly at slot 0:

```
[sym.value - 4] -> CompleteObjectLocator (??_R4...)
[sym.value + 0]    vfunc slot 0   <-- Object's vptr points directly here
[sym.value + 4]    vfunc slot 1
[sym.value + 8]    vfunc slot 2
...
```

Unlike Itanium (which has an offset-to-top header and a direct pointer to
`type_info` at `vptr - 4`), MSVC places a pointer to an **RTTICompleteObjectLocator**
at `vptr - 4`.

```c
struct RTTICompleteObjectLocator {
    DWORD signature;             // 0 on 32-bit x86 (1 on x64 indicating image-relative RVAs)
    DWORD offset;                // Offset of this vftable pointer relative to complete object start
    DWORD cdOffset;              // Constructor displacement offset (usually 0)
    TypeDescriptor* pTypeDescriptor;           // -> TypeDescriptor (?AVClassName@@)
    RTTIClassHierarchyDescriptor* pClassDesc;  // -> ClassHierarchyDescriptor
};
```

### TypeDescriptor (`??_R0`)

```c
struct TypeDescriptor {
    const void* pVFTable;        // -> type_info::`vftable` (in CRT / msvcr*.dll)
    DWORD spare;                 // Internal runtime scratch / reserved (0)
    char name[...];              // Null-terminated mangled class name (e.g. ".?AVbox@@")
};
```
The ASCII name always starts with `.?AV` (for classes/structs) or `.?AU` (for interfaces).

### ClassHierarchyDescriptor (`??_R3`)

```c
struct RTTIClassHierarchyDescriptor {
    DWORD signature;             // 0 on 32-bit x86
    DWORD attributes;            // Bit flags:
                                 //   0x1: Multiple inheritance
                                 //   0x2: Virtual inheritance
                                 //   0x4: Ambiguous base classes
    DWORD numBaseClasses;        // Count of descriptors in pBaseClassArray
    RTTIBaseClassArray* pBaseClassArray; // -> Array of pointers to BaseClassDescriptor
};
```

### BaseClassDescriptor (`??_R1`) and `_PMD`

```c
struct PMD {
    int mdisp;                   // Member displacement (offset of base subobject in class)
    int pdisp;                   // Offset of vbtable pointer within subobject (-1 if non-virtual)
    int vdisp;                   // Offset within vbtable to virtual base displacement value
};

struct RTTIBaseClassDescriptor {
    TypeDescriptor* pTypeDescriptor;           // -> Base class TypeDescriptor
    DWORD numContainedBases;                   // Number of sub-bases underneath this base
    struct PMD where;                          // Displacement specification { mdisp, pdisp, vdisp }
    DWORD attributes;                          // Bit flags:
                                               //   0x20: Virtual base class
                                               //   0x40: pClassDescriptor pointer is present
    RTTIClassHierarchyDescriptor* pClassDesc;  // OPTIONAL: only present if (attributes & 0x40)
};
```

> [!NOTE]
> **Source-verified structure note (Pharos / Sabanal & Yason):**
> Older disassembly transcriptions (e.g. Yurichev ch. 51) sometimes show 7 DWORDs
> for a BaseClassDescriptor while others show 6. As verified in Pharos
> (`libpharos/datatypes.hpp`), the 7th field (`pClassDescriptor`) is optional:
> it is present if and only if `attributes & 0x40` is set.

### BaseClassArray (`??_R2`)

`RTTIBaseClassArray` is simply a flat array of 32-bit virtual addresses pointing to
`RTTIBaseClassDescriptor` structures for the class itself and every base in its
inheritance closure.

## The Self-Referencing Validation Invariant (`rTTISelfRef`)

As formalized in OOAnalyzer (`share/prolog/oorules/rtti.pl`), valid MSVC RTTI
forms a closed circular loop that you can use to verify recovered vtables with
100% confidence:

```
[vftable - 4] ──────> RTTICompleteObjectLocator
                         │             │
        ┌────────────────┘             └────────────────┐
        ▼                                               ▼
  TypeDescriptor                            ClassHierarchyDescriptor
   ("?AVDerived@@")                                     │
        ▲                                               ▼
        │                                        BaseClassArray
        │                                               │
        │ [0] (first element)                           ▼
        └─────────────────────────────────── BaseClassDescriptor (self)
                                              where = { mdisp: 0, pdisp: -1, vdisp: 0 }
```

In any primary vftable:
1. `CompleteObjectLocator.pTypeDescriptor` points to class $C$'s `TypeDescriptor`.
2. `CompleteObjectLocator.pClassDesc` points to $C$'s `ClassHierarchyDescriptor`.
3. `ClassHierarchyDescriptor.pBaseClassArray[0]` points to $C$'s own `BaseClassDescriptor`.
4. That `BaseClassDescriptor.pTypeDescriptor` points back to the identical `TypeDescriptor` from step 1, with displacement `{ mdisp: 0, pdisp: -1, vdisp: 0 }`.

If this loop holds, you have definitively identified the primary vftable and class name.

## Virtual Inheritance & `vbtable` (`??_8`)

When a class virtually inherits from a base (`class D : virtual public B`), MSVC does
not use Itanium-style negative vtable offsets. Instead:
1. Every instance contains a **virtual base table pointer** (`vbp`, or `vbtable` ptr)
   at a known offset in the object layout.
2. The `vbtable` (`??_8ClassName@@7B@`) is an array of 32-bit signed integers:
   - **Entry 0:** Displacement from the `vbp` back to the start of the subobject containing the `vbp` (typically 0 or negative).
   - **Entry $N$ ($N \ge 1$):** Displacement from the `vbp` to the $N$-th virtual base subobject.

### Assembly Pattern for Virtual Base Access (`_PMD` evaluation)

When code accesses a member of a virtual base, the compiler emits a two-step displacement:
```asm
; Given this in ECX, access virtual base at vbtable offset 4:
mov  eax, [ecx]          ; Load vbtable pointer (or [ecx + pdisp])
mov  edx, [eax + 4]      ; Read displacement to virtual base (vdisp = 4)
lea  eax, [ecx + edx]    ; eax = adjusted this pointer for virtual base
mov  eax, [eax + 0x10]   ; Read member at offset 0x10 within virtual base (mdisp)
```

## Recovery Algorithm for Stripped Binaries (No Symbols)

When symbols are stripped from a PE binary, follow this automated scanning algorithm:

1. **Find TypeDescriptors:**
   Scan `.rdata` for ASCII strings starting with `.?AV` or `.?AU`.
   Backtrack 8 bytes from the string address (`sizeof(void*) + sizeof(DWORD)`) to
   find the base address of the `TypeDescriptor`.
2. **Find CompleteObjectLocators:**
   Search `.rdata` for 32-bit DWORDs whose value equals the `TypeDescriptor` address.
   Inspect candidates: check if `signature == 0` at offset `-12` (relative to the pointer)
   and if the following DWORD points to a valid `.rdata` address (`pClassDescriptor`).
3. **Find Vftables:**
   Search `.rdata` for 32-bit DWORDs whose value equals the `CompleteObjectLocator` address.
   The address immediately following that pointer (`addr + 4`) is **slot 0 of the vftable**.
4. **Enumerate Virtual Functions:**
   Read sequential 32-bit words starting at slot 0 until reaching a word that does NOT
   point into the `.text` executable code section, or reaches the next COL pointer (`-4`).
5. **Reconstruct Inheritance:**
   Dereference `pClassDesc` $\rightarrow$ read `numBaseClasses` $\rightarrow$ walk
   `pBaseClassArray` to enumerate every base class name and displacement `{ mdisp, pdisp, vdisp }`.

## Worked Manual Disassembly Example

From Yurichev (*Reverse Engineering for Beginners*, ch. 51.1.1), MSVC 2008 `/FAs` listing
for single-inheritance (`class box : public object`):

```asm
; BaseClassDescriptor for box
??_R1A@?0A@EA@box@@8:
    DD FLAT:??_R0?AVbox@@@8      ; pTypeDescriptor -> ".?AVbox@@"
    DD 01H                       ; numContainedBases = 1
    DD 00H                       ; where.mdisp = 0
    DD 0ffffffffH                ; where.pdisp = -1 (not virtual)
    DD 00H                       ; where.vdisp = 0
    DD 040H                      ; attributes = 0x40 (pClassDescriptor present)
    DD FLAT:??_R3box@@8          ; pClassDescriptor -> ClassHierarchyDescriptor

; BaseClassArray for box (self, then base)
??_R2box@@8:
    DD FLAT:??_R1A@?0A@EA@box@@8    ; -> box BaseClassDescriptor
    DD FLAT:??_R1A@?0A@EA@object@@8 ; -> object BaseClassDescriptor

; ClassHierarchyDescriptor for box
??_R3box@@8:
    DD 00H                       ; signature = 0
    DD 00H                       ; attributes = 0 (single inheritance)
    DD 02H                       ; numBaseClasses = 2 (box + object)
    DD FLAT:??_R2box@@8          ; pBaseClassArray

; CompleteObjectLocator for box
??_R4box@@6B@:
    DD 00H                       ; signature = 0
    DD 00H                       ; offset = 0
    DD 00H                       ; cdOffset = 0
    DD FLAT:??_R0?AVbox@@@8      ; pTypeDescriptor -> ".?AVbox@@"
    DD FLAT:??_R3box@@8          ; pClassDescriptor

; Vftable for box
??_7box@@6B@:
    ; (at ??_7box@@6B@ - 4 sits FLAT:??_R4box@@6B@)
    DD FLAT:?area@box@@UAENXZ    ; slot 0: virtual double box::area(void)
    DD FLAT:?volume@box@@UAENXZ  ; slot 1: virtual double box::volume(void)
```
