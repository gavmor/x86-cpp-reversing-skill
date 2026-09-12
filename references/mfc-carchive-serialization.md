# MFC `CArchive` Serialization Mechanics (32-bit x86, PE format)

*Objective: Discovery · Target: Raw Bytes and Assembly Code* (see
`AGENTS.md`'s design-rationale section for what these mean here.)

Scope: MFC's own polymorphic object-serialization protocol
(`CObject::Serialize`, `CArchive::ReadObject`/`WriteObject`,
`IMPLEMENT_SERIAL`, `CRuntimeClass`). This is **not** part of the core
Itanium/MSVC C++ ABI covered by `references/itanium-abi.md` and
`references/msvc-abi.md` -- it's a separate, hand-rolled reflection and
versioned-serialization system that Microsoft's MFC library layers on top
of ordinary C++ classes. When a Windows binary uses `CArchive` to load a
custom container format, the container's *field layout inside each
class's `Serialize()`* is genuinely bespoke and has to be recovered the
way section 9/13 already describe -- but the *wrapper protocol carrying
those fields* (how the archive knows which class to construct next, how
it avoids repeating a class's full type info for every instance) is a
known, fixed, non-bespoke format. Treating the wrapper as part of the
unknown format wastes effort; this file exists so you don't.

Ground truth for everything below was read directly from real MFC source
(a public mirror of the shipped MFC source tree used to build classic
Visual Studio's MFC libraries: `arcobj.cpp`, `arccore.cpp`, `objcore.cpp`,
`afx.h`), not inferred or guessed.

## The `CRuntimeClass` struct -- MFC's own RTTI, and it's directly walkable

```c
struct CRuntimeClass {
    const char*      m_lpszClassName;   // literal ASCII class name, e.g. "CCompressedObjectTexture"
    int              m_nObjectSize;     // sizeof(the class)
    UINT             m_wSchema;         // schema number (in-memory: 4 bytes) -- see the on-disk/in-memory
                                        // size mismatch warning below
    CObject* (PASCAL *m_pfnCreateObject)();  // "new ClassName()" stub, NULL for an abstract class
    // the next field's type depends on how MFC was linked into this binary -- check first:
    CRuntimeClass*   m_pBaseClass;      // statically-linked MFC: a DIRECT pointer to the base
                                        // class's own CRuntimeClass, fixed at compile time
    // CRuntimeClass* (PASCAL *m_pfnGetBaseClass)();  // _AFXDLL (MFC42.DLL etc.) build: a FUNCTION
                                        // pointer instead -- one more call to trace, not a direct read
    CRuntimeClass*   m_pNextClass;      // linked-list pointer; 0 in the file at rest, populated by a
                                        // static initializer before WinMain() -- see below
};
```

**Check which layout you have before reading anything from this struct**:
scan the import table for `MFC42.DLL`/`MFC42U.DLL`/`MFC7x.DLL`/etc. If none
are imported, MFC is statically linked into the binary and `m_pBaseClass`
is a plain data pointer -- the entire class hierarchy is then readable
straight out of `.rdata`/`.data` with **no disassembly and no runtime
execution at all**, because `RUNTIME_CLASS(base_class_name)` expands to
`&base_class_name::classbase_class_name`, a compile-time-constant address
baked directly into the struct's static initializer. If an MFC DLL *is*
imported, that field is instead a function pointer (`_GetBaseClass()`) --
only one instruction (`ret RUNTIME_CLASS(base)`) but it does require
reading the function rather than dereferencing a field.

**A concrete offset trap, worth flagging given this project's own
already-confirmed off-by-one bug:** `m_wSchema` is a `UINT` (4 bytes) in
this in-memory struct, but the *on-disk* schema number written by
`CRuntimeClass::Store` is a `WORD` (2 bytes) -- see the wire format below.
Don't let one size assumption bleed into the other; they are genuinely
different widths at two different layers of the same system.

## Enumerating every serializable class statically, without running anything

`IMPLEMENT_SERIAL(class_name, base_class_name, wSchema)` expands to
(among other things) a hidden global object:

```c
AFX_CLASSINIT _init_##class_name(RUNTIME_CLASS(class_name));
```

`AFX_CLASSINIT`'s constructor calls a single fixed function,
`AfxClassInit(CRuntimeClass* pNewClass)`, which prepends `pNewClass` onto
a global list (`AfxGetModuleState()->m_classList`, a plain global for a
statically-linked binary). Every `IMPLEMENT_SERIAL`'d class in the binary
therefore has, as a C++ static/global object, a constructor call to
`AfxClassInit` somewhere in the pre-`main`/pre-`WinMain` static-initializer
sequence -- the same "constructor runs before `main`" tell
`references/msvc-abi.md` already uses for identifying global-object
constructors generally.

| Step | Action | Checkpoint |
|---|---|---|
| 1 | Find one call site to `AfxClassInit` (any `CRuntimeClass*` you've already identified via `LoadObject`/`Serialize` tracing will have one) | A `call AfxClassInit`/`call sub_XXXXXX` instruction with a single pushed argument, sitting in the static-init call chain before the program's real entry logic |
| 2 | `axt`/xref-sweep every call to that same function address | A list of call sites, one per registered serializable class -- this is a closed, finite set, not a sample |
| 3 | For each call site, read the single pushed argument -- that address is a `CRuntimeClass*` | Dereference it with the struct layout above and get a real class name string back |
| **Exit** | Every serializable class in the binary, with name + schema + object size + base class, from one xref sweep | Cross-check count against however many `LoadObject`/`Serialize` call sites you'd found manually -- a mismatch means you missed some classes doing it by hand |

This turns "trace `LoadObject` call by call as you happen to encounter each
class" into "read one finite table" -- the direct MFC analog of walking
Itanium/MSVC RTTI structures instead of inferring a class hierarchy from
scattered vtable reads.

## The on-disk wire format (from `CRuntimeClass::Store`/`Load`, `CArchive::ReadClass`/`WriteClass`)

A class is only fully described in the archive **the first time** any
instance of it is serialized; every later instance of the same class
references it by a small index instead. Concretely, immediately before an
object's own `Serialize()` data:

```
WORD  tag
  0x0000            NULL pointer (no object follows)
  0x0001 - 0x7FFE    back-reference: index of an object already read/written
  0x7FFF            "big tag" marker -- a DWORD tag follows instead of fitting in this WORD
  0x8001 - 0xFFFE    back-reference: index of a CLASS already seen (high bit set == class, not object)
  0xFFFF            brand-new class definition follows (CRuntimeClass::Load/Store below)

# only present when tag == 0xFFFF:
WORD  schema_number        # NOTE: 2 bytes on disk, vs. 4-byte UINT in the in-memory struct
WORD  name_length
BYTE  class_name[name_length]   # raw ASCII, NOT null-terminated in the file
```

So a fresh `.E3`/archive-style file's very first object of a given class
looks like: `FF FF` (new-class tag) · schema (2 bytes, LE) · name length (2
bytes, LE) · the literal class name as ASCII (e.g. `CCompressedObjectTexture`)
-- then whatever that class's own `Serialize()` writes.

**This means every class name that actually appears in a real archive file
is a plain, greppable ASCII string in that file, independent of anything
in `ESOTERIA.EXE`.** Scanning real `.E3` samples for the byte pattern `FF
FF` followed by a plausible schema WORD, a small length WORD, and that
many bytes of printable ASCII starting with `C` recovers, per file, every
class actually used in it -- zero disassembly, and it directly
cross-checks the class list recovered from the `AfxClassInit` sweep above
(names should match exactly; a name in one list but not the other is a
lead, not noise -- either a class that's registered but never actually
serialized in your sample set, or evidence your byte-pattern scan mismatched
something).

## Putting it together with the rest of this skill

- Use the `AfxClassInit` sweep (static, from the .exe) to get the full
  class roster with schema numbers and base classes.
- Use the class-name string scan (static, from real `.E3` files) to
  confirm which of those classes actually appear in your corpus, and as
  an independent cross-check on the first list.
- Once you have schema number -> class name pairs, that's exactly the
  finite, enumerable dispatch table `references/tool-recipes.md` section
  13.3 describes writing as a Kaitai `switch-on: class_tag` -- one `case`
  arm per row here, added as you recover each class's own `Serialize()`
  layout by disassembly.
- The wire format's own `m_pBaseClass` field (statically-linked case) also
  gives you real inheritance edges for free -- if two classes turn out to
  share a base per this field, that's ground truth for the "near-identical
  class name, are they actually related" disambiguation problem, without
  needing `references/msvc-abi.md`'s VPS vtable-tracing procedure at all
  for this specific question (that procedure is still the right tool when
  you only have a vtable pointer and no `CRuntimeClass` to walk).
