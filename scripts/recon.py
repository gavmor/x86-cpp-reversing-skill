#!/usr/bin/env python3
"""Static triage + Itanium C++ ABI vtable/RTTI recovery for x86 binaries.

Emits one JSON object to stdout describing:
  - binfo: arch/bits/endianness/format/pie, so you can confirm you're actually
    looking at 32-bit little-endian x86 before trusting anything downstream.
  - symbols: demangled function/data symbols.
  - vtables: for every _ZTV* symbol (Itanium vtable), the offset-to-top,
    resolved typeinfo, and each virtual function slot classified as either
    a resolved function pointer or an unresolved "marker" word (which for
    multiply-inherited classes is very likely a secondary sub-vtable's own
    offset-to-top/typeinfo pair -- see references/itanium-abi.md for how to
    read those by hand).
  - typeinfo: parsed __class_type_info / __si_class_type_info /
    __vmi_class_type_info structures, giving you the base-class graph
    without having to walk the raw bytes yourself.

Scope: this only knows the Itanium C++ ABI (GCC/Clang on Linux/BSD/etc,
mangled names starting with "_Z"). MSVC vftables/RTTI on PE binaries use a
different layout entirely (see references/msvc-abi.md) and are NOT walked
automatically here -- guessing at that layout without a way to validate it
would be worse than not guessing, so PE binaries only get binfo+symbols.

Usage:
    python3 recon.py <binary> [--max-slots N] [--max-depth N]

Requires: LIEF (`pip install lief`), and `c++filt` (binutils, virtually
always preinstalled on Linux). If LIEF isn't available, fall back to the
manual objdump/readelf/nm/c++filt recipes in references/tool-recipes.md.
"""
import json
import shutil
import struct
import subprocess
import sys

try:
    import lief
except ImportError:
    print(json.dumps({"error": "LIEF not installed. pip install lief, or use "
                                "references/tool-recipes.md for the manual "
                                "objdump/readelf/nm/c++filt workflow instead."}))
    sys.exit(1)

CXXFILT = shutil.which("c++filt")


def demangle(name):
    if not name or not CXXFILT:
        return None
    try:
        out = subprocess.run([CXXFILT, "-n"], input=name, capture_output=True,
                              text=True, timeout=5).stdout.strip()
        return out if out and out != name else None
    except Exception:
        return None


class Reader:
    """Little-endian word reads by virtual address, with symbol/section/
    relocation lookups.

    PIE/dynamically-linked binaries don't store real pointers for anything
    that crosses a shared-library boundary (e.g. a typeinfo's link to
    __cxxabiv1::__si_class_type_info's vtable, which lives in libstdc++) --
    the file just has a placeholder (usually the addend, e.g. the "+8 vptr"
    offset) plus a relocation entry naming the real target symbol. Reading
    raw bytes and ignoring relocations silently gives you garbage in that
    case, so every pointer-sized read goes through resolve_pointer() instead,
    which checks the relocation table first.
    """

    def __init__(self, binary):
        self.b = binary
        self.symbols = [s for s in binary.symbols if s.value]
        self.symbols.sort(key=lambda s: s.value)
        self.by_exact_addr = {}
        for s in self.symbols:
            self.by_exact_addr.setdefault(s.value, s)
        # Relocation resolution is only needed for the Itanium/ELF vtable walk
        # below; PE's Relocation type doesn't even expose the same fields, so
        # don't bother building this map for non-ELF binaries.
        self.reloc_by_addr = {}
        if str(binary.format).split(".")[-1] == "ELF":
            for r in binary.relocations:
                self.reloc_by_addr[r.address] = r

    def read_bytes(self, addr, size):
        data = self.b.get_content_from_virtual_address(addr, size)
        if not data or len(data) < size:
            return None
        return bytes(data)

    def read_u32(self, addr):
        data = self.read_bytes(addr, 4)
        return struct.unpack("<I", data)[0] if data else None

    def read_i32(self, addr):
        data = self.read_bytes(addr, 4)
        return struct.unpack("<i", data)[0] if data else None

    def resolve_pointer(self, addr):
        """Returns ('external', symbol_name) for a pointer that only exists
        via a symbol relocation (target lives outside this binary), or
        ('addr', value) for a plain in-file virtual address -- which is what
        you want for everything else, including R_386_RELATIVE-relocated
        internal pointers (their stored bytes already are the correct
        link-time address when the load base is 0)."""
        reloc = self.reloc_by_addr.get(addr)
        if reloc is not None:
            sym = reloc.symbol
            if sym is not None and sym.name and not sym.value:
                return ("external", sym.name)
        value = self.read_u32(addr)
        return ("addr", value)

    def read_cstring(self, addr, max_len=256):
        data = self.read_bytes(addr, max_len)
        if not data:
            return None
        end = data.find(b"\x00")
        raw = data[: end if end != -1 else max_len]
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    def in_code_section(self, addr):
        for sec in self.b.sections:
            flags = int(sec.flags)
            is_exec = bool(flags & 0x4)  # SHF_EXECINSTR (ELF) -- see note below for PE
            if sec.virtual_address <= addr < sec.virtual_address + sec.size and is_exec:
                return True
        return False

    def symbol_at(self, addr):
        return self.by_exact_addr.get(addr)

    def symbol_covering_vptr(self, addr):
        """Find a symbol S such that S.value + 8 == addr (the Itanium 'vtable
        address as stored in objects' convention: 8 bytes after the exported
        vtable symbol, past offset-to-top + typeinfo-ptr)."""
        for s in self.symbols:
            if s.value + 8 == addr:
                return s
        return None


ABI_KIND_BY_SYMBOL_SUFFIX = {
    "N10__cxxabiv117__class_type_infoE": "no_base",
    "N10__cxxabiv120__si_class_type_infoE": "single_base",
    "N10__cxxabiv121__vmi_class_type_infoE": "multi_or_virtual_base",
}


def classify_typeinfo_kind(reader, addr):
    """addr is the location of the typeinfo's own vtable-pointer field
    (the struct's first word), not its value -- resolution must go through
    the relocation table since this pointer very often crosses into
    libstdc++ (e.g. plain __class_type_info / __si_class_type_info are
    provided by the runtime, not emitted per-binary)."""
    kind_of, value = reader.resolve_pointer(addr)
    if kind_of == "external":
        name = value
    else:
        sym = reader.symbol_covering_vptr(value) if value else None
        name = sym.name if sym else None
    if name:
        for suffix, kind in ABI_KIND_BY_SYMBOL_SUFFIX.items():
            if name.endswith(suffix):
                return kind
    return "unknown"


def resolve_addr_like(reader, addr):
    """Resolve a pointer-sized field at addr, returning a plain address int
    or None -- collapses the ('external', name)/('addr', value) distinction
    for callers (like typeinfo name/base lookups) that just need somewhere
    to keep reading from. External targets (e.g. a base class's typeinfo
    living in libstdc++) can't be followed further, so they come back None."""
    kind_of, value = reader.resolve_pointer(addr)
    return value if kind_of == "addr" else None


def parse_typeinfo(reader, addr, depth=0, max_depth=4, seen=None):
    if seen is None:
        seen = set()
    if addr is None or addr in seen or depth > max_depth:
        return {"addr": hex(addr) if addr else None, "truncated": True}
    seen.add(addr)

    kind = classify_typeinfo_kind(reader, addr)
    name_ptr = resolve_addr_like(reader, addr + 4)
    if name_ptr is None:
        return {"addr": hex(addr), "kind": kind, "error": "name pointer unresolvable (external?)"}

    raw_name = reader.read_cstring(name_ptr)
    result = {
        "addr": hex(addr),
        "raw_mangled_name": raw_name,
        "demangled": demangle("_Z" + raw_name) if raw_name else None,  # class names demangle as _Z<name>
        "kind": kind,
    }

    if kind == "single_base":
        base_ti_ptr = resolve_addr_like(reader, addr + 8)
        result["base"] = parse_typeinfo(reader, base_ti_ptr, depth + 1, max_depth, seen)
    elif kind == "multi_or_virtual_base":
        flags = reader.read_u32(addr + 8)
        base_count = reader.read_u32(addr + 12)
        bases = []
        if base_count is not None and base_count < 32:  # sanity cap
            for i in range(base_count):
                entry_addr = addr + 16 + i * 8
                base_ti_ptr = resolve_addr_like(reader, entry_addr)
                offset_flags = reader.read_u32(entry_addr + 4)
                if offset_flags is None:
                    break
                is_virtual = bool(offset_flags & 0x1)
                packed = offset_flags >> 8
                entry = {
                    "base": parse_typeinfo(reader, base_ti_ptr, depth + 1, max_depth, seen),
                    "is_virtual": is_virtual,
                    "is_public": bool(offset_flags & 0x2),
                }
                if is_virtual:
                    # For a virtual base this packed value is NOT the base's byte
                    # offset in the object -- per the Itanium ABI it's an offset
                    # into *this derived class's own vtable* where the real,
                    # most-derived-type-dependent object offset is stored at
                    # runtime (see references/itanium-abi.md). Reporting it as
                    # "offset" would silently mislead.
                    entry["vbase_offset_field"] = packed
                else:
                    entry["offset"] = packed
                bases.append(entry)
        result["flags"] = flags
        result["bases"] = bases
    return result


def locate_primary_header(reader, sym, max_prefix_words=8):
    """Find the [offset-to-top][typeinfo] pair at the start of a vtable group.

    For plain single/non-virtual-multiple inheritance this is always at
    sym.value/sym.value+4. But when the class has a virtual base *anywhere*
    in its hierarchy (even transitively, like Joined here via Left/Right's
    virtual Base), the ABI prepends one or more vbase-offset/vcall-offset
    words before the pair -- and the count isn't fixed, it depends on the
    hierarchy shape. Rather than compute that count (which requires fully
    modeling the ABI's offset-assignment algorithm), locate the pair by
    scanning for the first word that resolves to this class's own `_ZTI`
    symbol -- the word immediately before it is always offset-to-top, by
    ABI invariant, regardless of how many prefix words came before that.
    """
    for i in range(max_prefix_words):
        candidate = sym.value + i * 4
        kind_of, value = reader.resolve_pointer(candidate)
        if kind_of == "addr" and value:
            ti_sym = reader.symbol_at(value)
            if ti_sym and ti_sym.name.startswith("_ZTI"):
                prefix_words = [reader.read_i32(sym.value + j * 4) for j in range(i - 1)]
                return prefix_words, reader.read_i32(candidate - 4), value, candidate + 4
    # No _ZTI match found in range -- fall back to the no-virtual-inheritance
    # assumption rather than failing outright.
    return [], reader.read_i32(sym.value), resolve_addr_like(reader, sym.value + 4), sym.value + 8


def walk_vtable(reader, sym):
    """sym is a _ZTV<...> symbol. Returns offset-to-top, typeinfo, and slots.

    Layout (Itanium C++ ABI): sym.value is the start of the vtable *group*.
    [sym.value+0]  offset-to-top (ptrdiff_t)         <- only true absent virtual inheritance;
    [sym.value+4]  pointer to typeinfo structure         see locate_primary_header() otherwise
    [[email protected]] virtual function pointers (the address that actually
                     gets stored as an object's vptr is the word after typeinfo)
    sym.size (when nonzero, which GCC/Clang reliably emit) is the authoritative
    end of the whole group, including any secondary sub-vtables for multiple
    inheritance -- so we trust it over guessing where slots stop.
    """
    prefix_words, offset_to_top, typeinfo_ptr, vfunc_start = locate_primary_header(reader, sym)
    typeinfo = parse_typeinfo(reader, typeinfo_ptr) if typeinfo_ptr else None

    end = sym.value + sym.size if sym.size else vfunc_start + 64 * 4  # fallback cap: 64 slots
    slots = []
    addr = vfunc_start
    while addr < end:
        kind_of, value = reader.resolve_pointer(addr)
        if kind_of == "external":
            slots.append({
                "vtable_offset": addr - vfunc_start,
                "resolved_name": value,
                "demangled": demangle(value),
                "kind": "vfunc",
            })
            addr += 4
            continue
        word = value
        if word is None:
            break
        func_sym = reader.symbol_at(word)
        if reader.in_code_section(word):
            slots.append({
                "vtable_offset": addr - vfunc_start,
                "target": hex(word),
                "resolved_name": func_sym.name if func_sym else None,
                "demangled": demangle(func_sym.name) if func_sym else None,
                "kind": "vfunc",
            })
        else:
            # Not code -- almost certainly an offset-to-top/typeinfo pair
            # belonging to a secondary sub-vtable (multiple inheritance).
            # See references/itanium-abi.md for how to interpret this by hand.
            slots.append({
                "vtable_offset": addr - vfunc_start,
                "raw_value": hex(word) if word >= 0 else word,
                "kind": "marker_or_secondary_header",
            })
        addr += 4

    return {
        "symbol": sym.name,
        "demangled": demangle(sym.name),
        "group_start": hex(sym.value),
        "prefix_words": prefix_words,
        "vptr_address": hex(vfunc_start),
        "size_bytes": sym.size,
        "offset_to_top": offset_to_top,
        "typeinfo": typeinfo,
        "slots": slots,
    }


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    path = args[0]

    binary = lief.parse(path)
    if binary is None:
        print(json.dumps({"error": f"LIEF could not parse {path}"}))
        sys.exit(1)

    fmt = str(binary.format).split(".")[-1]
    header = binary.header
    # ELF exposes header.machine_type; PE exposes header.machine -- normalize both.
    machine_raw = getattr(header, "machine_type", None) or getattr(header, "machine", None)
    machine = str(machine_raw).split(".")[-1] if machine_raw is not None else None
    is_32 = machine in ("I386",)
    is_64 = machine in ("X86_64", "AMD64")
    binfo = {
        "format": fmt,
        "machine": machine,
        "bits": "32" if is_32 else ("64" if is_64 else "unknown"),
        "endianness": "little" if (is_32 or is_64) else "unknown",  # x86/x86-64 is always LE
        "entrypoint": hex(binary.entrypoint) if binary.entrypoint else None,
        "is_pie": getattr(binary, "is_pie", None),
    }
    if not is_32:
        binfo["warning"] = ("This binary does not look like 32-bit x86 (machine=%s). "
                             "vtable/RTTI recovery here targets IA-32 Itanium ABI layouts "
                             "specifically -- offsets and pointer sizes assume 4-byte words, "
                             "which will misparse a 64-bit binary." % machine)

    reader = Reader(binary)

    symbols = []
    for s in reader.symbols:
        if not s.name:
            continue
        symbols.append({
            "name": s.name,
            "demangled": demangle(s.name),
            "value": hex(s.value),
            "size": s.size,
        })

    result = {"binfo": binfo, "symbol_count": len(symbols), "symbols": symbols}

    if fmt == "ELF":
        vtable_syms = [s for s in reader.symbols if s.name.startswith("_ZTV")]
        result["vtables"] = [walk_vtable(reader, s) for s in vtable_syms]
    else:
        result["note"] = ("Non-ELF binary: vtable/RTTI auto-recovery is Itanium-ABI-only. "
                           "Use references/msvc-abi.md for manual MSVC vftable/RTTI recovery.")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
