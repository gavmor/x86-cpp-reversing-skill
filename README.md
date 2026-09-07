# x86-cpp-reversing

A [Claude Code skill](https://docs.claude.com/en/docs/claude-code/skills) for reverse-engineering 32-bit little-endian x86 (IA-32) binaries and disassembly compiled from C++. Recovers class layouts, vtables, virtual dispatch, and RTTI/inheritance hierarchies from ELF or PE binaries, and covers the workflows that come up once you have that structure: recovering a custom file format, mapping a data file's indexed entries back to the code/entity that uses them, and recognizing obfuscation or anti-debugging tricks along the way.

Built for agent use: `SKILL.md` is the entry point an agent reads, written so that mechanical, well-specified work (ABI struct layouts, relocation resolution, symbol demangling) is front-loaded into structured JSON via `scripts/recon.py` rather than spent as reasoning effort on raw disassembly. Everything degrades gracefully to manual `objdump`/`readelf`/`nm`/GDB recipes if the fancier tooling (radare2, LIEF, Triton) isn't available.

## What it covers

| Area | Automated? | Where |
|---|---|---|
| ELF/Itanium ABI (GCC/Clang, `_Z`-mangled): vtables, RTTI, multiple/virtual inheritance | Yes -- `scripts/recon.py` | `references/itanium-abi.md` |
| PE/MSVC ABI (`?`-mangled): thiscall, vftable, Complete Object Locator | Manual recipe only (no MSVC toolchain to validate an automated pass against), but the layout is cross-verified against multiple independent sources plus a real compiler-generated worked example | `references/msvc-abi.md` |
| Custom binary file-format loaders (no C++ classes involved) | Manual recipe | `references/tool-recipes.md` §9 |
| Resource-binding recovery: mapping a data file's indexed entries to the code/owner that uses them | Manual recipe + `scripts/backward_slice.py` (Triton-based backward slicing) | `references/tool-recipes.md` §10 |
| WinDbg/DbgEng dynamic analysis (native Windows PE binaries GDB can't attach to) | Manual recipe | `references/tool-recipes.md` §11 |
| Recognizing obfuscation (junk code, opaque predicates, xref-evasion tricks) | Manual recipe | `references/obfuscation.md` |
| Recognizing anti-debugging techniques | Manual recipe | `references/anti-debugging.md` |

## Requirements

- **Always available**: `objdump`, `readelf`, `nm`, `c++filt`, `gdb` (standard binutils/GDB, present on almost any Linux box).
- **Recommended, not required**: [radare2](https://github.com/radareorg/radare2) + `r2pipe`, and `pip install lief capstone pwntools` -- unlocks the automated/structured recipes; without them, `references/tool-recipes.md` has manual fallbacks for everything.
- **Optional, for `scripts/backward_slice.py` only**: `triton-library` (the [JonathanSalwan/Triton](https://github.com/JonathanSalwan/Triton) binary-analysis project) in a **dedicated virtualenv** -- do not `pip install triton-library` into your regular environment if you have any ML tooling installed (PyTorch, vLLM, etc.), since OpenAI's unrelated GPU-kernel-compiler package is also importable as `triton` and the two collide. See `AGENTS.md` and the script's own docstring.

## Installing as a Claude Code skill

```bash
git clone git@github.com:gavmor/x86-cpp-reversing-skill.git ~/.agents/skills/x86-cpp-reversing
ln -s ~/.agents/skills/x86-cpp-reversing ~/.claude/skills/x86-cpp-reversing
```

Claude Code will pick it up automatically for prompts like "what does this .exe do," "recover the class hierarchy from this binary," or "why does this crash inside a virtual call" -- see `SKILL.md`'s description for the full trigger conditions.

## Repo layout

```
SKILL.md                    entry point: workflow, triage steps, output format
AGENTS.md                   instructions for agents editing this repo's own content
scripts/recon.py            LIEF-based static triage + Itanium ABI vtable/RTTI recovery
scripts/backward_slice.py   Triton-based backward slicing (needs its own venv, see above)
references/itanium-abi.md   ELF/Itanium ABI details
references/msvc-abi.md      PE/MSVC ABI details
references/tool-recipes.md  concrete commands, by task (triage through §11)
references/obfuscation.md   recognizing deliberate obfuscation
references/anti-debugging.md recognizing anti-debugging techniques
```

## Contributing

If you're extending this skill's own content (not just using it against a target binary), read `AGENTS.md` first -- in particular, its norm on verifying external tool/library/paper citations against the primary source before they land in `references/*.md`.
