#!/usr/bin/env python3
"""Automated backward slicing for the resource-binding-recovery workflow
(references/tool-recipes.md section 10.3, step 2: "Runtime-computed value").

Given a binary, an emulation entry point, an address at which to compute
the slice, and a register, this symbolically emulates from entry to the
slice address using Triton and prints every prior instruction that
contributed to that register's value at that point -- the same technique
Andriesse's *Practical Binary Analysis* ch. 13.3 demonstrates in C++, here
as a directly runnable script instead of a from-scratch tool.

"Backward slicing" is the formal term for this (Weiser, "Program Slicing,"
ICSE 1981 / IEEE TSE 1984): the subset of a program's instructions that
could have influenced a given variable's value at a given point. This
script computes exactly that slice, just for one register at one address
in machine code instead of a source-level variable.

Ketterlin & Clauss ("Recovering memory access patterns of executable
programs," Science of Computer Programming 80, 2014) describe essentially
this same substitution -- recursively replacing each register with its
SSA definition back to a loop-invariant value or memory load (their
`Expand()` procedure, restricted to linear ADD/SUB/scaled-MUL operations
so the result stays a closed-form `register*scale+offset` expression) --
as the formal basis for recovering a loop's address pattern without
running it. What this script automates concretely via Triton, that paper
describes as a hand-followable algorithm; see
`references/tool-recipes.md` section 9.4/10.3 for the by-hand version when
you don't want to set up the venv for a single address.

Triton concretely emulates each instruction's semantics (including calls,
jumps, and rets -- it isn't a linear disassembly walk), so it follows real
control flow through calls and unconditional jumps on its own. The one
caveat is conditional branches: with no symbolic configuration supplied,
any memory or registers this script hasn't set default to zero, so a branch
whose direction depends on unset state may take a path that doesn't match
the real run you're investigating. If the printed slice looks wrong, check
whether a conditional branch between entry and slice_addr depended on
memory/registers you didn't set -- this is deliberately minimal (no
--sym-config option) since the workflow's typical case is a straight run
from function entry to a call site with no branches in between.

Every section with real file content (`.text`/`.rodata`/`.data`/etc., not
`.bss`) is preloaded into Triton's concrete memory before emulation starts.
Without this, any instruction that reads *data* rather than code -- a
global, a jump/lookup table, a string, a vtable slot -- would silently read
0 instead of the real file bytes (verified directly: a global-array read
through this script returned 0 pre-fix, the real value post-fix), which is
worse than an error because it fails quietly rather than crashing. Indirect
jumps through an in-file jump table (a `switch` statement) will therefore
resolve to the real target now, rather than jumping to address 0 and
immediately hitting the "no mapped content" error. This script still has no
special jump-table *detection* -- it only benefits from correct data because
the table's bytes are now actually present -- see Vishnyakov et al., "Sydr:
Cutting Edge Dynamic Symbolic Execution" (ISPRAS, 2021), section V, for a
more thorough jump-table/indirect-jump resolution technique if you need to
enumerate *all* of a switch's targets rather than just follow the one your
concrete inputs happen to take.

REQUIRES A DEDICATED VENV. This machine (and possibly yours) may already
have OpenAI's unrelated GPU-kernel-compiler package also importable as
`triton` (a common transitive PyTorch dependency) -- if both are on
sys.path, `import triton` resolves ambiguously and can silently load the
wrong one, then fail with a confusing error (observed here as
`AttributeError: module 'triton' has no attribute 'max_shared_mem'`, which
is OpenAI-Triton failing to detect a GPU driver, not this script). Always
run this script through the skill's own venv, not the ambient interpreter:

    python3 -m venv <skill_dir>/.venv
    <skill_dir>/.venv/bin/pip install triton-library lief
    <skill_dir>/.venv/bin/python3 backward_slice.py <binary> <entry> <slice_addr> <reg>

Usage:
    backward_slice.py <binary> <entry_addr> <slice_addr> <reg> [--max-instructions N]

    <entry_addr>, <slice_addr>  hex or decimal, e.g. 0x401000 or 4198400
    <reg>                       eax, ecx, esi, ... (32-bit GPRs)
    --max-instructions N        safety cap on emulated instructions (default 100000);
                                triggers if execution from entry_addr never reaches
                                slice_addr (wrong entry point, a loop, or a conditional
                                branch resolved differently than the real run you're
                                investigating -- see the control-flow note above)
"""
import argparse
import json
import sys

try:
    import lief
except ImportError:
    print(json.dumps({"error": "LIEF not installed in this interpreter. Use the skill's "
                                "dedicated venv -- see this script's docstring."}))
    sys.exit(1)

try:
    from triton import ARCH, MODE, TritonContext, Instruction
except ImportError as e:
    print(json.dumps({"error": f"triton-library not importable ({e}). Use the skill's "
                                "dedicated venv -- see this script's docstring."}))
    sys.exit(1)

if not hasattr(sys.modules["triton"], "TritonContext"):
    # The classic symptom of the OpenAI-triton/triton-library name collision:
    # `import triton` succeeded but resolved to the wrong package entirely.
    print(json.dumps({"error": "import triton resolved to the wrong package (no "
                                "TritonContext) -- this is almost certainly OpenAI's "
                                "GPU-compiler 'triton', not 'triton-library'. Run this "
                                "script through the skill's dedicated venv instead of the "
                                "ambient interpreter -- see this script's docstring."}))
    sys.exit(1)


def parse_int(s):
    return int(s, 0)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary")
    p.add_argument("entry_addr", type=parse_int)
    p.add_argument("slice_addr", type=parse_int)
    p.add_argument("reg")
    p.add_argument("--max-instructions", type=int, default=100000)
    args = p.parse_args()

    binary = lief.parse(args.binary)
    if binary is None:
        print(json.dumps({"error": f"LIEF could not parse {args.binary}"}))
        sys.exit(1)

    # Cross-format bitness check (ELF and PE headers expose this differently).
    is_32 = True
    fmt = binary.format
    if fmt == lief.Binary.FORMATS.ELF:
        is_32 = binary.header.identity_class == lief.ELF.Header.CLASS.ELF32
    elif fmt == lief.Binary.FORMATS.PE:
        is_32 = binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386
    if not is_32:
        print(json.dumps({"error": "This script only supports 32-bit x86 (this skill's "
                                    "scope) -- got a 64-bit or non-x86 binary."}))
        sys.exit(1)

    ctx = TritonContext(ARCH.X86)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)

    # Without this, Triton's concrete memory is zero-filled everywhere except
    # the code bytes fed to Instruction() below -- so any instruction that
    # *reads data* (a global, a jump/lookup table, a string, a vtable slot)
    # silently gets 0 instead of the real file content, rather than erroring.
    # Preload every section that actually has file content (skips .bss/NOBITS,
    # which is genuinely zero at load time -- Triton's default already matches).
    for section in binary.sections:
        if section.virtual_address and len(section.content) > 0:
            ctx.setConcreteMemoryAreaValue(section.virtual_address, bytes(section.content))

    reg = getattr(ctx.registers, args.reg.lower(), None)
    if reg is None:
        print(json.dumps({"error": f"Unknown register {args.reg!r} for x86"}))
        sys.exit(1)

    pc = args.entry_addr
    steps = 0
    reached = False
    while steps < args.max_instructions:
        code = binary.get_content_from_virtual_address(pc, 16)
        if not code:
            print(json.dumps({"error": f"No mapped content at 0x{pc:x} "
                                        "(execution left the mapped sections -- likely a "
                                        "conditional branch resolved differently than the "
                                        "real run, or the wrong entry point)"}))
            sys.exit(1)
        inst = Instruction(pc, bytes(code))
        ctx.processing(inst)
        disasm = str(inst)
        for se in inst.getSymbolicExpressions():
            se.setComment(disasm)
        steps += 1

        if pc == args.slice_addr:
            reached = True
            break
        pc = ctx.getConcreteRegisterValue(ctx.registers.eip)

    if not reached:
        print(json.dumps({"error": f"Hit --max-instructions ({args.max_instructions}) "
                                    "without reaching slice_addr -- wrong entry point, an "
                                    "actual loop, or a conditional branch resolved "
                                    "differently than the real run you're investigating"}))
        sys.exit(1)

    reg_expr = ctx.getSymbolicRegisters().get(reg.getId())
    if reg_expr is None:
        print(json.dumps({
            "entry": hex(args.entry_addr), "slice_addr": hex(args.slice_addr),
            "register": args.reg, "slice": [],
            "note": f"{args.reg} was never symbolically written on this path -- its value "
                    "is whatever it concretely was at entry (check the calling context, "
                    "or this may genuinely be a literal/unmodified register)."
        }))
        return

    slice_exprs = ctx.sliceExpressions(reg_expr)
    slice_lines = sorted(
        (se.getComment() for se in slice_exprs.values() if se.getComment()),
        key=lambda line: int(line.split(":", 1)[0], 16),
    )

    print(json.dumps({
        "entry": hex(args.entry_addr),
        "slice_addr": hex(args.slice_addr),
        "register": args.reg,
        "slice": slice_lines,
    }, indent=2))


if __name__ == "__main__":
    main()
