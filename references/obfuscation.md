# Recognizing obfuscation

Not every hard-to-read binary is stripped or optimized -- some are
deliberately obfuscated. This file covers *recognizing* the common patterns
(so you don't waste time treating deliberately-hostile code as if it were
just unusual compiler output) rather than automatically defeating them,
which is a much larger topic than this skill's scope.

Everything below is drawn from Dang, Gazet, Bachaalany & Josse, *Practical
Reverse Engineering* (Wiley, 2014), ch. 5.

## The assumptions obfuscators break

Reading disassembly at a level of abstraction higher than raw bytes relies
on assumptions: a `CALL` always invokes a function and returns to the next
instruction; a basic block's instructions are sequential; a jump table's
targets are all valid code. Obfuscators specifically target these
assumptions, not the underlying logic -- which is why static analysis
degrades disproportionately against obfuscated code even when the actual
program behavior is simple.

## Named patterns worth recognizing

**`call`-as-`jmp`.** A `CALL` whose target never returns to the instruction
after it -- instead the callee discards the pushed return address and
continues elsewhere. Breaks the "a call returns" assumption most linear
disassemblers rely on:

```
01: call target_addr
02: <junk code>
03: target_addr:
04: add esp, 4        ; discards the return address CALL just pushed
```

If you see a function immediately fix up `esp` right after its own entry
point with no corresponding `call`/`push` in its own body, this is why --
line 2's "junk code" is never executed and exists purely to mislead a
disassembler that assumed line 1 was a normal call.

**Opaque predicates.** A branch whose direction is always the same at
runtime, but expensive or difficult to *prove* statically without emulating
the actual arithmetic (see Collberg, "A Taxonomy of Obfuscating
Transformations," for the formal treatment) -- used to insert dead/junk
code paths that a naive disassembler still has to traverse and try to make
sense of. A trivial worked example combining an opaque predicate with junk
code:

```
01: push eax
02: xor eax, eax     ; eax is now provably 0
03: jz 09             ; always taken -- eax is 0 -- but not obvious without emulating
04: <junk code start>
05: jg 04
06: inc esp
07: ret
08: <junk code end>
09: pop eax
```

Six bytes of junk sit between the always-taken jump and its target. The
junk block itself is built from instructions (`jg`, `inc esp`, `ret`) chosen
specifically to make a linear disassembler think a new branch and a
function boundary exist there, when the block is in fact dead code that
never executes.

**Uncommon-instruction obfuscation.** Compilers rarely emit certain
instructions, so their presence is itself a signal that hand-written or
obfuscator-generated code is nearby. A representative example combining the
"XOR swap trick" (exchanging two registers without a temp, lines 1-3) with
several uncommon instructions used purely to obscure a simple arithmetic
sequence:

```
01: xor ebx, eax
02: xor eax, ebx
03: xor ebx, eax
04: inc eax
05: neg ebx
06: add ebx, 0A6098326h
07: cmp eax, esp
08: mov eax, 59F67CD5h
09: xor eax, 0FFFFFFFFh
10: sub ebx, eax
11: rcl eax, cl
12: push 0F9CBE47Ah
13: add dword ptr [esp], 6341B86h
14: sbb eax, ebp
15: sub dword [esp], ebx
16: pushf
17: pushad
18: pop eax
19: add esp, 20h
20: test ebx, eax
21: pop eax
```

`RCL`, `SBB`, and `PUSHF`/`PUSHAD` in particular are rare enough in normal
compiler output that seeing them clustered together is itself a strong
obfuscation signal, independent of working out what the block actually
computes.

**Control-flow flattening and dead-code insertion** are named in the same
chapter as broader structural techniques (flattening a function's control
flow into a single dispatcher loop driven by a state variable, rather than
natural nested branches) -- recognize the *shape* (one big switch/dispatch
loop where you'd expect nested control flow) even without a worked example
here.

**String hiding.** Constructing a string byte-by-byte at runtime
(`mov byte ptr [ebx], 'h'` / `mov byte ptr [ebx+1], 'e'` / ...) rather than
storing it as a literal defeats `strings`/IDA string search entirely --
there's no contiguous ASCII run in the binary to find. A comparison can be
hidden the same way (`cmp byte ptr [ebx], 'j'` / `jnz fail` / `cmp byte ptr
[ebx+1], 'o'` / ... character-by-character rather than one string compare),
and a split-argument `sprintf(buf, "%s%c%s%c%s", "hel", 'l', "o w", 'o',
"rld")` reads as nonsense until you notice it reassembles a fixed string
(Yurichev, *Reverse Engineering for Beginners*, ch. 50.1). If you can't find
a resource name, sound cue, or debug string you're fairly sure must exist
somewhere in the binary, check for this before concluding it isn't there.

**Indirect-pointer and bloated-instruction xref evasion.** Two more named
techniques from the same source that specifically defeat *static
cross-reference sweeps* (directly relevant to this skill's own xref-sweep-
heavy methodology in tool-recipes.md section 10) -- see tool-recipes.md
section 10.1 for the worked examples: computing a real target via `add`/
`lea` off an unrelated anchor symbol (ch. 50.2.5), and substituting a direct
`call`/`jmp` with an equivalent `push`+`ret` sequence specifically because
"IDA will not show the references to the label" (ch. 50.2.2).

## Disassembler desync vs. deliberate obfuscation

A related but distinct problem: a disassembler that has genuinely lost sync
(started decoding mid-instruction, or followed a bad jump target) can
produce output that looks obfuscated without any obfuscation being present
at all. Named signals for recognizing desync specifically (Yurichev, ch.
49):

- **Unusually diverse instruction mix in one place** -- FPU, `IN`/`OUT`, or
  privileged/system instructions all clustered together in what should be
  ordinary application code. Real compiled code from a single function
  essentially never mixes these; seeing them together is a much stronger
  signal of misaligned decoding than of real obfuscation.
- **Big or seemingly random immediates and offsets** that don't correspond
  to any plausible constant, address, or struct offset.
- **Jumps landing mid-instruction** relative to how the surrounding code was
  decoded -- if re-disassembling from a jump's target produces a completely
  different (and more sensible) instruction stream than continuing linearly
  through the bytes, the linear decode was wrong, not the code.

If you hit one of these, try re-disassembling from a different, more
certain starting point (a known function boundary, an xref-confirmed call
target) before concluding the binary is obfuscated -- the fix is often just
picking a better start address, not defeating an obfuscator.

## Suspicious code patterns as heuristics (not proof)

Two low-cost signals worth checking before spending time on a block, from
Yurichev ch. 61:

- **`XOR reg, reg` with a large or mismatched second operand elsewhere
  nearby** is a common tell for hand-rolled checksum/crypto/hashing code
  rather than compiler output -- with one common exception: a stack-canary
  XOR (`xor ecx, ebp` or similar against the stack cookie), which is
  compiler-generated and looks superficially similar. Check whether the
  value being XORed traces back to `__security_cookie`/a stack slot set up
  in the prologue before treating it as hand-written.
- **`LOOP`, `RCL`, a missing standard prologue/epilogue, or a
  non-standard calling convention** together are a signal that a function
  was hand-written in assembly rather than compiler-generated -- compilers
  essentially never emit `LOOP` (it's slower than the `dec`/`jnz` pairs
  compilers actually generate) and rarely emit `RCL`. Worth flagging in a
  report as "likely hand-written," which changes how much weight to put on
  compiler-convention assumptions (frame layout, calling convention) for
  that specific function.

## Tools (survey, not endorsement -- verify current API before use)

- **VMProtect, CodeVirtualizer** -- commercial VM-based obfuscators/packers.
  If you recognize their characteristic bytecode-interpreter loop, treat it
  as "this function's logic has been compiled to a custom bytecode," not as
  a normal function to disassemble directly.
- **Miasm, Metasm** -- IR-based binary analysis frameworks used for
  deobfuscation (disassemble -> lift to an intermediate representation ->
  simplify/symbolically execute -> regenerate). **The book's own code
  sample uses a ~2014-era Miasm API (`from miasm.arch.ia32_arch import *`,
  `ExprOp`/`ExprAff`) that does not match the current `miasm` package on
  PyPI.** Don't cite or copy that import path -- re-verify against current
  Miasm's actual API before using it for anything, per this skill's own
  `AGENTS.md` norm on primary-source verification.
- **VxStripper** -- a binary-rewriting/simplification research tool by
  Sébastien Josse (one of the book's co-authors), described in the book but
  with no confirmed public repository found -- treat as a described research
  approach, not as installable tooling, unless you separately confirm it's
  actually downloadable.
