# Working on this skill (not the workflow it teaches -- see SKILL.md for that)

Instructions for an agent editing/extending this repo's own content
(`SKILL.md`, `references/*.md`, `scripts/*`) -- not instructions for
reverse-engineering a target binary.

## Verify external citations before shipping them

Before naming a specific external repo, library, paper, or API in
`references/*.md` (function names, architecture/platform support, claimed
capabilities), verify the claim against the primary source -- clone the
repo, read the actual docs/PDF pages, or run the install and a smoke test --
rather than trusting a secondhand summary, even one that looks
well-researched.

This isn't hypothetical: a research-style summary of "repos worth
evaluating" for the resource-binding-recovery recipe (section 10) was
mostly accurate but cited `tkhquang/DetourModKit` as if applicable to this
skill's 32-bit domain, when the repo is actually Windows-x64-only -- caught
only by cloning it directly (see git history around commit `2a13fdc`).
Conversely, reading Andriesse's *Practical Binary Analysis* directly (not
from memory) turned up precise, directly-usable APIs (Triton's `ARCH.X86`,
Pin's `INS_InsertCall`) that a paraphrase would have gotten wrong or vague.

If verification reveals a mismatch, either correct the citation with an
explicit caveat (see the DetourModKit paragraph in
`references/tool-recipes.md` section 10.6 for the pattern) or drop it
entirely -- don't let an unverified claim ship.

## `triton-library` requires a dedicated venv -- do not install it ambiently

`scripts/backward_slice.py` depends on `triton-library` (the
JonathanSalwan/Triton dynamic-binary-analysis project, importable as
`triton`). On any machine that also has ML tooling installed (PyTorch,
vLLM, etc.), OpenAI's unrelated GPU-kernel-compiler package is *also*
importable as `triton` -- a real collision, not a hypothetical one:
`pip install triton-library` into an ambient interpreter that already has
OpenAI's `triton` present can leave `import triton` resolving to the wrong
package, failing with a confusing, unrelated error
(`AttributeError: module 'triton' has no attribute 'max_shared_mem'`).

Always set up and use a dedicated venv:

```bash
python3 -m venv .venv
.venv/bin/pip install triton-library lief
.venv/bin/python3 scripts/backward_slice.py <binary> <entry_addr> <slice_addr> <reg>
```

`.venv/` is gitignored -- recreate it rather than expecting it to be
committed. If `import triton` ever behaves unexpectedly while working on
this script, check `triton.__file__` first to see which package actually
loaded before debugging further.

## Git workflow

Commits in this repo are local by default -- confirm with the user before
pushing to `origin` (`gavmor/x86-cpp-reversing-skill`). Prefer small,
single-purpose commits (see git history for the established granularity:
one recipe addition or one correction per commit, not batched).
