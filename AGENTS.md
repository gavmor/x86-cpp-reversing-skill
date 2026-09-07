# Working on this skill (not the workflow it teaches -- see SKILL.md for that)

Instructions for an agent editing/extending this repo's own content
(`SKILL.md`, `references/*.md`, `scripts/*`) -- not instructions for
reverse-engineering a target binary.

## Design rationale: where this skill sits, and why that combination holds together

Hu et al., *SoK: Potentials and Challenges of Large Language Models for
Reverse Engineering* (2025), taxonomizes LLM-based RE work along five
dimensions: **Objective** (Performance / Interpretability / Discovery /
Robustness), **Target** (Raw Bytes / Assembly Code / Decompiled Code /
Source Code), **Method** (Zero/Few-Shot Prompting / Fine-Tuning / RAG /
Agent-Based / Data Generation), **Evaluation** (Expert-Based / Automated
Metric / Ground-Truth Validation), and **Data Scale** (Proof-of-Concept /
Fine-Tuning / Pre-Training-Massive). This skill is itself an LLM-based-RE
artifact, so the taxonomy applies to it, not just to the papers it cites.

**The paper's own analytical move is the useful part, not just the labels.**
Its §5.2 case study contrasts two systems: DeGPT succeeds because its
choices *align* across dimensions -- Decompiled-Code target (where
interpretability work pays off), evaluated with *both* automated metrics
*and* expert assessment (so gamification of one metric gets caught by the
other). DISASLLM, by contrast, combines an Assembly-Code target with
fine-tuning and automated-metric-only evaluation -- and its accuracy
"degrades sharply in heavily obfuscated regions, with recall dropping below
0.60 for junk-byte cases," a failure its own evaluation pipeline had no way
to surface, because nothing in that pipeline was positioned to catch it.
Misalignment isn't a style problem; it's where a design's blind spots live.

Reading this skill against that lens deliberately, not just for the labels:

- **Objective:** Performance and Robustness are both heavily invested
  (`scripts/recon.py`'s automation; `references/obfuscation.md`,
  `anti-debugging.md`, `untrusted-binary-content.md`). Interpretability
  shows up concretely in the Annotated Artifact exit criterion (see
  `SKILL.md`). **Discovery is out of scope by design, not by oversight**:
  this skill recovers structures a compiler faithfully encoded per a known
  ABI (a vtable really exists, per the spec) -- it is not built for
  open-ended novel-vulnerability or undocumented-protocol discovery, and
  extending it in that direction would need a different verification
  posture than "check against the ABI spec."
- **Target:** the Phased Workflow in `SKILL.md` climbs this dimension in
  order -- Raw Bytes, then Assembly Code for the bulk of the work, arriving
  at Decompiled Code only in the final Annotated Artifact. This mirrors the
  paper's own observation that Assembly Code "closely mirror[s] the demands
  placed on human analysts" for authentic technical challenges, while
  Decompiled Code is "a pragmatic middle ground" better suited to the
  interpretability payoff at the end, not the structural-recovery work in
  the middle. Source Code has no direct target here (there is none, by
  construction of the RE problem) but re-enters as *comparison* data via
  section 8's compile-your-own-reference-binary technique.
- **Method:** this skill is Zero/Few-Shot Prompting (the skill file itself)
  combined with Agent-Based orchestration (external tools -- debuggers,
  disassemblers, Triton -- integrated with results fed back for reasoning,
  exactly the paper's definition). The `references/*.md` files that get
  pulled into context on demand are, functionally, a hand-curated RAG
  corpus. **Fine-Tuning and Data Generation are out of scope by design**:
  this is a context-engineering artifact, not a model-training project, and
  extending it with either would change what kind of thing it is.
  Critically, the paper names the exact risk Agent-Based methods
  introduce -- "orchestration complexity... expands the attack surface,
  including vulnerabilities such as prompt injection against tool callback
  interfaces" -- which is precisely `untrusted-binary-content.md`'s subject.
  That file exists because this skill's own Method choice predicts it
  should, not as a generic caution bolted on afterward.
- **Evaluation:** deliberately weighted toward Ground-Truth Validation
  (section 8's recompile-and-diff technique, the whole verify-before-
  shipping norm below) and Expert-style self-verification (confidence
  markers, the Verification & Hard Exit Criteria section), with Automated
  Metric Scoring kept intentionally lightweight -- the Annotated Artifact
  checklist, not a computed score -- exactly to avoid the DISASLLM failure
  mode of a single automatable metric with nothing else positioned to
  catch what it misses.
- **Data Scale** does not apply. There is no training run here to place on
  this axis; treating that as a gap would be a category error, not an
  omission.

**How to use this when extending the skill:** before adding a new
capability, place it on these five axes and ask whether it's *aligned* with
the choices above or fighting them. A new recipe that's Assembly-Code-
target and Ground-Truth-validated fits this skill's grain. A proposal that
requires fine-tuning, massive data, or open-ended discovery-oriented
hypothesis generation is a sign you're building a different kind of
artifact, not extending this one -- that's a reason to say so explicitly
(as with `references/tool-recipes.md` section 10.3's `angr`/REMaQE note,
which cites the *technique* without adopting REMaQE's own no-longer-
applicable evaluation framing) rather than force the fit.

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
