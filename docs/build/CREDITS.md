# Taxonomy sources and attribution

Aphasia's technique catalog (`engine/src/aphasia/data/catalog.yaml`, surfaced by `aphasia catalog`
and TUI section 8) is a merged, deduplicated reference built from three public taxonomies. Their
licenses require attribution; keep this file and the per-entry `sources` in the catalog.

| Source | Author | License | Used for |
|---|---|---|---|
| [AATMF v3](https://github.com/SnailSploit/AATMF-Adversarial-AI-Threat-Modeling-Framework) | Kai Aizen (SnailSploit) | CC BY-SA 4.0 | tactic/technique ids (`T<n>-AT-<nnn>`), coverage structure |
| [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) | Jason Haddix, Arcanum Information Security | CC BY 4.0 | technique / evasion / intent names |
| [ZeroLeaks](https://github.com/ZeroLeaks/zeroleaks) | ZeroLeaks | FSL-1.1-Apache-2.0 | probe category names |

**What was taken:** only the taxonomy — names, ids and categories of tactics, techniques and
procedures. No code, payloads, prompts, images or datasets were copied from any source. Each catalog
entry cites the source ids it maps to; one source id maps to at most one Aphasia technique (deduplicated).

**CC BY-SA 4.0 note (AATMF):** the catalog file, as a derivative of AATMF's taxonomy, is distributed
under CC BY-SA 4.0. It is a standalone data file; it does not relicense Aphasia's Apache-2.0 code.

**Attribution lines**
- "Technique taxonomy based in part on the Arcanum Prompt Injection Taxonomy by Jason Haddix
  (Arcanum Information Security), CC BY 4.0."
- "Includes tactics/techniques from AATMF v3 by Kai Aizen (SnailSploit), CC BY-SA 4.0."
- "Probe categories informed by ZeroLeaks (FSL-1.1-Apache-2.0)."

**Not incorporated:** ZeroLeaks is source-available under FSL (an Apache-2.0 future license); only its
public category names are used as reference, no code. If you later vendor any ZeroLeaks or AATMF *code*,
revisit license compatibility with Aphasia's Apache-2.0.
