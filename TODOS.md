# TODOs

## ArtifactBundle serialization to CLI

**What:** Define how `bsp_profile` gets serialized from ArtifactBundle to the scan API
when the bbclass calls `sciath scan run` as a subprocess.

**Why:** The bbclass invokes the CLI as a subprocess. The CLI needs to receive BSP patch
data to include in the scan. Currently no serialization path exists.

**Context:** The packaging plan (kimmo-main-design-packaging-20260406.md) moves discovery/
into sciath-cli post-sprint. Once discovery is in-process with the CLI, serialization is
trivial (Python objects). But during the sprint, discovery is in sciath-meta and the CLI
is separate. Options: JSON file on disk, environment variable, or CLI flag.

**Depends on:** Week 4 scan pipeline integration.

## Cross-layer bbappend resolution

**What:** Scan all layers (not just the BSP layer) for .bbappend files that add patches
to the kernel recipe. Respect BBFILE_PRIORITY ordering.

**Why:** Custom layers can add kernel patches via bbappends in different layers. The
current implementation only scans same-layer bbappends (decision 2A from eng review).
This misses patches added by overlay layers.

**Context:** Same-layer covers the 80% case for vendor BSP layers (Toradex, RPi, PHYTEC
all have kernel recipes in their own layer). Cross-layer is mainly needed for custom
overlays on top of BSPs. Getting priority ordering wrong could cause false suppressions
(attributing a patch from the wrong machine). Deferred until a customer hits this case.

**Depends on:** BSP layer resolver v1 shipped and validated.

## Curated mitigation database (replaces fingerprinting)

**What:** Build a customer-contributed mitigation database where verified CVE
mitigations compound across all users on the same BSP vendor/version. When one
customer verifies a CVE is mitigated (patch, config, not-applicable), that
suppression applies to every other customer on the same BSP.

**Why:** Version suppression alone gives 27-38% on-branch suppression. Vigiles
beats this with years of manual CVE-to-patch curation. Instead of building an
automated fingerprinter (narrow, only handles single-commit kernel patches), build
a product feature where customer-verified mitigations compound.

**Data model:** (BSP vendor, kernel version range, CVE ID, mitigation type,
evidence, confidence, source customer/anonymous). Mitigation types: patch verified,
config mitigation, vendor advisory, not-applicable-with-rationale.

**Integration:** Plugs directly into VEX export (CRA requirement). Each mitigation
is a VEX justification. The curated DB becomes the suppression layer between
version suppression and the final action items list.

**Context:** This replaces the deferred file-patch fingerprinting (git patch-id)
from the original sprint plan. The fingerprinter only handles one mitigation type.
The curated DB handles all types and creates a data moat that compounds with
customer count. Identified 2026-04-07 as the competitive response to Vigiles.

**Depends on:** Week 4 scan pipeline integration. VEX model in sciath backend.

## DBOS pipeline for automated BSP re-ingestion

**What:** Set up DBOS jobs that watch public BSP layer repos (meta-raspberrypi,
meta-toradex-bsp-common, meta-phytec) and automatically re-run ingestion on each
new commit. Keep bsp_data/*.json files always current.

**Why:** BSP layers update frequently (kernel version bumps, new patches, config
changes). Manual re-ingestion falls behind. Automated ingestion means the demo
always shows fresh data and new vendor patches are captured within hours of commit.

**Context:** The ingestion script (`scripts/ingest_bsp.py`) already supports
`--vendor` targeting and shallow clones. A DBOS workflow would: (1) watch each
repo via webhook or polling, (2) on new commit, run `ingest_bsp.py --vendor X`,
(3) compare output with previous bsp_data JSON, (4) if changed, commit updated
JSON to sciath-meta or push to the backend API. The `related_repos` pattern
(Toradex kconfig + machines) means the workflow also watches dependent repos.

**Depends on:** BSP pre-ingestion v1 validated. DBOS infrastructure setup.
