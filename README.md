# VGK Platform Security Stack

![language](https://img.shields.io/badge/C%2B%2B-research%20reference-informational)
![target](https://img.shields.io/badge/target-vgk__rm.sys-blueviolet)
![status](https://img.shields.io/badge/status-static%20analysis-lightgrey)

Independent reverse-engineering study of the platform-integrity, measurement and
attestation surface inside Riot Vanguard's kernel driver (`vgk_rm.sys`).

The work was done privately on a personal lab machine, written up as a
section-by-section reconstruction, and then handed to Riot Games' Vanguard team
so the findings could be triaged and fixed. This repository is the annotated,
readable form of that material.

> **Informational only.** This is a reading reference, not a product. It is not a
> driver you load, not a runtime tool, and not intended to be used as a bypass or
> a replacement for any part of the stack. It exists to explain how a hardened
> platform-security component is put together — nothing more.

Not affiliated with, endorsed by, or published on behalf of Riot Games.

---

## Background

The project started from one deliberately narrow question: *how does this
component decide whether it trusts the machine it is running on?*

Answering it meant going through the security-relevant portion of the driver
from the bottom up — TPM wire protocol, PCR measurement, Secure Boot and BCD
state, HVCI/VBS probes, hardware identifiers, debug-register handling, emulator
fingerprinting, signature verification and the anti-tamper guards around the
image itself. Each area was reconstructed into reference C++ that mirrors the
original control flow, annotated with the address it came from and how confident
the lift is.

Two constraints shaped the output:

- **No runtime dependency.** Nothing here is a DLL, an injector or an overlay.
  All of it is static: source you read, not code you run.
- **Checkability over polish.** Every module keeps the section number, the VA
  anchor and the verification status of the lift, so a reader can re-derive a
  claim instead of trusting it.

When the write-up reached a coherent state it was given to the Vanguard team at
Riot. The purpose was narrow: hand the people who own the component a second,
independent description of what it does and where its assumptions are brittle.
Everything published here was part of that handoff.

Riot's own build remains the source of truth. Where the driver has moved on, this
material is history, not documentation.

Longer write-up of the origin, the handoff and the boundaries of the work:
[docs/background.md](docs/background.md).

## Scope

**In scope** — the parts of the driver that measure, attest and verify a host:
TPM command construction and PCR measurement, EK certificate handling, quote and
credential flows, Secure Boot / UEFI / BCD readers, HVCI / VBS / VTL and
hypervisor probes, composite HWID collection, debug-register paths, emulator and
drift detection, crypto verification, evidence packets, guard chains.

**Out of scope** — the game-facing pieces. No rendering, no entity lists, no offset
tables, no menu code. Those are covered elsewhere; this repository is the security
stack only.

## Methodology

The driver ships obfuscated, so the first stage was to get an unpacked,
string-recovered image and a working IDB. From there the work was static:

1. **Function triage by behaviour**, not by name: TPM TIS/IOCTL plumbing, UEFI
   variable reads, ACPI table walks and crypto imports are all recognisable from
   constants, structure layouts and call shapes alone.
2. **Reconstruction per section.** Each section was lifted with Hex-Rays, then
   corrected against the disassembly where the decompiler lost types, folded
   constants or dropped an argument.
3. **Cross-check.** Two independent views of the same code — decompiler and
   disassembly — plus a third one for the cases where both are ambiguous: the
   surrounding call graph.
4. **Lab validation** where state is observable. TPM command bytes, PCR banks,
   `SetupMode`/`db`/`dbx` presence and the SMBIOS/ATA/EDID sources behind the
   composite identifier can all be observed directly on a real machine and
   compared against what the lift predicts.
5. **Labelling.** Each audited row records a separate status for the decompiled
   view, the disassembly view and the cross-reference check, plus a compounded
   overall status, using the `PASS` / `PARTIAL` / `FAIL` / `UNKNOWN` scale defined
   in `include/vgk/common.hpp`. Problems are left visible rather than smoothed
   over.

The result is 317 sections over roughly 25k lines, with 161 anchors tracked in an
explicit audit table: 151 full lifts, 9 partial, 1 that never resolved. Holes are
left visible on purpose — an honest map with holes is more useful to a reviewer
than a tidy one that quietly guesses.

## What is worth a defender's attention

Observations from the lift. These are description, not vulnerabilities found and
proved — each one is a place where the design makes a decision a reader can
disagree with.

| # | Observation | Where |
|---|-------------|-------|
| 1 | Integrity depends on a chain of measurements (PCR0/7/14 plus an EK whose certificate *profile* is validated in code). The interesting part is the failure path: what the stack does with a host that reports `SetupMode`, a broken EK chain, or an unexpected PPI state, versus a host that simply reports nothing. | SECTION 11, 15-16, 20-22, 34-49 |
| 2 | The composite identifier is assembled from many mutually independent sources — SMBIOS, ATA SMART, NDIS, GPT, EDID, `MachineGuid`. That makes any single source cheap to spoof but expensive to spoof *consistently*; disagreement between sources is itself a signal. | SECTION 24-25, 271, 296-305 |
| 3 | Emulated TPMs are fingerprinted rather than assumed away: known emulator vendor strings plus native-versus-hypervisor TSC delta. The thresholds are worth arguing with. | SECTION 17 (emulator strings), 196, 259 |
| 4 | Debug-register capture and the context-strip behaviour decide which debugger-adjacent states are invisible to the stages that run afterwards. | SECTION 298 |
| 5 | Coverage of the surrounding environment is broad and defensive: a BYOVD string scanner, an `NtProtectVirtualMemory` inline-hook validator and a reflective-loader detector all live on the same scan loop. | SECTION 300, 308, 309 |
| 6 | The image guards itself — hash chain, canaries, guard chain, Authenticode verification of its own body — so the integrity story is recursive, not one-directional. | SECTION 7, 153, 312-313 |

Open questions left in the material:

- How are the severity thresholds in the evidence classifier actually tuned, and
  what is the false-positive budget behind them?
- How do the evidence rings bound themselves under sustained load, and what is
  dropped first when they wrap?
- Which of the probe paths are cheap enough to be worth attacking versus which
  are load-bearing?
- Does the guard chain cover the data the probes consume, or only the code that
  consumes it?

## Repository layout

```
include/vgk/common.hpp     Shared types, audit statuses, research stubs
src/                       Split modules (see src/README.md)
docs/background.md         Origin, handoff, and how to read this as research
docs/architecture.md       How the pieces connect
docs/section-index.md      Every SECTION N with start line
reference/                 Original monolithic lift (unchanged)
tools/                     Notes for future extraction work
```

| Module | Sections | Focus |
|--------|----------|-------|
| `src/01_foundation.cpp` | 0-8 | Types, constants, structs, crypto helpers, TPM open |
| `src/02_tpm_core.cpp` | 9-22 | Builders, PCR, EK/ASN.1, emulator, severity |
| `src/03_identity.cpp` | 23-33 | Secure Boot, HWID report, evidence packet, public surface |
| `src/04_attestation.cpp` | 34-49 | Quote/MakeCredential, hierarchy, master reports |
| `src/05_tpm_extended.cpp` | 50-64 | Sign/Hash/Create/Load/Import/RSA/Startup |
| `src/06_platform.cpp` | 65-99 | UEFI sig lists, Hyper-V, ACPI IOMMU, BCD, Authenticode |
| `src/07_evidence_obf.cpp` | 100-152 | Evidence rings, XOR-IAT, IOCTL path, obfuscation notes |
| `src/08_tamper_auth.cpp` | 153-249 | Self-tamper, Authenticode body, verification tables |
| `src/09_hwid_runtime.cpp` | 250-295 | HWID runtime, IOMMU probes, NDIS/EDID, PCR extend |
| `src/10_detection.cpp` | 296-317 | Catalogs, DR trap, BYOVD notes, scan-loop lifts |

The full SECTION list is in [docs/section-index.md](docs/section-index.md).

## Build status

**Not a drop-in kernel driver.**

The reconstruction assumed a private `precompiled.hpp` (WDK / project-local
headers) which is not part of the dump. The modules are oriented for reading,
cross-referencing VAs and wiring up your own analysis harness:

1. Point includes at your WDK plus research stubs — `include/vgk/common.hpp` is a
   starting point.
2. Compile against `reference/vgk_security_stack.cpp` as a single TU if you need
   one amalgam.
3. Use `docs/section-index.md` to jump by topic.

## Working with the anchors

Anchors in this repository are tied to one image. The example image base used
throughout is `0xFFFFF8013AD40000`; VAs and RVAs move between builds, so treat
them as the coordinates of *that* sample, not as constants.

Against your own `vgk_rm.sys`: rebase to the recorded image base, rebase deltas
from there, and expect the section index to need renumbering where the compiler
or the authors changed ordering. Everything in `src/` is safe to read without
rebasing; the addresses are only there to let you find the same code.

## Provenance

- **Target:** `vgk_rm.sys` — Vanguard kernel-mode component
- **Sample:** one unpacked, deobfuscated image, analysed statically
- **Tooling:** IDA Pro / Hex-Rays, manual disassembly correction, lab observation
- **Distribution:** source only — no Microsoft or Riot binaries are redistributed
  here; you supply your own sample
- **Handoff:** material shared with the Vanguard team; publication here is of the
  same content afterwards

No compile-verified parity with the current driver is claimed. Where this
repository and the live driver disagree, the driver wins.

## By the numbers

| Metric | Value |
|--------|------:|
| Sections | 317 |
| Sections with a start line in the index | 268 |
| Anchors tracked in the audit table | 161 |
| — full lift (all three checks pass) | 151 |
| — partial | 9 |
| — unresolved | 1 |
| Reference monolith | 25,467 lines |
| Modules | 10 |

## Legal

- Copyright (c) 2026 noel. All rights reserved — see [LICENSE](LICENSE).
- Riot, Vanguard, Microsoft, Intel, AMD and the TPM specifications belong to their
  respective owners; names are used descriptively only.
- Published for security research and education: platform integrity, attestation,
  measured boot.
- Third-party reimplementation of observed behaviour. Independently produced, no
  Riot source was used as an input.

## Quick start (reading)

1. Skim [docs/architecture.md](docs/architecture.md)
2. Open [docs/section-index.md](docs/section-index.md) and jump to a SECTION
3. Open the matching `src/0x_*.cpp` module
4. Fall back to `reference/vgk_security_stack.cpp` for the original ordering
