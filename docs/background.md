# Background, handoff, and how to read this as research

Companion to the top-level README. It records *why* the material exists and what
was actually shared, so a reviewer can judge the work on its own terms instead of
having to infer intent from the code.

## Origin

Personal lab project, run privately, on one's own time. The subject was chosen
because Vanguard's kernel component is one of the few widely deployed,
well-obfuscated pieces of client-side platform-security code, and because almost
nothing describes what it actually does in terms a defender can check.

The angle was deliberately defensive from the start: not "what does it inspect
that a player could influence", but "what does it believe about a host, on what
evidence, and how brittle is that belief". That framing explains the shape of the
work — heavy on measurement, attestation, signatures and self-guarding, light on
game-facing details.

## How the work was sequenced

1. **Image preparation.** Get to unpacked code and recovered strings, build an IDB,
   confirm the sections of interest still resolve to discrete functions.
2. **Boundary finding.** The platform-security surface is reachable by chase, not by
   name: TPM TIS/IOCTL plumbing leads to command builders, `ExGetFirmwareEnvironmentVariable`
   leads to the UEFI readers, ACPI table walks lead to the DMAR/IVRS probes, BCrypt
   imports lead to the verifiers.
3. **Lift and correct.** Hex-Rays first, then manual correction against disassembly
   for every lost type, folded constant and dropped argument.
4. **Cross-check.** Decompiled view, disassembly view, and call graph. Where the
   three disagree, the section is labelled partial instead of guessed.
5. **Lab confirmation** for observable state — TPM wire bytes, PCR banks,
   `SetupMode`/`db`/`dbx`, and the SMBIOS/ATA/EDID inputs behind the composite
   identifier can be read on a real machine and compared with what the lift predicts.
6. **Write-up**, one section per behaviour, with anchors and status.

## The handoff

Once the material was coherent it was given to the Vanguard team at Riot Games.
The intent was not to file formal bug reports but to hand the owners of the
component an independent description of it: which probes exist, what they read,
what the failure paths do, and where an assumption carries more weight than the
evidence behind it.

What this means in practice:

- Everything published in this repository was part of that material. Nothing new
  was written for publication.
- **No fix is claimed.** Whether any observation was triaged, accepted or worked
  on is Riot's call and is not represented here.
- **No current-build guarantee.** The target image is the one analysed. Vanguard
  moves; where this repository disagrees with a current build, the current build
  is right.
- Nothing here is an official Riot publication, and no Riot review of the text
  should be assumed.

## What is deliberately *not* here

- **No binaries.** No `vgk_rm.sys`, no extracted blob, no redistributed headers.
  The vendor's own software is the authority; this repository only describes it.
- **No runtime component.** No driver to install, no DLL to inject, no overlay.
  The project exists to be read.
- **No game-facing offsets or entity work.** Those already have plenty of coverage
  and would blur the security focus.
- **No trademark or configuration specifics** from the driver's own store, beyond
  what the code needs in order to be legible.

## Reading order for a reviewer

1. Top-level README — scope, method, and the observations flagged as interesting.
2. [`architecture.md`](./architecture.md) — how the subsystems chain together.
3. [`section-index.md`](./section-index.md) — jump straight into a topic.
4. Whichever module the index points at, then the matching lines in
   [`reference/`](../reference/vgk_security_stack.cpp).

## Judging the quality

Two things are worth checking directly, because they carry the weight:

- **The audit table** (types in SECTION 0, rows in `src/03_identity.cpp`)
  records decompile status, disassembly status and xref status per row. A reviewer
  can pull rows that are `PARTIAL` and see whether the stated reason holds.
- **The failure paths.** `src/03_identity.cpp` and `src/04_attestation.cpp` spend
  more lines on what happens when a measurement is absent or malformed than on the
  happy path. That is where the design intent is legible.
