# Architecture map

High-level view of how the reconstructed Vanguard platform-security surface is organized in this repo.

Part of a private research study of the stack, later shared with the vendor.
Informational reference only — not a runtime component, not a bypass. Background
and scope: [background.md](./background.md).<br>

## Data flow (conceptual)

```
                    host / kernel environment
                              |
              +---------------+----------------+
              |               |                |
         TPM device      UEFI variables    Hardware IDs
         (IOCTL/TIS)     (Secure Boot)   (SMBIOS/ATA/NDIS)
              |               |                |
              v               v                v
        +-----------+  +------------+  +--------------+
        | TPM wire  |  | SB / BCD   |  | HWID collect |
        | builders  |  | readers    |  | + drift check|
        +-----+-----+  +------+-----+  +------+-------+
              |               |                |
              +-------+-------+--------+-------+
                      |                |
                      v                v
               PCR / EK / Quote   composite HWID
               attestation        evidence packet
                      |                |
                      +--------+-------+
                               |
                               v
                    severity + evidence log
                    (VAN-style tags, rings)
                               |
                               v
                    anti-tamper / self-hash
                    + periodic scan loop
```

## Module dependency sketch

```
01_foundation
    ^
    |-- 02_tpm_core
    |       ^
    |       |-- 03_identity
    |       |-- 04_attestation
    |       |-- 05_tpm_extended
    |
    |-- 06_platform
    |-- 07_evidence_obf
    |-- 08_tamper_auth
    |-- 09_hwid_runtime
    |-- 10_detection
```

Everything was originally one translation unit. After the split, modules still
assume shared globals, constants, and helpers from earlier sections. Treat
cross-module calls as **reference links**, not as a cleaned public API.

## Important orchestrators (search these names)

| Symbol / topic | Rough home | Role |
|----------------|------------|------|
| Master attestation orchestrator | SECTION 39 / `04_attestation.cpp` | End-to-end TPM attestation path |
| Platform-security report aggregator | SECTION 49 / `04_attestation.cpp` | Roll-up report |
| IOCTL master dispatcher | SECTION 116 / `07_evidence_obf.cpp` | Control-code routing |
| Self-tamper master orchestrator | SECTION 153 / 312 | Integrity / guard chain |
| Main scan loop thread | SECTION 315 / `10_detection.cpp` | Periodic detection loop (manual lift) |
| HWID composite / evidence packet | SECTIONS 24-25, 271 | Identity blob layouts |

## Verification tiers used in the dump

The original author tracked per-topic status with:

- decompile fidelity
- disassembly check
- cross-reference consistency

See SECTION 0 / audit table types in `include/vgk/common.hpp` and the large
audit table near the end of the monolith (`SECTION 32` in `10_detection` or
the full table in `reference/`).

## Binary anchors (examples)

These appear throughout comments as live VA anchors (example image base used
in the dump: `0xFFFFF8013AD40000`). They are research markers, not guarantees
for every Vanguard build:

- HWID family region around `0xFFFFF8013AD58A40` - `0xFFFFF8013AD5B770`
- Various named lifts (`vgk_machine_guid_capture`, `emit_evidence_packet`, ...)

Always re-verify against **your** sample; RVAs move between builds.

## How to navigate by research goal

| Goal | Start here |
|------|------------|
| TPM command formats | `02_tpm_core.cpp` SECTION 9-10 |
| PCR measurement | `02_tpm_core.cpp` SECTION 11; later replay SECTIONS in `09_*` |
| Secure Boot variables | `03_identity.cpp` SECTION 23; deep readers SECTION 44 in `04_*`/`06_*` |
| HWID schema | `03_identity.cpp` 24-25; `09_hwid_runtime.cpp`; catalog in `10_detection.cpp` |
| HVCI / hypervisor | `06_platform.cpp`, later runtime probes in `09_*` |
| Obfuscation / XOR-IAT | `07_evidence_obf.cpp` SECTION 108+ |
| Detection loop | `10_detection.cpp` SECTION 315+ |
