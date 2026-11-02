# Source modules

| File | Sections | Description | Lines |
|------|----------|-------------|------:|
| `src/01_foundation.cpp` | 0-8 | Audit types, constants, wire structs, globals, endian, paths, BCrypt wrappers, anti-tamper chain, TPM open/IOCTL | 1387 |
| `src/02_tpm_core.cpp` | 9-22 | TPM 2.0 builders/parsers, PCR readers, TPM 1.2 fallback, capabilities, ASN.1/EK, emulator, PPI, severity | 1906 |
| `src/03_identity.cpp` | 23-33 | Secure Boot, HWID TPM/SB report, evidence packets, attestation helpers, public surface, self-test | 1322 |
| `src/04_attestation.cpp` | 34-49 | KDFa/AES/HMAC, MakeCredential, Quote verify, ActivateCredential, hierarchy, master orchestrators | 1280 |
| `src/05_tpm_extended.cpp` | 50-64 | Certify/Sign/Hash/HMAC sequences, GetRandom, clock, SelfTest, Create/Load, Import, RSA, Startup | 893 |
| `src/06_platform.cpp` | 65-99 | UEFI signature lists, KEK fingerprints, WDAC, SafeBoot, Hyper-V, ACPI DMAR/IVRS, mitigations, BCD, TPM ACPI | 2345 |
| `src/07_evidence_obf.cpp` | 100-152 | Evidence APC/rings, XOR-IAT catalogue, canaries, IOCTL dispatcher, PE section lookup, obfuscation taxonomy | 3062 |
| `src/08_tamper_auth.cpp` | 153-249 | Self-tamper orchestrator, Authenticode verifier, size tables, production attestation scaffolding | 5215 |
| `src/09_hwid_runtime.cpp` | 250-295 | PCR replay, HWID pipelines, NDIS/EDID, VT-x/VT-d/AMD-Vi, DMA Guard, Pluton, boot HWID schemas | 4310 |
| `src/10_detection.cpp` | 296-999 | HWID/peripheral/anti-debug catalog, handle filter, DR trap, BYOVD scanner, hooks, main scan loop lifts | 5766 |
