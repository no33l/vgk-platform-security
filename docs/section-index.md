# Section Index

Generated from the original monolithic reference. Line numbers refer to eference/vgk_security_stack.cpp.

| Section | Title | Start line |
|--------:|-------|----------:|
| 0 | audit row + harness types  (C linkage; defined at file bottom) | 46 |
| 1 | constants | 93 |
| 2 | wire-format structs + internal records + installable hooks | 665 |
| 3 | globals | 947 |
| 4 | endian helpers | 1008 |
| 5 | XOR-decoded device / registry path emitters (XOR key 0x5A) | 1057 |
| 6 | BCrypt SHA-256 / SHA-1 one-shot wrappers | 1154 |
| 7 | anti-tamper hash chain + canary feed | 1242 |
| 8 | TPM device open / close + IOCTL submit | 1296 |
| 9 | TPM 2.0 command builders | 1371 |
| 10 | high-level TPM 2.0 wire-call helpers + wire parsers | 1772 |
| 11 | PCR readers (PCR0, PCR7 isolated, PCR14, banks, boot chain) | 2092 |
| 13 | capability helpers (manufacturer, firmware, NV buffer max, | 2326 |
| 14 | ASN.1 DER walker | 2408 |
| 15 | EK cert ASN.1 profile validation | 2448 |
| 16 | EK certificate extraction (NV_ReadPublic + chunked NV_Read) | 2680 |
| 18 | PPI registry probe | 2779 |
| 19 | composite projection + fallback fill | 2832 |
| 20 | EK extraction master + ek_read_public_wrapped | 2857 |
| 21 | EK change detection + history ring + churn analyser | 2988 |
| 22 | severity classification + VAN 68 emission | 3072 |
| 24 | HWID_TPM_SB_REPORT assembler | 3262 |
| 25 | CRC-32 + 'veve' (LE of 0x65766576) HWID evidence packet | 3320 |
| 27 | TCG event log parser + PCR replay  (REMOVED) | 3371 |
| 28 | attestation flow helpers | 3595 |
| 29 | public surface | 3692 |
| 30 | self-test + diagnostic dumps | 3849 |
| 32 | extern "C" audit table + harness (C linkage at file scope) | 23065 |
| 33 | BCrypt safe-close helper (translated from | 3571 |
| 34 | KDFa (SHA-256), AES-CFB, HMAC-SHA256 | 3940 |
| 35 | MakeCredential host-side compute (full TPM2 wrap path) | 4044 |
| 36 | TPM2_Quote signature verifier | 4161 |
| 38 | PCR7 whitelist seeding  (REMOVED) | 3878 |
| 39 | Master attestation orchestrator | 3907 |
| 40 | ActivateCredential host-side unwrap (inverse of SECTION 35) | 4375 |
| 41 | TPM 1.2 deep surface (PERMANENT_FLAGS, STCLEAR_FLAGS, sessions) | 4462 |
| 42 | TPM 2.0 hierarchy + NV admin command builders | 4599 |
| 44 | SecureBoot deep readers (PK, KEK, db, dbx, dbt, dbr, | 4935 |
| 45 | HVCI / Code Integrity / Memory Integrity (MI) | 5058 |
| 48 | Hypervisor detection (CPUID 0x40000000 vendor probe) | 5251 |
| 49 | Master platform-security report aggregator | 4711 |
| 50 | TPM2_Certify (CC 0x148) + TPM2_CertifyCreation (CC 0x14A) | 4775 |
| 51 | Microsoft AIK CA root pinning + cert chain validation | 5303 |
| 52 | TPM2_Sign (CC 0x15D) + TPM2_VerifySignature (CC 0x177) | 5372 |
| 53 | TPM2_Hash (CC 0x17D) + TPM2_HMAC (CC 0x155) | 5438 |
| 54 | HashSequence + EventSequence (crypto-agile PCR_Event) | 5493 |
| 55 | TPM2_GetRandom (CC 0x17B) + TPM2_StirRandom (CC 0x146) | 5582 |
| 56 | TPM2_ReadClock (CC 0x181) + TPM2_ClockSet + ClockRateAdjust | 5633 |
| 57 | TPM2_SelfTest (CC 0x143) + IncrementalSelfTest + GetTestResult | 5688 |
| 58 | TPM2_Create + CreatePrimary + CreateLoaded + Load + LoadExternal | 5722 |
| 59 | TPM2_ContextSave + ContextLoad + EvictControl | 5801 |
| 60 | (consolidated into earlier §8 / §10 NV_Read + NV_ReadPublic | 5859 |
| 61 | TPM2_Startup (CC 0x144) + TPM2_Shutdown (CC 0x145) | 5876 |
| 62 | TPM2_Import (CC 0x156) + TPM2_Duplicate + TPM2_Rewrap | 5930 |
| 63 | TPM2_RSA_Encrypt + TPM2_RSA_Decrypt | 5976 |
| 65 | EFI_SIGNATURE_LIST / EFI_SIGNATURE_DATA parser for db / dbx | 6021 |
| 66 | Microsoft KEK / Production PCA / 3rdParty UEFI CA fingerprints | 6113 |
| 67 | WDAC / SiPolicy file header walker | 6169 |
| 68 | Driver Signing Policy + SafeBoot registry | 6213 |
| 69 | Hyper-V hypercall fingerprints + synth MSR map | 6288 |
| 70 | ACPI DMAR (Intel VT-d) + IVRS (AMD-Vi) ACPI table walker | 6356 |
| 71 | Process mitigation policy + Credential Guard + Control Flow | 6480 |
| 72 | TPM 1.2 deep getters (TPM_PcrRead parse, TPM_GetTickCount, | 6547 |
| 73 | TPM 2.0 vendor manufacturer-ID dictionary | 6579 |
| 74 | TPM2_GetCapability extended (consolidated with §1 constants) | 6635 |
| 75 | Authenticode PE/COFF hash | 6682 |
| 77 | Full TPMS_PCR_SELECTION builder | 7046 |
| 78 | TPM2_PolicyAuthorize (CC 0x16A) signed-update flow + ticket | 7106 |
| 79 | TCG Algorithm Registry (TPM_ALG_*) full table | 7182 |
| 80 | TPMA_OBJECT / TPMA_SESSION / TPMA_LOCALITY / | 7232 |
| 83 | AIK / Attestation Key template (RSA 2048 + SHA-256 signing) | 7315 |
| 84 | Boot Configuration Data (BCD) measured-boot reader | 7348 |
| 86 | ACPI table fetch via SystemFirmwareTableInformation('ACPI') | 6808 |
| 87 | TPM 2.0 ACPI table (TPM2 signature 0x324D5054) parser | 6855 |
| 88 | TCPA table (TPM 1.2 ACPI signature 0x41504354) parser | 6913 |
| 89 | Microsoft AIK extension OIDs + EK Credential profile OIDs | 6952 |
| 90 | IVRS (AMD-Vi) ACPI table walker | 7506 |
| 91 | Master platform-security report extension v2 | 7592 |
| 93 | PCR0-23 baseline catalog | 7790 |
| 94 | Hyper-V hypercall ABI builder | 7879 |
| 95 | IOMMU page-table walker via Intel VT-d DRHD register base | 8017 |
| 96 | vgk_evidence_pool_alloc / free (found by the user researcher, then | 8218 |
| 97 | vgk_authenticode_asn1_signer_scan (found by the user researcher, then | 7677 |
| 97 | vgk_authenticode_asn1_signer_scan (found by the user researcher, then | 8271 |
| 98 | vgk_rsa_pinned_pubkey_db_walk (found by the user researcher, then | 7422 |
| 99 | vgk_syscall_stack_walker_pcr (found by the user researcher, then | 8378 |
| 100 | Evidence APC routine triple (found by the user researcher, then | 8451 |
| 101 | vgk_post_guard_evidence_ring_writer (found by the user researcher, | 7531 |
| 101 | vgk_post_guard_evidence_ring_writer (found by the user researcher, | 8519 |
| 102 | CPU vendor classifier + per-vendor MSR pick + dual evidence-pool ring init | 7638 |
| 102 | CPU vendor classifier + per-vendor MSR pick + dual evidence-pool ring init | 8641 |
| 103 | TPM-EK / SecureBoot HWID composite slot offsets | 8878 |
| 104 | UEFI variable hash chain dispatchers | 8936 |
| 105 | Vanguard boot-status record (found by the user researcher, then | 8983 |
| 106 | Firmware / NMI / DMA-Guard probes (found by the user researcher, | 9141 |
| 107 | Anti-tamper section hash (found by the user researcher, then | 9219 |
| 108 | XOR-IAT catalogue: master deobfuscation table | 9269 |
| 109 | Canary mailbox + cookies: full secret-slot inventory | 9348 |
| 110 | Anti-tamper section hash KeBugCheckEx fail path (found by the | 9434 |
| 111 | Anti-DMA .grfn1 gadget cluster (found by the user researcher, then | 9477 |
| 112 | BCrypt verifier .grfn1 wrapper cluster (found by the user researcher, | 9531 |
| 113 | SHA-1 round-pad constants + monolith address table | 9597 |
| 114 | BCrypt CNG IAT thunks (found by the user researcher, then | 9650 |
| 115 | vgk_evidence_enqueue_passive (found by the user researcher, then | 8544 |
| 115 | vgk_evidence_enqueue_passive (found by the user researcher, then | 9680 |
| 116 | vgk_ioctl_master_dispatcher (verified bit-for-bit from | 8577 |
| 116 | vgk_ioctl_master_dispatcher (found by the user researcher, then | 9709 |
| 116 | vgk_ioctl_master_dispatcher (found by the user researcher, then | 9750 |
| 117 | vgk_ioctl_reservation_gate | 9845 |
| 120 | vgk_multimodule_evidence_collector (prologue stub) | 9988 |
| 121 | vgk_evidence_log_central (prologue stub, biggest of the set) | 10099 |
| 122 | vgk_pe_section_name_lookup_ci body (found by the user researcher, | 10146 |
| 126 | vgk_pe_section_name_lookup_ci body, FULLY DEOBFUSCATED | 10220 |
| 127 | vgk_multimodule_evidence_collector body, FULLY DEOBFUSCATED | 10291 |
| 128 | Vanguard obfuscation taxonomy (extracted across §96-§127) | 10428 |
| 131 | sub_FFFFF8013ADBD7C8 (PE-magic check) | 10464 |
| 135 | vgk_ioctl_acceptlist_filter_ladder @ 0xAD9A304 | 10769 |
| 141 | vgk_ioctl_heartbeat_ping_handler @ 0xAE1C70B | 10832 |
| 143 | NEW binary-database-named XOR-IAT slot pointers discovered this session | 10048 |
| 146 | NEW HWID extraction chain (12 binary-database-named functions) | 11177 |
| 146 | NEW HWID extraction chain (12 binary-database-named functions) | 11293 |
| 147 | Live-binary-database function VA + size reference (.text scan output) | 10328 |
| 147 | Live-binary-database function VA + size reference (.text scan output) | 11241 |
| 147 | Live-binary-database function VA + size reference (.text scan output) | 11357 |
| 148 | BIT-FOR-BIT SIZE VERIFICATION TABLE | 11413 |
| 149 | vgk_pte_present_batch_toggle (NEW binary-database find this session) | 11479 |
| 150 | BCrypt algorithm name string constants (NEW binary-database find) | 11619 |
| 151 | Coverage of .grfn1 obfuscation cluster (356+ functions) | 11652 |
| 152 | Whole-file verification statement | 10620 |
| 152 | Whole-file verification statement | 11685 |
| 153 | vgk_self_tamper_master_orchestrator @ 0xADB409C | 11733 |
| 154 | vgk_module_authenticode_verifier @ 0xADD7E0C | 11796 |
| 155 | vgk_read_boot_guid (NEW binary-database find) | 11853 |
| 156 | HWID extraction functions confirmed as XOR-IAT slots | 11870 |
| 157 | THIRD CONFIRMATION pass invariants | 11901 |
| 158 | VGC boot driver interface surface (19 NEW binary-database symbols) | 11935 |
| 159 | vgk_qpc_bugcheck_bind_companion @ 0xAEDEBEF | 12005 |
| 162 | Final size verification regression check | 10865 |
| 163 | Missing TPM 2.0 algorithm IDs + post-quantum signatures | 10906 |
| 164 | UEFI variable attribute flag bits (per UEFI Spec 2.10 §8.2) | 10928 |
| 165 | DRTM PCR initialization values + Locality 4 launch | 10957 |
| 166 | Microsoft AIK CA + WHQL signing root SHA-1 thumbprints | 10995 |
| 167 | Intel SGX + AMD SEV-SNP attestation report magic + EREPORT | 11036 |
| 168 | Intel VT-d capability register bits (DMAR rev 4.0) | 11070 |
| 169 | AMD-Vi (IVHD) flags + IOMMU control register bits | 11121 |
| 172 | BCrypt + grfn1 helper function VAs (NEW binary-database symbols) | 11270 |
| 177 | New extern declarations (binary-database symbol pointers) | 12020 |
| 178 | PKCS#1 signature algorithm OID strings (NEW binary-database finds) | 12062 |
| 179 | Process gate strings (CONFIRMED via strings_cache) | 12095 |
| 180 | BYOVD (Bring-Your-Own-Vulnerable-Driver) detection strings | 12118 |
| 181 | Late .grfn1 mega-cluster boundary (NEW boundary at 0xD0000000) | 12156 |
| 182 | Newly-found protected-process + detection globals | 12205 |
| 183 | Final post-ready manifest (the file is now this complete) | 12225 |
| 184 | Three .grfn1 VM mega prologues (cracked bit-for-bit) | 12285 |
| 185 | NEW .riot1 SEGMENT discovered (1,168 functions) | 12385 |
| 186 | DI (DLL Injection) detection chain (9 NEW binary-database symbols) | 12415 |
| 187 | Device-scan family (12 NEW binary-database symbols + USB BYOVD detection) | 12439 |
| 188 | Syscall hook detection chain (8 NEW binary-database symbols) | 12465 |
| 189 | Periodic detection orchestrator + remaining symbols | 12492 |
| 190 | ABSOLUTE FINAL STATE post-ready manifest | 12515 |
| 191 | vgk_kill_marker_byte_writer @ 0xAD4BC70 | 12567 |
| 196 | vgk_cpuid_smt_anti_emul @ 0xAD41000 | 12613 |
| 201 | Complete TCG PC Client Platform Firmware Profile event types | 12677 |
| 202 | Windows-specific SIPA (System Integrity Policy Action) types | 12728 |
| 203 | Full PCR replay verifier (TCG SHA-256 bank) | 12791 |
| 204 | Live-TPM vs replayed-PCR cross-check | 12891 |
| 205 | TPM 2.0 PCR_Event command builder (CC 0x0000013C) | 12933 |
| 206 | TPM2_PCR_Read response parser (multi-bank, hash-agile) | 12977 |
| 207 | Boot-time HWID early capture orchestrator | 13114 |
| 208 | SMBIOS Type 1 / Type 2 string + UUID extractors | 13203 |
| 209 | CPUID brand string capture (leaves 0x80000002-04) | 13346 |
| 210 | TPM2_NV_Write builder (CC 0x00000137) | 13385 |
| 211 | TPM2_PolicyOR builder (CC 0x00000171) | 13432 |
| 212 | boot driver hardware capture protocol | 13476 |
| 215 | Boot-time NDIS NIC MAC address enumeration | 13655 |
| 216 | Boot-time GPT/MBR boot disk signature reader | 13710 |
| 217 | Boot-time PCR baseline seal/verify via TPM2_NV | 13726 |
| 218 | Boot-time hardware-identity stable composite hash | 13790 |
| 219 | TPM2_NV_DefineSpace builder (CC 0x0000012A) | 13886 |
| 223 | Boot-time volume serial reader (\\.\C: equivalent) | 13945 |
| 224 | TPM2_PCR_Allocate full response parser | 14019 |
| 225 | Boot orchestrator (full chain: enum disks + NICs + TPM seal) | 14067 |
| 226 | TPM 1.2 wire protocol constants (TCG TPM 1.2 Main Spec Part 2) | 14133 |
| 229 | TPM 2.0 admin/hierarchy command codes + builders | 14246 |
| 230 | TPM 2.0 attestation commands (Quote / Certify / GetTime) | 13813 |
| 230 | TPM 2.0 attestation commands (Quote / Certify / GetTime) | 13828 |
| 230 | TPM 2.0 attestation commands (Quote / Certify / GetTime) | 14382 |
| 230 | TPM 2.0 attestation commands (Quote / Certify / GetTime) | 14536 |
| 231 | ATA SMART data fetch via IOCTL_ATA_PASS_THROUGH | 14503 |
| 232 | NVMe IDENTIFY CONTROLLER via STORAGE_PROTOCOL_COMMAND | 14664 |
| 232 | NVMe IDENTIFY CONTROLLER via STORAGE_PROTOCOL_COMMAND | 14712 |
| 233 | CPUID extended capacity probes (0x80000008 + 0x16 + 0x1A) | 14899 |
| 234 | TPM 2.0 StartAuthSession + PolicySecret + PolicyAuthValue | 14997 |
| 235 | Windows TBS API + TPM 2.0 context management | 15039 |
| 237 | TPM 2.0 GetCapability full property catalog + builder | 15132 |
| 237 | TPM 2.0 GetCapability full property catalog + builder | 15160 |
| 237 | TPM 2.0 GetCapability full property catalog + builder | 15291 |
| 239 | Windows VBS / HVCI / IUM / DeviceGuard probe surface | 15439 |
| 240 | Hyper-V hypercall ABI + synth MSRs (HV TLFS rev B0) | 15612 |
| 241 | Intel TXT (Trusted Execution Technology) MLE header | 15744 |
| 242 | Intel SGX EREPORT structure + capability probe | 15905 |
| 243 | AMD SEV-SNP attestation report (1184 bytes) + GHCB MSR ABI | 16043 |
| 244 | DMAR ACPI table parser (VT-d IOMMU descriptor) | 16200 |
| 245 | IVRS ACPI table parser (AMD-Vi IOMMU descriptor) | 16395 |
| 248 | TCG_EfiSpecIdEvent crypto-agile log header (PFP rev 105 §9.4) | 16904 |
| 250 | Boot-time PCR baseline computation (full chain) | 16984 |
| 251 | TPM 2.0 NV index types (PinPass / Counter / Bits / Extend) | 17109 |
| 251 | TPM 2.0 NV index types (PinPass / Counter / Bits / Extend) | 17134 |
| 252 | Boot driver companion IPC channel (TPM bridge) | 17191 |
| 253 | Windows WMI activation status reader (Slmgr / SPP product key) | 17304 |
| 254 | Runtime (in-game) HWID re-fetch + drift detector | 17342 |
| 255 | TPM 2.0 GetRandom + ReadClock + GetTime command builders | 17456 |
| 256 | PCI Configuration Space access (live device identification) | 17508 |
| 257 | SMBIOS Type 3 (Chassis) + Type 4 (Processor) + Type 17 (Memory) | 17441 |
| 257 | SMBIOS Type 3 (Chassis) + Type 4 (Processor) + Type 17 (Memory) | 17620 |
| 258 | Registry HWID readers (MachineGuid + InstallDate + ProductId) | 16518 |
| 258 | Registry HWID readers (MachineGuid + InstallDate + ProductId) | 17773 |
| 259 | TSC drift watcher + monotonic clock pair | 16676 |
| 260 | Hot-plug enumeration triggers for runtime HWID re-baseline | 17909 |
| 261 | TPM 2.0 NV well-known indexes (TCG Platform Working Group) | 18002 |
| 262 | KUSER_SHARED_DATA boot identification fields | 18097 |
| 263 | Boot disk geometry + GPT partition entry walker | 18261 |
| 264 | ATA SMART threshold + attribute classifier table | 18430 |
| 265 | BCD store + standard well-known objects (BootMgr / OSLoader) | 18537 |
| 266 | Windows ETW system providers for HWID + boot evidence stream | 18662 |
| 267 | Hyper-V VTL register catalog + Secure Kernel surface | 18754 |
| 268 | System Guard SecureLaunch (DRTM) attestation surface | 18852 |
| 269 | Hardware breakpoint + DR-register snapshot via KeSaveExtendedProcessorState | 18941 |
| 270 | TPM 2.0 PolicyAuthValue + PolicyPassword + Signature verify | 19087 |
| 271 | Boot HWID composite output schemas (binary + base64-ready) | 19120 |
| 272 | Pluton + Microsoft TPM softTPM provider identification | 19188 |
| 273 | TPM 2.0 Sign + VerifySignature + Hash command builders | 19263 |
| 276 | TPM 2.0 hash sequence builders (HashSequenceStart/Update/Complete) | 19338 |
| 277 | TPM TIS MMIO transport helpers (locality-aware) | 19409 |
| 278 | AML walker for ACPI _DSM TPM 2.0 PPI (Physical Presence) | 19503 |
| 279 | Network adapter (NDIS) hardware identifier OIDs | 19549 |
| 280 | DXGK display adapter LUID + monitor EDID HWID surface | 19668 |
| 281 | Intel VT-x VMCS field catalog (Intel SDM Vol 3D Appendix B) | 19778 |
| 282 | VT-d IOMMU register catalog (Intel VT-d 4.0 Chapter 11) | 19950 |
| 284 | TPM 2.0 audit session + Command Audit Digest readers | 20021 |
| 285 | HVCI ON/OFF runtime detection (THREE independent methods) | 20120 |
| 286 | VT-d IOMMU runtime MMIO probe (Translation-Enabled verifier) | 20340 |
| 287 | AMD-Vi IOMMU runtime MMIO probe (IOMMUEn verifier) | 20429 |
| 288 | DMA Guard policy + Kernel DMA Protection runtime probe | 20502 |
| 289 | Companion (boot) driver-to-userland HWID collection commands | 20581 |
| 290 | TPM 2.0 PCR per-bank parallel extend orchestration | 20663 |
| 291 | VT-d Root + Context table walker (4-level page-table base) | 20765 |
| 292 | PCI capability list walker (status+capability_ptr -> linked list) | 20903 |
| 296 | VERIFIED HWID / PERIPHERAL / ANTI-DEBUG CATALOG | 19989 |
| 296 | Found-by-researcher / decompile-verified HWID / PERIPHERAL / ANTI-DEBUG CATALOG | 21013 |
| 296 | Found-by-researcher / decompile-verified HWID / PERIPHERAL / ANTI-DEBUG CATALOG | 21155 |
| 297 | VGC HANDLE PROTECTION FILTER (vgk_ob_handle_filter_master) | 21134 |
| 297 | VGC HANDLE PROTECTION FILTER (vgk_ob_handle_filter_master) | 21291 |
| 298 | DEBUG REGISTER TRAP CAPTURE (vgk_dr_trap_context_capture) | 21348 |
| 299 | HWID NAL DEVICE DIRECT READER | 21483 |
| 300 | REFLECTIVE DLL INJECTION DETECTOR | 21540 |
| 305 | MONITOR EDID FULL HWID EXTRACTION | 21630 |
| 306 | PRODUCTION-READINESS ATTESTATION | 21703 |
| 307 | HWID BAN ACTIVE ENFORCEMENT DISPATCH | 21745 |
| 307 | HWID BAN ACTIVE ENFORCEMENT DISPATCH | 21901 |
| 308 | BYOVD (BRING-YOUR-OWN-VULNERABLE-DRIVER) STRING SCANNER | 21888 |
| 309 | NtProtectVirtualMemory INLINE HOOK VALIDATOR | 22092 |
| 311 | R12 BIT-FOR-BIT LIFT COMPENDIUM | 20815 |
| 312 | vgk_self_tamper_master_orchestrator_body @ 0xAE42678 | 23756 |
| 313 | vgk_module_authenticode_verifier @ 0xADD7E0C | 24610 |
| 314 | R15 BATCH CLEAN HAND-TRANSLATIONS (sequential 4-per-turn) | 24766 |
| 315 | DECOMPILER UNLIFTABLE: vgk_main_scan_loop_thread @ 0xAD45D38 | 25504 |
| 317 | R19 final-three batch  ---------------------------------------- | 26004 |
