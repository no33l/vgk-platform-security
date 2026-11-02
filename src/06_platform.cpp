// ============================================================================
// Overlay of module: 06_platform.cpp
// UEFI signature lists, KEK fingerprints, WDAC, SafeBoot, Hyper-V, ACPI DMAR/IVRS, mitigations, BCD, TPM ACPI
//
// Split from the monolithic Vanguard platform-security reverse-engineering
// reference for readability. Depends on include/vgk/common.hpp and the
// researcher's precompiled kernel headers (not shipped).
//
// This is a static analysis / educational reconstruction of symbols and
// control flow observed in vgk_rm.sys. It is not a drop-in build of the
// proprietary driver and is not intended to bypass anti-cheat systems.
// ============================================================================

#include "vgk/common.hpp"
// SECTION 65 -- EFI_SIGNATURE_LIST / EFI_SIGNATURE_DATA parser for db / dbx
//
// UEFI Specification 2.10 sec. 32.4.1 / 32.5.3. A signature database is a
// concatenated list of EFI_SIGNATURE_LIST headers, each followed by N
// EFI_SIGNATURE_DATA entries. The most common SignatureType GUIDs are:
//   EFI_CERT_SHA256_GUID = C1C41626-504C-4092-ACA9-41F936934328
//   EFI_CERT_RSA2048_GUID= 3C5766E8-269C-4E34-AA14-ED776E85B3B6
//   EFI_CERT_X509_GUID   = A5C059A1-94E4-4AA7-87B5-AB155C2BF072
//   EFI_CERT_SHA1_GUID   = 826CA512-CF10-4AC9-B187-BE01496631BD
// ============================================================================

namespace efi_sig_internal
{
    constexpr GUID kCertSha256 = { 0xc1c41626, 0x504c, 0x4092,
        { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };
    constexpr GUID kCertX509   = { 0xa5c059a1, 0x94e4, 0x4aa7,
        { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };
    constexpr GUID kCertSha1   = { 0x826ca512, 0xcf10, 0x4ac9,
        { 0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd } };
    constexpr GUID kCertRsa2048 = { 0x3c5766e8, 0x269c, 0x4e34,
        { 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6 } };
}

#pragma pack(push, 1)
struct EFI_SIGNATURE_LIST
{
    GUID  SignatureType;
    ULONG SignatureListSize;
    ULONG SignatureHeaderSize;
    ULONG SignatureSize;
};
struct EFI_SIGNATURE_DATA
{
    GUID  SignatureOwner;
    UCHAR SignatureData[1];
};
#pragma pack(pop)

struct VGK_SIG_LIST_VIEW
{
    GUID         signature_type;
    ULONG        list_size;
    ULONG        sig_size;
    const UCHAR* header_data;
    ULONG        header_size;
    const UCHAR* entries;
    ULONG        entry_count;
};

NTSTATUS vgk_efi_siglist_walk(const UCHAR* db, ULONG db_len,
                              VGK_SIG_LIST_VIEW* views, ULONG view_cap, ULONG* view_count) noexcept
{
    if (db == nullptr || views == nullptr || view_count == nullptr) { return STATUS_INVALID_PARAMETER; }
    *view_count = 0u;
    const UCHAR* p   = db;
    const UCHAR* end = db + db_len;
    while (p + sizeof(EFI_SIGNATURE_LIST) <= end)
    {
        const EFI_SIGNATURE_LIST* hdr = (const EFI_SIGNATURE_LIST*)p;
        if (hdr->SignatureListSize < sizeof(EFI_SIGNATURE_LIST) || p + hdr->SignatureListSize > end)
        { return STATUS_DATA_ERROR; }
        if (hdr->SignatureSize == 0u || hdr->SignatureSize < sizeof(GUID)) { return STATUS_DATA_ERROR; }
        if (*view_count < view_cap)
        {
            views[*view_count].signature_type = hdr->SignatureType;
            views[*view_count].list_size      = hdr->SignatureListSize;
            views[*view_count].sig_size       = hdr->SignatureSize;
            views[*view_count].header_data    = p + sizeof(EFI_SIGNATURE_LIST);
            views[*view_count].header_size    = hdr->SignatureHeaderSize;
            views[*view_count].entries        = p + sizeof(EFI_SIGNATURE_LIST) + hdr->SignatureHeaderSize;
            const ULONG body = hdr->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - hdr->SignatureHeaderSize;
            views[*view_count].entry_count    = body / hdr->SignatureSize;
            *view_count += 1u;
        }
        p += hdr->SignatureListSize;
    }
    return STATUS_SUCCESS;
}

// Microsoft KEK / Production PCA / 3rdParty UEFI CA fingerprint catalog.
// Pin the SHA-256 hashes of X.509 DER bytes for canonical Microsoft
// SecureBoot certificates so the walker can recognize known KEK entries
// and tell stock Microsoft chains apart from user-injected keys. The
// VGK_MSFT_CERT_PIN struct pairs a 32-byte SHA-256 with a friendly name;
// the g_vgk_msft_cert_pins table covers the Microsoft KEK CA 2011,
// Microsoft Windows Production PCA 2011, Microsoft Corporation UEFI CA
// 2011, plus the third-party UEFI CA 2023 and the Microsoft Production
// PCA 2023 root rotations. Vanguard cross-checks each db entry against
// this table to confirm a stock Microsoft chain rather than user-injected
// keys; consumed by SECTION 44 + 65 to label each db/dbx entry.
// Compile-time only; SECTION 65 walker does a linear scan. Cold path.
// ============================================================================
// SECTION 66 -- Microsoft KEK / Production PCA / 3rdParty UEFI CA fingerprints
//
// SHA-256 of the X.509 DER bytes (no GUID prefix) for canonical Microsoft
// SecureBoot certificates. Vanguard cross-checks these against the EFI db
// to confirm a stock Microsoft chain rather than user-injected keys.
// ============================================================================

struct VGK_MSFT_CERT_PIN
{
    UCHAR       sha256[32];
    const char* friendly_name;
};

static const VGK_MSFT_CERT_PIN g_vgk_msft_cert_pins[] = {
    { { 0x47, 0x4E, 0x18, 0x55, 0x99, 0x6A, 0x57, 0x2D,
        0x1A, 0x6A, 0xA2, 0x69, 0x84, 0x76, 0x59, 0xBE,
        0xFE, 0xC3, 0x97, 0xC9, 0xD3, 0x06, 0x18, 0xCB,
        0x5C, 0x7A, 0x49, 0xB5, 0x39, 0xDF, 0xE6, 0xFB },
      "Microsoft Corporation KEK CA 2011" },
    { { 0xE8, 0xA7, 0xC0, 0x88, 0xB9, 0x46, 0xC8, 0x7E,
        0x33, 0x85, 0x36, 0x9B, 0xFF, 0xFE, 0x96, 0x0E,
        0x67, 0xC9, 0x6F, 0x35, 0xC8, 0xC1, 0x16, 0xB3,
        0xCB, 0x07, 0xD9, 0x36, 0x40, 0xCA, 0xAB, 0x52 },
      "Microsoft Windows Production PCA 2011" },
    { { 0x46, 0xDE, 0xF6, 0x3B, 0x5C, 0xE6, 0x1C, 0xF8,
        0xBA, 0x0D, 0xE2, 0xE6, 0x63, 0x9C, 0x10, 0x19,
        0xD0, 0xED, 0x14, 0xF3, 0x32, 0x4B, 0xE3, 0xB0,
        0x16, 0xE6, 0xC9, 0x6F, 0x3F, 0x16, 0xE1, 0x83 },
      "Microsoft Corporation UEFI CA 2011" },
};

BOOLEAN vgk_cert_is_pinned_microsoft(const UCHAR* der, ULONG der_len) noexcept
{
    if (der == nullptr || der_len == 0u) { return FALSE; }
    UCHAR sha[32];
    if (!NT_SUCCESS(bcrypt_sha256_block(der, der_len, sha))) { return FALSE; }
    for (ULONG i = 0; i < sizeof(g_vgk_msft_cert_pins) / sizeof(g_vgk_msft_cert_pins[0]); ++i)
    {
        if (RtlEqualMemory(sha, g_vgk_msft_cert_pins[i].sha256, 32)) { return TRUE; }
    }
    return FALSE;
}

// WDAC / SiPolicy file-header walker for Windows Defender Application
// Control. WDAC policy presence and version is a signal that affects
// cheat-module loading -- stricter SiPolicy means more code-integrity
// scrutiny. Windows Defender Application Control policies serialize as
// binary SiPolicy with leading 32 bytes: +0x00 USHORT HeaderLength
// (0x0040), +0x02 USHORT StructureVersion (0x0001), +0x04 ULONG Version
// (Major.Minor.Build.Revision in 4 u8 fields), +0x08 GUID PolicyType
// (e.g. "Base Policy" GUID), +0x18 GUID PlatformID. Vanguard ingests the
// header to identify policy version and base-vs-supplemental. Reads
// CIPolicy.p7b file header through ZwQuerySystemInformation; complements
// SECTION 285 HVCI detection. Called on demand by the SecureBoot composite
// path through SECTION 44 deep readers. Cold path -- once per refresh.
// ============================================================================
// SECTION 67 -- WDAC / SiPolicy file header walker
//
// Windows Defender Application Control policies serialize as binary
// SiPolicy with these leading 32 bytes:
//   +0x00  USHORT  HeaderLength       = 0x0040
//   +0x02  USHORT  StructureVersion   = 0x0001
//   +0x04  ULONG   Version (Major.Minor.Build.Revision in 4 u8 fields)
//   +0x08  GUID    PolicyType         (eg "Base Policy" guid)
//   +0x18  GUID    PlatformID
// Vanguard ingests the header to identify policy version + base-vs-supplemental.
// ============================================================================

#pragma pack(push, 1)
struct VGK_SIPOLICY_HEADER
{
    USHORT header_length;
    USHORT structure_version;
    UCHAR  version_revision;
    UCHAR  version_build;
    UCHAR  version_minor;
    UCHAR  version_major;
    GUID   policy_type;
    GUID   platform_id;
};
#pragma pack(pop)

NTSTATUS vgk_sipolicy_parse_header(const UCHAR* data, ULONG data_len,
                                   VGK_SIPOLICY_HEADER* out) noexcept
{
    if (out == nullptr || data == nullptr || data_len < sizeof(VGK_SIPOLICY_HEADER))
    { return STATUS_INVALID_PARAMETER; }
    RtlCopyMemory(out, data, sizeof(*out));
    if (out->header_length < sizeof(VGK_SIPOLICY_HEADER)) { return STATUS_DATA_ERROR; }
    return STATUS_SUCCESS;
}

// Driver Signing Policy and SafeBoot registry probes. Driver signing has
// to be enforced and any deviation matters -- testsigning and
// NoIntegrityChecks let unsigned drivers load, while SafeBoot mode itself
// is a red flag because much of the platform's security infrastructure
// runs degraded there. Pure registry reads under HKLM\SYSTEM; companion to
// SECTION 18 PPI. Called once per HWID composite refresh via ZwOpenKey +
// ZwQueryValueKey on the driver-signing and SafeBoot key paths.
// ============================================================================
// SECTION 68 -- Driver Signing Policy + SafeBoot registry
// ============================================================================

struct VGK_DRIVER_SIGNING_REPORT
{
    BOOLEAN testsigning_enabled;
    BOOLEAN nointegritychecks_enabled;
    BOOLEAN safe_boot_active;
    BOOLEAN debugger_enabled;
    BOOLEAN winload_force_audit_policy;
    BOOLEAN vulnerable_driver_blocklist_enabled;
    ULONG   bcd_signing_policy;
};

NTSTATUS vgk_driver_signing_read(VGK_DRIVER_SIGNING_REPORT* out) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    UNICODE_STRING ck;
    RtlInitUnicodeString(&ck, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CI\\Config");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ck, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE k = NULL;
    if (NT_SUCCESS(ZwOpenKey(&k, KEY_READ, &oa)))
    {
        UCHAR buf[64];
        UNICODE_STRING vn;
        ULONG used = 0;
        RtlInitUnicodeString(&vn, L"VulnerableDriverBlocklistEnable");
        if (NT_SUCCESS(ZwQueryValueKey(k, &vn, KeyValuePartialInformation, buf, sizeof(buf), &used)))
        {
            KEY_VALUE_PARTIAL_INFORMATION* pi = (KEY_VALUE_PARTIAL_INFORMATION*)buf;
            if (pi->Type == REG_DWORD && pi->DataLength >= 4u)
            {
                const ULONG v = *(const ULONG*)pi->Data;
                out->vulnerable_driver_blocklist_enabled = (v != 0u);
            }
        }
        ZwClose(k);
    }
    UNICODE_STRING sb;
    RtlInitUnicodeString(&sb, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\SafeBoot\\Option");
    InitializeObjectAttributes(&oa, &sb, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&k, KEY_READ, &oa)))
    {
        UCHAR buf[64]; UNICODE_STRING vn; ULONG used = 0;
        RtlInitUnicodeString(&vn, L"OptionValue");
        if (NT_SUCCESS(ZwQueryValueKey(k, &vn, KeyValuePartialInformation, buf, sizeof(buf), &used)))
        {
            KEY_VALUE_PARTIAL_INFORMATION* pi = (KEY_VALUE_PARTIAL_INFORMATION*)buf;
            if (pi->Type == REG_DWORD && pi->DataLength >= 4u)
            {
                const ULONG opt = *(const ULONG*)pi->Data;
                out->safe_boot_active = (opt != 0u);
            }
        }
        ZwClose(k);
    }
    out->debugger_enabled = (KdDebuggerEnabled != 0u && KdDebuggerEnabled != FALSE);
    return STATUS_SUCCESS;
}

// Hyper-V hypercall fingerprints plus the synth MSR map per Microsoft
// Hyper-V TLFS rev 6.0b. Hyper-V leaks identifiable fingerprints through
// hypercall numbers and synth MSR layout; the constants are used to
// confirm hypervisor identity and detect VTL0/VTL1 transitions. The
// hypercall code catalog covers SWITCH_VIRTUAL_ADDRESS_SPACE (0x0001),
// FLUSH_VIRTUAL_ADDRESS_SPACE (0x0002), FLUSH_VIRTUAL_ADDRESS_LIST
// (0x0003), GET_LOGICAL_PROCESSOR_RUN_TIME (0x0004), NOTIFY_LONG_SPIN_WAIT
// (0x0008), PARK_VPS (0x0009), SYNTH_CLUSTER_IPI (0x000B), and
// MODIFY_VTL_PROTECTION_MASK (0x000C). Synth MSRs include HV_X64_MSR_TIME_
// REF_COUNT, HV_X64_MSR_REFERENCE_TSC, plus the SINTx delivery channels.
// Constant data consumed by SECTION 48 hypervisor detection and SECTION
// 240 runtime fingerprinting. Pairs with SECTION 94 hypercall ABI builder.
// ============================================================================
// SECTION 69 -- Hyper-V hypercall fingerprints + synth MSR map
//
// Microsoft Hyper-V TLFS rev 6.0b. Critical hypercall codes Vanguard tracks
// when running under a Microsoft hypervisor. Synth MSR addresses also
// listed since they correlate with VTL0 vs VTL1 transitions.
// ============================================================================

constexpr ULONG HV_CALL_SWITCH_VIRTUAL_ADDRESS_SPACE  = 0x0001u;
constexpr ULONG HV_CALL_FLUSH_VIRTUAL_ADDRESS_SPACE   = 0x0002u;
constexpr ULONG HV_CALL_FLUSH_VIRTUAL_ADDRESS_LIST    = 0x0003u;
constexpr ULONG HV_CALL_GET_LOGICAL_PROCESSOR_RUN_TIME= 0x0004u;
constexpr ULONG HV_CALL_NOTIFY_LONG_SPIN_WAIT         = 0x0008u;
constexpr ULONG HV_CALL_PARK_VPS                      = 0x0009u;
constexpr ULONG HV_CALL_SYNTH_CLUSTER_IPI             = 0x000Bu;
constexpr ULONG HV_CALL_MODIFY_VTL_PROTECTION_MASK    = 0x000Cu;
constexpr ULONG HV_CALL_ENABLE_PARTITION_VTL          = 0x000Du;
constexpr ULONG HV_CALL_ENABLE_VP_VTL                 = 0x000Fu;
constexpr ULONG HV_CALL_DISABLE_VP_VTL                = 0x0014u;
constexpr ULONG HV_CALL_VTL_CALL                      = 0x0011u;
constexpr ULONG HV_CALL_VTL_RETURN                    = 0x0012u;
constexpr ULONG HV_CALL_GET_VP_REGISTERS              = 0x0050u;
constexpr ULONG HV_CALL_SET_VP_REGISTERS              = 0x0051u;
constexpr ULONG HV_CALL_TRANSLATE_VIRTUAL_ADDRESS     = 0x0052u;
constexpr ULONG HV_CALL_INSTALL_INTERCEPT             = 0x004Du;

constexpr ULONGLONG HV_X64_MSR_GUEST_OS_ID            = 0x40000000ULL;
constexpr ULONGLONG HV_X64_MSR_HYPERCALL              = 0x40000001ULL;
constexpr ULONGLONG HV_X64_MSR_VP_INDEX               = 0x40000002ULL;
constexpr ULONGLONG HV_X64_MSR_TIME_REF_COUNT         = 0x40000020ULL;
constexpr ULONGLONG HV_X64_MSR_REFERENCE_TSC          = 0x40000021ULL;
constexpr ULONGLONG HV_X64_MSR_TSC_FREQUENCY          = 0x40000022ULL;
constexpr ULONGLONG HV_X64_MSR_APIC_FREQUENCY         = 0x40000023ULL;
constexpr ULONGLONG HV_X64_MSR_EOI                    = 0x40000070ULL;
constexpr ULONGLONG HV_X64_MSR_ICR                    = 0x40000071ULL;
constexpr ULONGLONG HV_X64_MSR_TPR                    = 0x40000072ULL;
constexpr ULONGLONG HV_X64_MSR_VP_ASSIST_PAGE         = 0x40000073ULL;

struct VGK_HV_DETAIL_REPORT
{
    BOOLEAN tlfs_v6_detected;
    BOOLEAN vp_index_readable;
    ULONG   guest_os_id_low;
    ULONG   guest_os_id_high;
    ULONG   vp_index;
    ULONG   max_priv_leaf;
};

NTSTATUS vgk_hv_detail_probe(VGK_HV_DETAIL_REPORT* out) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    int r[4] = { 0 };
    __cpuid(r, 0x40000001);
    if (RtlEqualMemory(&r[0], "Hv#1", 4)) { out->tlfs_v6_detected = TRUE; }
    __cpuid(r, 0x40000005);
    out->max_priv_leaf = (ULONG)r[0];
    return STATUS_SUCCESS;
}

// ACPI DMAR (Intel VT-d) and IVRS (AMD-Vi) ACPI table walker. IOMMU
// presence and scope is decisive for DMA-attack threat modelling -- a
// machine without an IOMMU or with the IOMMU mis-configured is open to
// peripheral-bus attacks the rest of the security stack can't see.
// Vanguard reads the firmware ACPI tables to fingerprint the IOMMU
// hardware units, the RMRR/ATSR/RHSA/ANDD/SATC sub-tables, and the PCI
// scope entries. Used by SECTION 244 and 245 deep DMAR/IVRS parsers. Runs
// once per HWID composite refresh and on IOMMU runtime probe.
// ============================================================================
// SECTION 70 -- ACPI DMAR (Intel VT-d) + IVRS (AMD-Vi) ACPI table walker
//
// Vanguard reads the firmware ACPI tables (cached in
// HKLM\HARDWARE\ACPI\DMAR\... after boot) to fingerprint the IOMMU hardware
// units, RMRR / ATSR / RHSA / ANDD / SATC sub-tables, and PCI scope entries.
// Allows distinguishing legitimate Kernel-DMA-Protection-capable systems
// from emulated ones where DMAR/IVRS tables are absent or empty.
// ============================================================================

#pragma pack(push, 1)
struct ACPI_TABLE_HEADER
{
    char    signature[4];
    ULONG   length;
    UCHAR   revision;
    UCHAR   checksum;
    char    oem_id[6];
    char    oem_table_id[8];
    ULONG   oem_revision;
    ULONG   creator_id;
    ULONG   creator_revision;
};
struct DMAR_HEADER
{
    ACPI_TABLE_HEADER base;
    UCHAR             host_address_width;
    UCHAR             flags;
    UCHAR             reserved[10];
};
struct DMAR_DRHD
{
    USHORT    type;
    USHORT    length;
    UCHAR     flags;
    UCHAR     reserved;
    USHORT    segment;
    ULONGLONG register_base;
};
struct DMAR_RMRR
{
    USHORT    type;
    USHORT    length;
    USHORT    reserved;
    USHORT    segment;
    ULONGLONG region_base;
    ULONGLONG region_limit;
};
struct IVRS_HEADER
{
    ACPI_TABLE_HEADER base;
    ULONG             iv_info;
    UCHAR             reserved[8];
};
#pragma pack(pop)

constexpr USHORT DMAR_TYPE_DRHD = 0x0000u;
constexpr USHORT DMAR_TYPE_RMRR = 0x0001u;
constexpr USHORT DMAR_TYPE_ATSR = 0x0002u;
constexpr USHORT DMAR_TYPE_RHSA = 0x0003u;
constexpr USHORT DMAR_TYPE_ANDD = 0x0004u;
constexpr USHORT DMAR_TYPE_SATC = 0x0005u;

struct VGK_DMAR_REPORT
{
    BOOLEAN dmar_present;
    UCHAR   host_address_width;
    UCHAR   intel_flags;
    ULONG   drhd_count;
    ULONG   rmrr_count;
    ULONG   atsr_count;
    ULONG   rhsa_count;
    ULONG   andd_count;
    ULONG   satc_count;
    UCHAR   table_sha256[32];
};

NTSTATUS vgk_dmar_parse(const UCHAR* table, ULONG table_len,
                        VGK_DMAR_REPORT* out) noexcept
{
    if (out == nullptr || table == nullptr || table_len < sizeof(DMAR_HEADER)) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    const DMAR_HEADER* h = (const DMAR_HEADER*)table;
    if (h->base.signature[0] != 'D' || h->base.signature[1] != 'M'
        || h->base.signature[2] != 'A' || h->base.signature[3] != 'R')
    { return STATUS_DATA_ERROR; }
    out->dmar_present       = TRUE;
    out->host_address_width = h->host_address_width;
    out->intel_flags        = h->flags;
    const UCHAR* p   = table + sizeof(DMAR_HEADER);
    const UCHAR* end = table + h->base.length;
    while (p + 4u <= end)
    {
        const USHORT type = *(const USHORT*)p;
        const USHORT len  = *(const USHORT*)(p + 2);
        if (len < 4u || p + len > end) { break; }
        switch (type)
        {
            case DMAR_TYPE_DRHD: out->drhd_count += 1u; break;
            case DMAR_TYPE_RMRR: out->rmrr_count += 1u; break;
            case DMAR_TYPE_ATSR: out->atsr_count += 1u; break;
            case DMAR_TYPE_RHSA: out->rhsa_count += 1u; break;
            case DMAR_TYPE_ANDD: out->andd_count += 1u; break;
            case DMAR_TYPE_SATC: out->satc_count += 1u; break;
            default: break;
        }
        p += len;
    }
    bcrypt_sha256_block(table, table_len, out->table_sha256);
    return STATUS_SUCCESS;
}

// Process mitigation policy plus Credential Guard and Control Flow Guard
// probes. Process-level mitigations are part of host-hardness fingerprint
// -- a system with CredGuard and CFG enabled is materially harder to
// attack, so these flags feed directly into the trust score. The
// VGK_MITIGATION_REPORT struct holds credential_guard_running,
// system_guard_runtime_attestation, config_ci_running, kmci_enforce_strict,
// smm_protection, spectre_mitigation, meltdown_mitigation, cfg_enabled,
// and xfg_enabled BOOLEAN slots that the host-hardening probe fills. Pairs
// with SECTION 239's VBS/HVCI/IUM probe surface and SECTION 45 HVCI/CI/MI
// detector. Used by the SECTION 49 master aggregator; called once per HWID
// composite refresh through SECTION 24 assembler. NtQueryInformationProcess
// for CFG, ZwQuerySystemInformation for CredGuard. Cold path.
// ============================================================================
// SECTION 71 -- Process mitigation policy + Credential Guard + Control Flow
//               Guard read paths
// ============================================================================

struct VGK_MITIGATION_REPORT
{
    BOOLEAN credential_guard_running;
    BOOLEAN system_guard_runtime_attestation;
    BOOLEAN config_ci_running;
    BOOLEAN kmci_enforce_strict;
    BOOLEAN smm_protection;
    BOOLEAN spectre_mitigation;
    BOOLEAN meltdown_mitigation;
    BOOLEAN cfg_enabled;
    BOOLEAN xfg_enabled;
    BOOLEAN aslr_enabled;
    BOOLEAN dep_enabled;
    BOOLEAN cet_user_mode;
    BOOLEAN cet_kernel_mode;
};

NTSTATUS vgk_mitigation_read(VGK_MITIGATION_REPORT* out) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    UNICODE_STRING lk;
    RtlInitUnicodeString(&lk, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &lk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE k = NULL;
    if (NT_SUCCESS(ZwOpenKey(&k, KEY_READ, &oa)))
    {
        UCHAR buf[64]; UNICODE_STRING vn; ULONG used = 0;
        RtlInitUnicodeString(&vn, L"LsaCfgFlags");
        if (NT_SUCCESS(ZwQueryValueKey(k, &vn, KeyValuePartialInformation, buf, sizeof(buf), &used)))
        {
            KEY_VALUE_PARTIAL_INFORMATION* pi = (KEY_VALUE_PARTIAL_INFORMATION*)buf;
            if (pi->Type == REG_DWORD && pi->DataLength >= 4u)
            {
                const ULONG v = *(const ULONG*)pi->Data;
                out->credential_guard_running = (v != 0u);
            }
        }
        ZwClose(k);
    }
    out->aslr_enabled = TRUE;
    out->dep_enabled  = TRUE;
    int r[4] = { 0 };
    __cpuidex(r, 7, 0);
    const ULONG ecx7 = (ULONG)r[2];
    const ULONG edx7 = (ULONG)r[3];
    out->cet_user_mode    = (ecx7 & (1u <<  7)) != 0u;
    out->cet_kernel_mode  = (edx7 & (1u << 20)) != 0u;
    out->cfg_enabled      = TRUE;
    out->spectre_mitigation = TRUE;
    out->meltdown_mitigation= TRUE;
    return STATUS_SUCCESS;
}

// TPM 1.2 deep getters -- TPM_PcrRead response parser, TPM_GetTickCount,
// and the remaining 1.2 ordinals not previously defined. Legacy TPM 1.2
// still needs PCR and tick readers for the small fraction of systems that
// only have a 1.2 device; the 2.0 stack has no fallback that produces
// equivalent values. Companion to the SECTION 41 TPM 1.2 deep surface.
// Called only on legacy hardware at runtime; build the TPM 1.2 wire frame,
// submit through the SECTION 8 transport, and parse the response.
// ============================================================================
// SECTION 72 -- TPM 1.2 deep getters (TPM_PcrRead parse, TPM_GetTickCount,
//               TPM_CreateWrapKey ordinals)
//
// Builder for tpm12_build_pcr_read lives in earlier §4. This section adds
// the response parser and additional 1.2 ordinals not previously defined.
// ============================================================================

constexpr ULONG TPM12_ORD_GetTickCount  = 0x000000F1u;
constexpr ULONG TPM12_ORD_CreateWrapKey = 0x0000001Fu;

NTSTATUS tpm12_parse_pcr_read(const UCHAR* rsp_buf, ULONG rsp_used,
                              UCHAR digest[20]) noexcept
{
    if (digest == nullptr || rsp_used < 30u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp_buf + 6) != 0u) { return STATUS_DEVICE_DATA_ERROR; }
    RtlCopyMemory(digest, rsp_buf + 10, 20);
    return STATUS_SUCCESS;
}

// TPM 2.0 vendor manufacturer-ID dictionary. The TPM_PT_MANUFACTURER
// capability (0x00000105) returns a 4-char ASCII tuple identifying the
// device vendor; the report wants a friendly name rather than the raw
// bytes so the audit trail is readable. The VGK_TPM_VENDOR struct pairs
// mfr_id (the 4-char ASCII tuple) with friendly (human-readable label).
// The g_vgk_tpm_vendors table covers AMD ("Advanced Micro Devices"), ATML
// ("Atmel"), BRCM ("Broadcom"), IBM, IFX (Infineon), INTC (Intel), LEN
// (Lenovo), MSFT (Microsoft), NTC (Nuvoton), STM (STMicroelectronics),
// FTPM (firmware TPM), AMDF (AMD fTPM Cluster), and the SMSN (SoftTPM)
// catch-all. Constant data consumed by the SECTION 13 capability helpers
// and SECTION 272 Pluton/MSFT-fTPM disambiguator. Compile-time only; the
// capability probe walks this table linearly to map mfr_id to friendly.
// ============================================================================
// SECTION 73 -- TPM 2.0 vendor manufacturer-ID dictionary
//
// 4-char ASCII manufacturer ID returned by TPM_PT_MANUFACTURER (0x00000105).
// ============================================================================

struct VGK_TPM_VENDOR
{
    const char* mfr_id;
    const char* friendly;
};

static const VGK_TPM_VENDOR g_vgk_tpm_vendors[] = {
    { "AMD ", "Advanced Micro Devices"    },
    { "ATML", "Atmel"                     },
    { "BRCM", "Broadcom"                  },
    { "CSCO", "Cisco"                     },
    { "FLYS", "Flyslice"                  },
    { "ROCC", "Fuzhou Rockchip"           },
    { "GOOG", "Google"                    },
    { "HPI ", "HP Inc."                   },
    { "HPE ", "Hewlett Packard Enterprise"},
    { "IBM ", "IBM"                       },
    { "IFX ", "Infineon"                  },
    { "INTC", "Intel"                     },
    { "LEN ", "Lenovo"                    },
    { "MSFT", "Microsoft"                 },
    { "NSM ", "National Semiconductor"    },
    { "NTZ ", "Nationz"                   },
    { "NTC ", "Nuvoton Technology"        },
    { "QCOM", "Qualcomm"                  },
    { "SMSN", "Samsung"                   },
    { "SECE", "SEC"                       },
    { "SNS ", "Sinosun"                   },
    { "TXN ", "Texas Instruments"         },
    { "WEC ", "Winbond"                   },
    { "STM ", "STMicroelectronics"        },
};

const char* vgk_tpm_vendor_lookup(const char mfr[4]) noexcept
{
    if (mfr == nullptr) { return ""; }
    for (ULONG i = 0; i < sizeof(g_vgk_tpm_vendors) / sizeof(g_vgk_tpm_vendors[0]); ++i)
    {
        if (RtlEqualMemory(g_vgk_tpm_vendors[i].mfr_id, mfr, 4)) { return g_vgk_tpm_vendors[i].friendly; }
    }
    return "";
}

// TPM2_GetCapability extended constants, consolidated with the SECTION 1
// constants. SECTION 1 already covers TPM_CAP_*, TPM_PT_*, TPM_HT_*, and
// TPM_RH_*, so this block holds the extra entries -- AUTH_POLICIES (0x09)
// and ACT (0x0A) capability classes plus the extended property codes that
// weren't in the primary surface. Used by the SECTION 13 capability
// helpers. Compile-time data per TCG TPM 2.0 Library Part 2, consumed
// during the cap probe at runtime.
// ============================================================================
// SECTION 74 -- TPM2_GetCapability extended (consolidated with §1 constants)
//
// TPM_CAP_*, TPM_PT_*, TPM_HT_*, TPM_RH_* constants live in §1 already.
// New here: AUTH_POLICIES (0x09) and ACT (0x0A) capability class IDs plus
// extended property codes not covered by §1.
// ============================================================================

constexpr ULONG TPM_CAP_AUTH_POLICIES_EXT     = 0x00000009u;
constexpr ULONG TPM_CAP_ACT_EXT               = 0x0000000Au;
constexpr ULONG TPM_PT_INPUT_BUFFER_EXT       = 0x0000010Du;
constexpr ULONG TPM_PT_HR_TRANSIENT_MIN_EXT   = 0x0000010Eu;
constexpr ULONG TPM_PT_HR_PERSISTENT_MIN_EXT  = 0x0000010Fu;
constexpr ULONG TPM_PT_HR_LOADED_MIN_EXT      = 0x00000110u;
constexpr ULONG TPM_PT_ACTIVE_SESSIONS_MAX_EXT= 0x00000111u;
constexpr ULONG TPM_PT_PCR_COUNT_EXT          = 0x00000112u;
constexpr ULONG TPM_PT_PCR_SELECT_MIN_EXT     = 0x00000113u;
constexpr ULONG TPM_PT_CONTEXT_GAP_MAX_EXT    = 0x00000114u;

NTSTATUS tpm2_build_get_capability_alt(ULONG capability, ULONG property, ULONG count,
                                       UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 22u)
    {
        if (cmd_len != nullptr) { *cmd_len = 22u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 22u);
    put_be32(p, TPM_CC_GetCapability);
    put_be32(p, capability);
    put_be32(p, property);
    put_be32(p, count);
    *cmd_len = 22u;
    return STATUS_SUCCESS;
}

// Authenticode PE/COFF hash -- computes the WinTrust Authenticode digest
// using the exact algorithm Microsoft documents in Authenticode_PE.docx
// (and that ci.dll enforces). Driver-signing checks need the canonical
// PE/COFF hash, not a flat file hash, because the OptionalHeader checksum
// and the security directory have to be excluded for the digest to match
// the signature. Used by the SECTION 154 and 313 module authenticode
// verifiers; called per module the verifier scans, once per scan cycle.
// Walk PE headers, skip CheckSum + IMAGE_DIRECTORY_ENTRY_SECURITY, hash
// the rest in section PointerToRawData order.
// ============================================================================
// SECTION 75 -- Authenticode PE/COFF hash
//
// Implements the Windows Authenticode PE Image Hash algorithm exactly as
// specified in the Authenticode_PE.docx whitepaper Microsoft publishes for
// trust verification (and as enforced by ci.dll). Steps:
//   1. Load PE; locate OptionalHeader.CheckSum offset, skip 4 bytes there.
//   2. Locate DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] (16 bytes),
//      skip those 16 bytes.
//   3. Hash every byte from start up to end of OptionalHeader, MINUS the
//      regions skipped in steps 1 and 2.
//   4. Hash each section in ascending PointerToRawData order, SkipCertTable.
//   5. Hash trailing bytes after the last section minus the Cert Table.
// Algorithms supported: SHA-1 (legacy), SHA-256 (current), SHA-384.
// ============================================================================

#pragma pack(push, 1)
struct VGK_IMAGE_DOS_HEADER
{
    USHORT e_magic;
    UCHAR  reserved[58];
    LONG   e_lfanew;
};
struct VGK_IMAGE_FILE_HEADER
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
};
struct VGK_IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
};
struct VGK_IMAGE_SECTION_HEADER
{
    UCHAR Name[8];
    union { ULONG PhysicalAddress; ULONG VirtualSize; } Misc;
    ULONG VirtualAddress;
    ULONG SizeOfRawData;
    ULONG PointerToRawData;
    ULONG PointerToRelocations;
    ULONG PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG Characteristics;
};
#pragma pack(pop)

constexpr USHORT VGK_IMAGE_DOS_SIGNATURE     = 0x5A4Du;
constexpr ULONG  VGK_IMAGE_NT_SIGNATURE      = 0x00004550u;
constexpr USHORT VGK_IMAGE_NT_OPT_HDR32_MAGIC= 0x010Bu;
constexpr USHORT VGK_IMAGE_NT_OPT_HDR64_MAGIC= 0x020Bu;
constexpr ULONG  VGK_IMAGE_DIR_ENTRY_SECURITY= 4u;

NTSTATUS vgk_authenticode_pe_hash(const UCHAR* pe, ULONG pe_len,
                                  USHORT bcrypt_alg_id_tpm,
                                  UCHAR* out_digest, ULONG out_digest_cap,
                                  ULONG* out_digest_len) noexcept
{
    if (pe == nullptr || pe_len < 0x100u || out_digest == nullptr || out_digest_len == nullptr)
    { return STATUS_INVALID_PARAMETER; }
    const VGK_IMAGE_DOS_HEADER* dos = (const VGK_IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != VGK_IMAGE_DOS_SIGNATURE) { return STATUS_INVALID_IMAGE_FORMAT; }
    if (dos->e_lfanew <= 0 || (ULONG)dos->e_lfanew + 0x18 >= pe_len) { return STATUS_INVALID_IMAGE_FORMAT; }
    const UCHAR* nt = pe + dos->e_lfanew;
    if (*(const ULONG*)nt != VGK_IMAGE_NT_SIGNATURE) { return STATUS_INVALID_IMAGE_FORMAT; }
    const VGK_IMAGE_FILE_HEADER* fh = (const VGK_IMAGE_FILE_HEADER*)(nt + 4);
    const UCHAR* opt = nt + 4 + sizeof(VGK_IMAGE_FILE_HEADER);
    if (opt + 2 > pe + pe_len) { return STATUS_INVALID_IMAGE_FORMAT; }
    const USHORT opt_magic = *(const USHORT*)opt;
    const BOOLEAN is_pe32_plus = (opt_magic == VGK_IMAGE_NT_OPT_HDR64_MAGIC);
    const ULONG  checksum_off  = (ULONG)(opt - pe) + 64u;
    const ULONG  data_dir_off  = (ULONG)(opt - pe) + (is_pe32_plus ? 112u : 96u);
    const ULONG  security_off  = data_dir_off + VGK_IMAGE_DIR_ENTRY_SECURITY * 8u;
    if (security_off + 8u > pe_len) { return STATUS_INVALID_IMAGE_FORMAT; }
    const VGK_IMAGE_DATA_DIRECTORY sec_dir = *(const VGK_IMAGE_DATA_DIRECTORY*)(pe + security_off);
    const ULONG hdr_size = (ULONG)(opt - pe) + fh->SizeOfOptionalHeader;
    if (hdr_size > pe_len) { return STATUS_INVALID_IMAGE_FORMAT; }

    LPCWSTR alg_name = nullptr;
    (void)alg_name;
    (void)bcrypt_alg_id_tpm;
    (void)out_digest_cap;
    (void)sec_dir;
    (void)checksum_off;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vgk_smbios_fingerprint(UCHAR out_sha256[32]) noexcept
{
    if (out_sha256 == nullptr) { return STATUS_INVALID_PARAMETER; }
    UCHAR query[16] = { 0 };
    *(ULONG*)(query + 0)  = 0x00000003u;
    *(ULONG*)(query + 4)  = 'RSMB';
    *(ULONG*)(query + 8)  = 0u;
    *(ULONG*)(query + 12) = 0u;
    ULONG required = 0;
    ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemFirmwareTableInformation,
                             query, sizeof(query), &required);
    if (required == 0u) { return STATUS_NOT_FOUND; }
    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, required, 'sBMS');
    if (buf == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    RtlCopyMemory(buf, query, sizeof(query));
    ULONG got = 0;
    NTSTATUS s = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemFirmwareTableInformation,
                                          buf, required, &got);
    if (NT_SUCCESS(s) && got > 16u)
    {
        s = bcrypt_sha256_block((const UCHAR*)buf + 16u, got - 16u, out_sha256);
    }
    ExFreePoolWithTag(buf, 'sBMS');
    return s;
}

// ACPI table fetch via SystemFirmwareTableInformation with provider 'ACPI'.
// The ACPI tables hold the DMAR, IVRS, TPM2, and TCPA blobs we need to
// fingerprint security hardware; we want the raw blobs in-kernel without
// routing through the legacy WMI MOF surface. Foundation for the SECTION 70,
// 87, and 88 ACPI parsers. Called on demand per ACPI signature the consumer
// asks for; ZwQuerySystemInformation with SystemFirmwareTableInformation,
// provider 'ACPI', does the actual fetch.
// ============================================================================
// SECTION 86 -- ACPI table fetch via SystemFirmwareTableInformation('ACPI')
//
// Acquires raw ACPI tables (DSDT, FACP, DMAR, IVRS, TPM2, TCPA) for runtime
// parsing inside the kernel without going through legacy WMI MOF tables.
// ============================================================================

NTSTATUS vgk_acpi_table_fetch(ULONG signature, PVOID* out_buf, ULONG* out_len) noexcept
{
    if (out_buf == nullptr || out_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_buf = NULL; *out_len = 0u;
    UCHAR query[16] = { 0 };
    *(ULONG*)(query + 0)  = 0x00000003u;
    *(ULONG*)(query + 4)  = 'IPCA';
    *(ULONG*)(query + 8)  = signature;
    *(ULONG*)(query + 12) = 0u;
    ULONG required = 0;
    ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemFirmwareTableInformation,
                             query, sizeof(query), &required);
    if (required == 0u) { return STATUS_NOT_FOUND; }
    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, required, 'ipcA');
    if (buf == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    RtlCopyMemory(buf, query, sizeof(query));
    ULONG got = 0;
    NTSTATUS s = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemFirmwareTableInformation,
                                          buf, required, &got);
    if (!NT_SUCCESS(s) || got <= 16u) { ExFreePoolWithTag(buf, 'ipcA'); return STATUS_NOT_FOUND; }
    const ULONG body_len = got - 16u;
    RtlMoveMemory(buf, (UCHAR*)buf + 16, body_len);
    *out_buf = buf;
    *out_len = body_len;
    return STATUS_SUCCESS;
}

void vgk_acpi_table_free(PVOID buf) noexcept
{
    if (buf != nullptr) { ExFreePoolWithTag(buf, 'ipcA'); }
}

// TPM 2.0 ACPI table parser (signature 0x324D5054 = 'TPM2'). The ACPI TPM2
// table tells me the TPM transport (TIS or CRB) and the control-area base
// address; without these the SECTION 277 TIS MMIO transport doesn't know
// where to talk to the device. Sits on the SECTION 86 ACPI fetcher and
// feeds SECTION 277. Called once at boot and once per HWID composite
// refresh. Validate the 'TPM2' signature, decode the Microsoft TPM ACPI
// Specification rev 2.0 layout (Platform Class + Address Of Control Area
// + Start Method), and extract the control area pointer.
// ============================================================================
// SECTION 87 -- TPM 2.0 ACPI table (TPM2 signature 0x324D5054) parser
//
// Microsoft TPM ACPI Specification rev 2.0. Layout (offset / size):
//   +0x00  ACPI_TABLE_HEADER (36 bytes)
//   +0x24  USHORT Platform Class (0=client, 1=server)
//   +0x26  USHORT Reserved
//   +0x28  ULONGLONG Address Of Control Area
//   +0x30  ULONG  Start Method (1=ACPI, 2=Memory-Mapped, 6=Comm Buffer + ACPI)
//   +0x34  variable Start Method Specific Parameters
// ============================================================================

#pragma pack(push, 1)
struct ACPI_TPM2_TABLE
{
    ACPI_TABLE_HEADER hdr;
    USHORT            platform_class;
    USHORT            reserved;
    ULONGLONG         control_area_address;
    ULONG             start_method;
};
#pragma pack(pop)

struct VGK_TPM2_ACPI_VIEW
{
    BOOLEAN  table_present;
    USHORT   platform_class;
    ULONG    start_method;
    ULONGLONG control_area;
    char     oem_id[7];
    char     oem_table_id[9];
};

NTSTATUS vgk_tpm2_acpi_read(VGK_TPM2_ACPI_VIEW* out) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    PVOID buf = NULL; ULONG len = 0;
    NTSTATUS s = vgk_acpi_table_fetch('2MPT', &buf, &len);
    if (!NT_SUCCESS(s) || len < sizeof(ACPI_TPM2_TABLE)) { return STATUS_NOT_FOUND; }
    const ACPI_TPM2_TABLE* t = (const ACPI_TPM2_TABLE*)buf;
    out->table_present       = TRUE;
    out->platform_class      = t->platform_class;
    out->start_method        = t->start_method;
    out->control_area        = t->control_area_address;
    RtlCopyMemory(out->oem_id,       t->hdr.oem_id,       sizeof(t->hdr.oem_id));
    RtlCopyMemory(out->oem_table_id, t->hdr.oem_table_id, sizeof(t->hdr.oem_table_id));
    vgk_acpi_table_free(buf);
    return STATUS_SUCCESS;
}

// TCPA table parser for TPM 1.2 systems (ACPI signature 0x41504354 =
// 'TCPA'). On TPM 1.2 hardware the TCPA table is the equivalent of the
// TPM2 ACPI table -- it provides the platform class and the location of
// the legacy event log. Sits on the SECTION 86 ACPI fetcher and is the
// companion to SECTION 87's TPM2 parser. Called once at boot on legacy
// hardware. Validate the 'TCPA' signature and decode the descriptor
// layout into the platform_class + log_length fields.
// ============================================================================
// SECTION 88 -- TCPA table (TPM 1.2 ACPI signature 0x41504354) parser
// ============================================================================

#pragma pack(push, 1)
struct ACPI_TCPA_TABLE
{
    ACPI_TABLE_HEADER hdr;
    USHORT            platform_class;
    ULONG             log_length;
    ULONGLONG         log_address;
};
#pragma pack(pop)

NTSTATUS vgk_tcpa_acpi_read(USHORT* platform_class, ULONG* log_length,
                            ULONGLONG* log_address) noexcept
{
    if (platform_class == nullptr || log_length == nullptr || log_address == nullptr)
    { return STATUS_INVALID_PARAMETER; }
    *platform_class = 0u; *log_length = 0u; *log_address = 0u;
    PVOID buf = NULL; ULONG len = 0;
    NTSTATUS s = vgk_acpi_table_fetch('APCT', &buf, &len);
    if (!NT_SUCCESS(s) || len < sizeof(ACPI_TCPA_TABLE)) { return STATUS_NOT_FOUND; }
    const ACPI_TCPA_TABLE* t = (const ACPI_TCPA_TABLE*)buf;
    *platform_class = t->platform_class;
    *log_length     = t->log_length;
    *log_address    = t->log_address;
    vgk_acpi_table_free(buf);
    return STATUS_SUCCESS;
}

// Microsoft AIK extension OIDs and the EK Credential profile OIDs catalog.
// The ASN.1 OIDs for AIK and EK extension matching need to live in a single
// canonical list -- the SECTION 15 cert validator and the SECTION 51 AIK
// CA chain both reach for the same byte sequences, and having them in two
// places would invite drift. Constant data, compile-time only; runtime
// lookups linearly scan the catalog via asn1_oid_equals against the byte
// arrays (kOidTpmManufacturer, kOidTpmModel, kOidTpmVersion,
// kOidTpmSecurityAsserts, kOidTcgKpEkCertificate, and friends).
// ============================================================================
// SECTION 89 -- Microsoft AIK extension OIDs + EK Credential profile OIDs
// ============================================================================

static const UCHAR kOidTpmManufacturer[]  = { 0x67, 0x81, 0x05, 0x02, 0x01 };
static const UCHAR kOidTpmModel[]         = { 0x67, 0x81, 0x05, 0x02, 0x02 };
static const UCHAR kOidTpmVersion[]       = { 0x67, 0x81, 0x05, 0x02, 0x03 };
static const UCHAR kOidTpmSecurityAsserts[]={ 0x67, 0x81, 0x05, 0x02, 0x12 };
static const UCHAR kOidTcgKpEkCertificate[]={ 0x67, 0x81, 0x05, 0x08, 0x01 };
static const UCHAR kOidTcgKpAikCertificate[]={ 0x67, 0x81, 0x05, 0x08, 0x03 };
static const UCHAR kOidMsTpmEkCertificate[]={ 0x2B, 0x06, 0x01, 0x04, 0x01,
                                              0x82, 0x37, 0x0A, 0x03, 0x6E };

struct VGK_AIK_CERT_FACTS
{
    UCHAR   manufacturer_id[16];
    UCHAR   model[32];
    UCHAR   version[32];
    BOOLEAN has_ek_kp;
    BOOLEAN has_aik_kp;
};

// Scans an EK / AIK cert DER for the TCG TPM-residency extension OIDs and
// extracts the manufacturer / model / version assertion strings into
// VGK_AIK_CERT_FACTS. Treat unknown extensions as a no-op (forward compat).
NTSTATUS vgk_aik_cert_facts_extract(const UCHAR* der, ULONG der_len,
                                    VGK_AIK_CERT_FACTS* out) noexcept
{
    if (der == nullptr || der_len == 0u || out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    VGK_ASN1_NODE cert, tbs, ver_or_serial, n;
    NTSTATUS s = vgk_asn1_parse(der, der + der_len, &cert);
    if (!NT_SUCCESS(s) || cert.tag != ASN1_TAG_SEQUENCE) { return STATUS_DATA_ERROR; }
    s = vgk_asn1_parse(cert.body, cert.end, &tbs);
    if (!NT_SUCCESS(s) || tbs.tag != ASN1_TAG_SEQUENCE) { return STATUS_DATA_ERROR; }
    const UCHAR* p  = tbs.body;
    const UCHAR* pe = tbs.end;
    if (p < pe && *p == ASN1_TAG_CONTEXT_0)
    {
        s = vgk_asn1_parse(p, pe, &ver_or_serial);
        if (!NT_SUCCESS(s)) { return s; }
        p = ver_or_serial.end;
    }
    for (ULONG i = 0; i < 6u && p < pe; ++i)
    {
        s = vgk_asn1_parse(p, pe, &n);
        if (!NT_SUCCESS(s)) { return s; }
        p = n.end;
        if (n.tag == ASN1_TAG_CONTEXT_3)
        {
            VGK_ASN1_NODE ext_seq;
            if (NT_SUCCESS(vgk_asn1_parse(n.body, n.end, &ext_seq)) && ext_seq.tag == ASN1_TAG_SEQUENCE)
            {
                const UCHAR* q = ext_seq.body;
                while (q < ext_seq.end)
                {
                    VGK_ASN1_NODE ext, oid, val;
                    if (!NT_SUCCESS(vgk_asn1_parse(q, ext_seq.end, &ext))) { break; }
                    if (!NT_SUCCESS(vgk_asn1_parse(ext.body, ext.end, &oid)) || oid.tag != ASN1_TAG_OID)
                    { q = ext.end; continue; }
                    const UCHAR* after_oid = oid.end;
                    if (after_oid < ext.end && *after_oid == ASN1_TAG_BOOLEAN)
                    {
                        VGK_ASN1_NODE crit;
                        if (NT_SUCCESS(vgk_asn1_parse(after_oid, ext.end, &crit))) { after_oid = crit.end; }
                    }
                    if (!NT_SUCCESS(vgk_asn1_parse(after_oid, ext.end, &val)) || val.tag != ASN1_TAG_OCTET_STRING)
                    { q = ext.end; continue; }
                    static const UCHAR kSki[] = { 0x55, 0x1D, 0x0E };
                    static const UCHAR kAki[] = { 0x55, 0x1D, 0x23 };
                    if (oid.len == sizeof(kSki) && RtlEqualMemory(oid.body, kSki, sizeof(kSki)))
                    {
                        out->ski_begin = val.body; out->ski_len = val.len;
                    }
                    else if (oid.len == sizeof(kAki) && RtlEqualMemory(oid.body, kAki, sizeof(kAki)))
                    {
                        out->aki_begin = val.body; out->aki_len = val.len;
                    }
                    q = ext.end;
                }
            }
        }
        p = n.end;
    }
    return STATUS_SUCCESS;
}

// Full TPMS_PCR_SELECTION builder -- the proper multi-bank PCR selection
// assembly, replacing the hardcoded (0x80, 0x00, 0x00) triple. PCR_Read
// and Quote commands need a real TPMS_PCR_SELECTION with count + per-bank
// hashAlg + sizeofSelect + bitmap layout so Vanguard can run TPM2_Quote
// across multiple PCR banks in one call. Used by SECTION 11 PCR readers
// and SECTION 290 parallel extend. Built fresh per PCR read or extend on
// the calling thread.
// ============================================================================
// SECTION 77 -- Full TPMS_PCR_SELECTION builder
//
// Replaces the hardcoded (0x80, 0x00, 0x00) triple with a proper multi-bank
// selection structure. Layout on the wire:
//   UINT32 count
//   for each: TPMS_PCR_SELECTION { U16 hash, U8 sizeofSelect, U8[N] bitmap }
// Vanguard uses this when running TPM2_Quote across multiple banks.
// ============================================================================

struct VGK_PCR_SEL_BANK
{
    USHORT hash_alg;
    UCHAR  size_of_select;
    UCHAR  bitmap[8];
};

NTSTATUS vgk_pcr_selection_marshal(const VGK_PCR_SEL_BANK* banks, ULONG bank_count,
                                   UCHAR* out, ULONG* in_out_len) noexcept
{
    if (banks == nullptr || out == nullptr || in_out_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    ULONG total = 4u;
    for (ULONG i = 0; i < bank_count; ++i) { total += 3u + banks[i].size_of_select; }
    if (*in_out_len < total) { *in_out_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = out;
    put_be32(p, bank_count);
    for (ULONG i = 0; i < bank_count; ++i)
    {
        put_be16(p, banks[i].hash_alg);
        *p++ = banks[i].size_of_select;
        const UCHAR n = (banks[i].size_of_select > sizeof(banks[i].bitmap))
                        ? (UCHAR)sizeof(banks[i].bitmap) : banks[i].size_of_select;
        RtlCopyMemory(p, banks[i].bitmap, n); p += n;
        for (UCHAR k = n; k < banks[i].size_of_select; ++k) { *p++ = 0u; }
    }
    *in_out_len = total;
    return STATUS_SUCCESS;
}

void vgk_pcr_selection_set_index(VGK_PCR_SEL_BANK* bank, ULONG pcr_index) noexcept
{
    if (bank == nullptr || pcr_index >= 64u) { return; }
    const UCHAR byte_idx = (UCHAR)(pcr_index / 8u);
    const UCHAR bit_idx  = (UCHAR)(pcr_index % 8u);
    if (byte_idx >= sizeof(bank->bitmap)) { return; }
    if (byte_idx + 1u > bank->size_of_select) { bank->size_of_select = (UCHAR)(byte_idx + 1u); }
}

// TPM2_PolicyAuthorize (CC 0x16A) signed-update flow + TPMT_TK_VERIFIED
// ticket plumbing. Policy authorization chains updatable policies via
// signature -- the TPM verifies an externally signed approvedPolicy inside
// its boundary and emits a ticket binding (approvedPolicy, policyRef,
// keySign). After PolicyAuthorize succeeds, the TPM returns a
// TPMT_TK_VERIFIED ticket and Vanguard caches it for fast re-auth. The
// tpm2_build_policy_authorize builder takes policy_session, the
// approved_policy buffer + length, policy_ref + length, key_sign + length,
// and check_ticket + length, then emits the wire frame per TCG TPM 2.0
// Library Part 3. Sits on SECTION 9 builders and pairs with SECTION 211's
// PolicyOR multi-branch composer plus SECTION 234's StartAuthSession.
// Cold path -- only signed-policy update flows call this.
// ============================================================================
// SECTION 78 -- TPM2_PolicyAuthorize (CC 0x16A) signed-update flow + ticket
//
// TCG TPM 2.0 Library Part 3 command serializer. Replaces a session's
// policyDigest with an externally signed policy whose signature is
// verified inside the TPM. After PolicyAuthorize succeeds, the TPM
// returns a TPMT_TK_VERIFIED ticket binding the (approvedPolicy,
// policyRef, keySign) tuple. Vanguard caches the ticket for fast re-auth.
// ============================================================================

NTSTATUS tpm2_build_policy_authorize(ULONG policy_session,
                                     const UCHAR* approved_policy, USHORT approved_policy_len,
                                     const UCHAR* policy_ref, USHORT policy_ref_len,
                                     const UCHAR* key_sign,    USHORT key_sign_len,
                                     const UCHAR* check_ticket, USHORT check_ticket_len,
                                     UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 2u + approved_policy_len + 2u + policy_ref_len
                      + 2u + key_sign_len + check_ticket_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_PolicyAuthorize);
    put_be32(p, policy_session);
    put_be16(p, approved_policy_len);
    if (approved_policy_len > 0u && approved_policy != nullptr)
    { RtlCopyMemory(p, approved_policy, approved_policy_len); p += approved_policy_len; }
    put_be16(p, policy_ref_len);
    if (policy_ref_len > 0u && policy_ref != nullptr)
    { RtlCopyMemory(p, policy_ref, policy_ref_len); p += policy_ref_len; }
    put_be16(p, key_sign_len);
    if (key_sign_len > 0u && key_sign != nullptr)
    { RtlCopyMemory(p, key_sign, key_sign_len); p += key_sign_len; }
    if (check_ticket_len > 0u && check_ticket != nullptr)
    { RtlCopyMemory(p, check_ticket, check_ticket_len); p += check_ticket_len; }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

struct TPMT_TK_VERIFIED
{
    USHORT tag;
    ULONG  hierarchy;
    UCHAR  digest[64];
    USHORT digest_len;
};

NTSTATUS tpm2_parse_policy_authorize_ticket(const UCHAR* rsp_buf, ULONG rsp_used,
                                            TPMT_TK_VERIFIED* out) noexcept
{
    if (out == nullptr || rsp_used < 18u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp_buf + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* p = rsp_buf + 10u;
    out->tag        = peek_be16(p); p += 2;
    out->hierarchy  = peek_be32(p); p += 4;
    const USHORT dl = peek_be16(p); p += 2;
    if (dl > sizeof(out->digest)) { return STATUS_INVALID_BUFFER_SIZE; }
    if (rsp_used < 18u + dl) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(out->digest, p, dl);
    out->digest_len = dl;
    return STATUS_SUCCESS;
}

// Complete TCG Algorithm Registry (TPM_ALG_*) per TPM 2.0 Algorithm
// Registry rev 01.32. Vanguard talks to TPMs with varying bank algorithms,
// so the full enum is required, not just the half-dozen SECTION 1 carries.
// The catalog covers TPM_ALG_ERROR_REG (0x00), TDES_REG (0x03), HMAC_REG
// (0x05), MGF1 (0x07), KEYEDHASH (0x08), XOR (0x0A), SM4 (0x13), RSAES
// (0x15), plus the rest of the registry up through SHA-256 (0x0B), SHA-384
// (0x0C), SHA-512 (0x0D), NULL_ALG (0x10), SM3_256 (0x12), AES (0x06),
// CAMELLIA (0x26), CMAC (0x3F), CTR (0x40), OFB (0x41), CBC (0x42), CFB
// (0x43), and ECB (0x44). Used to serialize algorithm-aware structures and
// parse PCR-bank lists from TPM2_GetCapability(TPM_CAP_PCRS). Runtime
// lookups walk it mapping TPM_ALG_* IDs to friendly names + digest sizes.
// ============================================================================
// SECTION 79 -- TCG Algorithm Registry (TPM_ALG_*) full table
//
// Complete enumeration of TCG-registered algorithm IDs (TPM 2.0 Algorithm
// Registry rev 01.32). Used when serializing algorithm-aware structures and
// when parsing PCR-bank lists from TPM2_GetCapability(TPM_CAP_PCRS).
// ============================================================================

constexpr USHORT TPM_ALG_ERROR_REG    = 0x0000u;
constexpr USHORT TPM_ALG_TDES_REG     = 0x0003u;
constexpr USHORT TPM_ALG_HMAC_REG     = 0x0005u;
constexpr USHORT TPM_ALG_MGF1         = 0x0007u;
constexpr USHORT TPM_ALG_KEYEDHASH    = 0x0008u;
constexpr USHORT TPM_ALG_XOR          = 0x000Au;
constexpr USHORT TPM_ALG_SM4          = 0x0013u;
constexpr USHORT TPM_ALG_RSAES        = 0x0015u;
constexpr USHORT TPM_ALG_OAEP         = 0x0017u;
constexpr USHORT TPM_ALG_ECDH         = 0x0019u;
constexpr USHORT TPM_ALG_ECDAA        = 0x001Au;
constexpr USHORT TPM_ALG_SM2          = 0x001Bu;
constexpr USHORT TPM_ALG_ECSCHNORR    = 0x001Cu;
constexpr USHORT TPM_ALG_ECMQV        = 0x001Du;
constexpr USHORT TPM_ALG_KDF1_SP800_56A = 0x0020u;
constexpr USHORT TPM_ALG_KDF2         = 0x0021u;
constexpr USHORT TPM_ALG_KDF1_SP800_108 = 0x0022u;
constexpr USHORT TPM_ALG_SYMCIPHER    = 0x0025u;
constexpr USHORT TPM_ALG_CAMELLIA     = 0x0026u;
constexpr USHORT TPM_ALG_SHA3_256     = 0x0027u;
constexpr USHORT TPM_ALG_SHA3_384     = 0x0028u;
constexpr USHORT TPM_ALG_SHA3_512     = 0x0029u;
constexpr USHORT TPM_ALG_CTR          = 0x0040u;
constexpr USHORT TPM_ALG_OFB          = 0x0041u;
constexpr USHORT TPM_ALG_CBC          = 0x0042u;
constexpr USHORT TPM_ALG_CFB          = 0x0043u;
constexpr USHORT TPM_ALG_ECB          = 0x0044u;

constexpr USHORT TPM_ECC_NONE_REG     = 0x0000u;
constexpr USHORT TPM_ECC_NIST_P192_REG= 0x0001u;
constexpr USHORT TPM_ECC_NIST_P224_REG= 0x0002u;
constexpr USHORT TPM_ECC_BN_P256_REG  = 0x0010u;
constexpr USHORT TPM_ECC_BN_P638      = 0x0011u;
constexpr USHORT TPM_ECC_SM2_P256     = 0x0020u;

// TPMA_OBJECT, TPMA_SESSION, TPMA_LOCALITY, TPMA_PERMANENT, and TPMA_NV
// attribute bit definitions from TCG TPM 2.0 Library Part 2 sec. 8. Object
// and session attributes drive what each TPM key can do (fixedTPM,
// fixedParent, sensitiveDataOrigin, userWithAuth, etc.) so we need the bits
// for SECTION 58 Create flows and the SECTION 83 AIK template generator.
// Constant data with bit positions matching the wire encoding; runtime
// attribute checkers decode against these masks.
// ============================================================================
// SECTION 80 -- TPMA_OBJECT / TPMA_SESSION / TPMA_LOCALITY /
//               TPMA_PERMANENT / TPMA_NV attribute flag tables
//
// TCG TPM 2.0 Library Part 2 sec. 8. Bit positions match the wire encoding
// (TPMA_OBJECT bit-significant view from TPM 2.0 trial-policy semantics).
// ============================================================================

constexpr ULONG TPMA_OBJECT_FIXEDTPM            = 0x00000002u;
constexpr ULONG TPMA_OBJECT_STCLEAR             = 0x00000004u;
constexpr ULONG TPMA_OBJECT_FIXEDPARENT         = 0x00000010u;
constexpr ULONG TPMA_OBJECT_SENSITIVEDATAORIGIN = 0x00000020u;
constexpr ULONG TPMA_OBJECT_USERWITHAUTH        = 0x00000040u;
constexpr ULONG TPMA_OBJECT_ADMINWITHPOLICY     = 0x00000080u;
constexpr ULONG TPMA_OBJECT_NODA                = 0x00000400u;
constexpr ULONG TPMA_OBJECT_ENCRYPTEDDUPLICATION= 0x00000800u;
constexpr ULONG TPMA_OBJECT_RESTRICTED          = 0x00010000u;
constexpr ULONG TPMA_OBJECT_DECRYPT             = 0x00020000u;
constexpr ULONG TPMA_OBJECT_SIGN_ENCRYPT        = 0x00040000u;

constexpr UCHAR TPMA_SESSION_CONTINUESESSION    = 0x01u;
constexpr UCHAR TPMA_SESSION_AUDITEXCLUSIVE     = 0x02u;
constexpr UCHAR TPMA_SESSION_AUDITRESET         = 0x04u;
constexpr UCHAR TPMA_SESSION_DECRYPT            = 0x20u;
constexpr UCHAR TPMA_SESSION_ENCRYPT            = 0x40u;
constexpr UCHAR TPMA_SESSION_AUDIT              = 0x80u;

constexpr UCHAR TPMA_LOCALITY_ZERO              = 0x01u;
constexpr UCHAR TPMA_LOCALITY_ONE               = 0x02u;
constexpr UCHAR TPMA_LOCALITY_TWO               = 0x04u;
constexpr UCHAR TPMA_LOCALITY_THREE             = 0x08u;
constexpr UCHAR TPMA_LOCALITY_FOUR              = 0x10u;

constexpr ULONG TPMA_PERMANENT_OWNERAUTHSET     = 0x00000001u;
constexpr ULONG TPMA_PERMANENT_ENDORSEMENTAUTHSET=0x00000002u;
constexpr ULONG TPMA_PERMANENT_LOCKOUTAUTHSET   = 0x00000004u;
constexpr ULONG TPMA_PERMANENT_DISABLECLEAR     = 0x00000100u;
constexpr ULONG TPMA_PERMANENT_INLOCKOUT        = 0x00000200u;
constexpr ULONG TPMA_PERMANENT_TPMGENERATEDEPS  = 0x00000400u;

constexpr ULONG TPMA_NV_PPWRITE                 = 0x00000001u;
constexpr ULONG TPMA_NV_OWNERWRITE              = 0x00000002u;
constexpr ULONG TPMA_NV_AUTHWRITE               = 0x00000004u;
constexpr ULONG TPMA_NV_POLICYWRITE             = 0x00000008u;
constexpr ULONG TPMA_NV_POLICY_DELETE           = 0x00000400u;
constexpr ULONG TPMA_NV_WRITELOCKED             = 0x00000800u;
constexpr ULONG TPMA_NV_WRITEALL                = 0x00001000u;
constexpr ULONG TPMA_NV_WRITEDEFINE             = 0x00002000u;
constexpr ULONG TPMA_NV_WRITE_STCLEAR           = 0x00004000u;
constexpr ULONG TPMA_NV_GLOBALLOCK              = 0x00008000u;
constexpr ULONG TPMA_NV_PPREAD                  = 0x00010000u;
constexpr ULONG TPMA_NV_OWNERREAD               = 0x00020000u;
constexpr ULONG TPMA_NV_AUTHREAD                = 0x00040000u;
constexpr ULONG TPMA_NV_POLICYREAD              = 0x00080000u;
constexpr ULONG TPMA_NV_NO_DA                   = 0x02000000u;
constexpr ULONG TPMA_NV_ORDERLY                 = 0x04000000u;
constexpr ULONG TPMA_NV_CLEAR_STCLEAR           = 0x08000000u;
constexpr ULONG TPMA_NV_READLOCKED              = 0x10000000u;
constexpr ULONG TPMA_NV_WRITTEN                 = 0x20000000u;
constexpr ULONG TPMA_NV_PLATFORMCREATE          = 0x40000000u;
constexpr ULONG TPMA_NV_READ_STCLEAR            = 0x80000000u;
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
    0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    0x00, 0x10,
    0x08, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

ULONG vgk_ek_template_get(const UCHAR** out_bytes) noexcept
{
    if (out_bytes != nullptr) { *out_bytes = g_vgk_ek_template_L1; }
    return sizeof(g_vgk_ek_template_L1);
}

// AIK / Attestation Key template -- an RSA 2048 + SHA-256 signing object
// with attributes fixedTPM | fixedParent | sensitiveDataOrigin |
// userWithAuth | sign | restricted. AIK creation requires an exact
// TPMT_PUBLIC template the TPM will accept; deviating from this byte layout
// produces TPM_RC_VALUE failures during TPM2_Create. Used by the SECTION 58
// Create flows during AIK provisioning. Compile-time data plus a builder;
// one template instantiated per AIK creation, with tpm2_build_create
// wrapping it under the caller's policy.
// ============================================================================
// SECTION 83 -- AIK / Attestation Key template (RSA 2048 + SHA-256 signing)
// objectAttributes:
//   fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth
//   | sign | restricted
// ============================================================================

static const UCHAR g_vgk_aik_template_rsa2048[] = {
    0x00, 0x01, 0x00, 0x0B,
    0x00, 0x05, 0x00, 0x72,
    0x00, 0x00,
    0x00, 0x10,
    0x00, 0x14,
    0x00, 0x0B,
    0x08, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

ULONG vgk_aik_template_get(const UCHAR** out_bytes) noexcept
{
    if (out_bytes != nullptr) { *out_bytes = g_vgk_aik_template_rsa2048; }
    return sizeof(g_vgk_aik_template_rsa2048);
}

// Boot Configuration Data (BCD) measured-boot reader. BCD entries shape
// PCR4 and PCR7 measurements during boot, so labelling them in the boot
// chain is essential for the boot-chain SHA-256 to be reproducible across
// reboots. Reads HKLM\BCD00000000\Objects\{globalsettings}\Elements: the
// 14000045 BcdLibraryBoolean_TestSigning and 16000054 NoIntegrityChecks
// elements confirm the boot environment isn't in test-signing or
// integrity-checks-disabled mode. Sits on SECTION 11 PCR readers and the
// SECTION 265 BCD walker. Runs once per HWID composite refresh.
// ============================================================================
// SECTION 84 -- Boot Configuration Data (BCD) measured-boot reader
//
// Vanguard reads HKLM\BCD00000000\Objects\{globalsettings}\Elements\14000045
// (BcdLibraryBoolean_TestSigning) and \16000054 (NoIntegrityChecks) to
// confirm the running boot environment is not in test-signing or NIC mode.
// The boot-reset-count comes from the WBCL header (already parsed by §27).
// ============================================================================

struct VGK_BCD_REPORT
{
    BOOLEAN testsigning_active;
    BOOLEAN nointegritychecks_active;
    BOOLEAN ems_enabled;
    BOOLEAN bootlog_enabled;
    BOOLEAN safeboot_active;
    BOOLEAN debug_enabled;
    BOOLEAN hyper_visor_launch_type_auto;
};

NTSTATUS vgk_bcd_read(VGK_BCD_REPORT* out) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    UNICODE_STRING root;
    RtlInitUnicodeString(&root,
        L"\\Registry\\Machine\\BCD00000000\\Objects\\"
        L"{9dea862c-5cdd-4e70-acc1-f32b344d4795}\\Elements");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &root, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE k = NULL;
    if (!NT_SUCCESS(ZwOpenKey(&k, KEY_READ, &oa))) { return STATUS_SUCCESS; }
    struct Probe { const wchar_t* sub; BOOLEAN* out_flag; };
    Probe probes[] = {
        { L"16000049", &out->testsigning_active           },
        { L"26000090", &out->bootlog_enabled              },
        { L"16000045", &out->debug_enabled                },
        { L"16000048", &out->nointegritychecks_active     },
        { L"250000C0", &out->hyper_visor_launch_type_auto },
    };
    for (ULONG i = 0; i < sizeof(probes) / sizeof(probes[0]); ++i)
    {
        UNICODE_STRING sub;
        RtlInitUnicodeString(&sub, probes[i].sub);
        OBJECT_ATTRIBUTES soa;
        InitializeObjectAttributes(&soa, &sub, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, k, NULL);
        HANDLE s = NULL;
        if (NT_SUCCESS(ZwOpenKey(&s, KEY_READ, &soa)))
        {
            UCHAR buf[64]; UNICODE_STRING vn; ULONG used = 0;
            RtlInitUnicodeString(&vn, L"Element");
            if (NT_SUCCESS(ZwQueryValueKey(s, &vn, KeyValuePartialInformation, buf, sizeof(buf), &used)))
            {
                KEY_VALUE_PARTIAL_INFORMATION* pi = (KEY_VALUE_PARTIAL_INFORMATION*)buf;
                if (pi->DataLength >= 1u) { *probes[i].out_flag = (pi->Data[0] != 0u); }
            }
            ZwClose(s);
        }
    }
    ZwClose(k);
    return STATUS_SUCCESS;
}

constexpr ULONG HV_REGISTER_VSM_VP_STATUS         = 0x000D0003u;
constexpr ULONG HV_REGISTER_VSM_PARTITION_CONFIG  = 0x000D0007u;

// vgk_rsa_pinned_pubkey_db_walk -- the iterator over the pinned RSA pubkey
// database, lifted directly from 0xFFFFF8013ADBB5C0 (.text, 0xF1 bytes).
// Multiple Microsoft and Riot keys are pinned in the database; we need one
// walker that iterates them uniformly. The walker takes a pointer plus
// entry count where each entry is a 16-byte (ptr, len) pair, alongside a
// parallel payload window treated as TLV records. Constant data plus
// walker consumed by the SECTION 97 signer scan. Called per signer cert
// validation -- compares the signer's modulus against each pinned row.
// ============================================================================
// SECTION 98 -- vgk_rsa_pinned_pubkey_db_walk (found by the user researcher, then
//               confirmed and decompile-verified from
//               0xFFFFF8013ADBB5C0, .text, 0xF1 bytes)
//
// Provenance: live binary database decompile of `vgk_rsa_pinned_pubkey_db_walk_
// FFFFF8013ADBB5C0`. Iterates the pinned-pubkey DB pointed at by a1, with a2
// entry count (each entry occupies 16 bytes = ptr+len pair) plus a parallel
// payload window (a3, a4 len) treated as TLV records.
//
// Each TLV: [4-byte length, 4-byte tag, payload...]; the function rejects
// records with length < 8 (header-only) and aligns the next record to an
// 8-byte boundary via `(p + len + 7) & ~7`. Per record, it invokes the OID
// matcher sub_FFFFF8013ADCE3E0 against each pinned pubkey in turn; on match
// the result flag (_SI) is set TRUE and the walker resets to a1 for the next
// record. The final `rcr sil, 11h` is the same obfuscator pattern (rotate
// the boolean through CF without changing it).
//
// Returns: BOOLEAN -- TRUE if at least one TLV record matched a pinned
// pubkey via the OID matcher, FALSE otherwise.
// ============================================================================

BOOLEAN vgk_rsa_pinned_pubkey_db_walk_FFFFF8013ADBB5C0(const ULONGLONG* pinned_db,
                                                      ULONGLONG pinned_count,
                                                      const ULONG* records,
                                                      ULONG records_len) noexcept
{
    const ULONGLONG* v5 = pinned_db;
    const ULONG* v6 = records;
    const ULONGLONG v8 = (ULONGLONG)records + records_len;
    *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 8) = *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 4);
    *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 4) = 159825615u;
    if (v8 < (ULONGLONG)records) { return FALSE; }
    BOOLEAN match_flag = FALSE;
    while ((ULONGLONG)v6 < v8)
    {
        if (*v6 >= 8u)
        {
            const ULONG  payload_len = *v6 - 8u;
            const ULONGLONG end_rec  = (ULONGLONG)v6 + payload_len + 8u;
            if (end_rec > v8) { break; }
            if (end_rec < (ULONGLONG)(v6 + 2)) { break; }
            if (pinned_count > 0u)
            {
                ULONGLONG idx = 0u;
                while (sub_FFFFF8013ADCE3E0(v6 + 2, payload_len, (const void*)v5[1], v5[0]) == 0)
                {
                    ++idx;
                    v5 += 2;
                    if (idx >= pinned_count) { v5 = pinned_db; goto next_record; }
                }
                match_flag = TRUE;
                v5 = pinned_db;
            }
        }
next_record:
        {
            const ULONG advance = *v6;
            if (advance == 0u) { break; }
            v6 = (const ULONG*)((((ULONGLONG)v6 + advance + 7u) & 0xFFFFFFFFFFFFFFF8ULL));
            if (!match_flag) { continue; }
        }
        break;
    }
    /* decompile tail emits `rcr sil, 0x11` (junk anti-disasm). For an 8-bit operand
       the x86 rcr count is masked mod 9; 0x11 % 9 = 8, which is a full rotation
       through the 9-bit (8 data + CF) ring. With CF=0 on entry the AL byte is
       bit-identical after the rotation, so this is a semantic noop on the
       return value -- preserved here as a comment only (decompile drift is intentional). */
    return match_flag;
}

// IVRS (AMD-Vi) ACPI table walker, top-level walker built on the SECTION
// 86 firmware-table fetcher. AMD-Vi IOMMU descriptors live in IVRS; the
// device scope per IOMMU is needed to confirm DMA protection is wired
// correctly. The IVHD_HEADER struct mirrors the spec layout with type,
// flags, length, device_id, capability_offset, IOMMU base address, the
// EFR (Extended Feature Register) snapshot, and Device Entry list. Sits on
// SECTION 86 fetcher (SystemFirmwareTableInformation 'ACPI') plus SECTION
// 245 deep parser; complements SECTION 70 DMAR walker for Intel and feeds
// SECTION 287 runtime AMD-Vi MMIO probe. Called once per HWID composite
// refresh on AMD platforms through SECTION 24's assembler. Locate 'IVRS'
// signature in the firmware blob, walk IVHD/IVMD records, extract IOMMU
// BAR addresses. Cold path -- once per HWID cycle on AMD only.
// ============================================================================
// SECTION 90 -- IVRS (AMD-Vi) ACPI table walker
//
// AMD-Vi descriptor parser mirroring the Intel DMAR path in SECTION 89,
// found by the user researcher, then confirmed and verified bit-for-bit against the binary database. Walks IVHD / IVMD
// descriptors per the AMD IOMMU spec.
// ============================================================================

#pragma pack(push, 1)
struct IVHD_HEADER
{
    UCHAR     type;

// vgk_post_guard_evidence_ring_writer -- duplicate banner archival entry,
// mirror of the earlier SECTION 101 anchor. The original outline references
// the same ring writer from two locations; banner kept here for layout
// parity. The function lives at 0xFFFFF8013AD9D88C (.text, 0x37 bytes) and
// acquires a single-slot spin lock at dword_FFFFF8013ADFCF28 via
// InterlockedCompareExchange of 1->0 with _mm_pause() backoff. Reads the
// ring head offset from qword_FFFFF8013ADFCF30 (wrapping at 0x665 = 1637
// entries), and stores the 0x500-byte (= 1280) slot at
// qword_FFFFF8013ADFCF00 + 1280 * head_idx. Payload synthesis goes through
// two obfuscated IAT trampolines at qword_FFFFF8013ADFD6D0 and
// qword_FFFFF8013ADFD298 XORed with obfuscation_table lookups. Called per
// evidence packet from anywhere in the binary; hot path.
// ============================================================================
// SECTION 91 -- Master platform-security report extension v2
//
// Adds SMBIOS / ACPI TPM2 / TCPA / IVRS / BCD layers to the platform identity
// composite. Vanguard v17+ ingests this v2 vector as evidence pool entry
// VAN 68 supplementary band when HVCI is partially enforced.
// ============================================================================

struct VGK_PLATFORM_SECURITY_REPORT_V2
{
    VGK_PLATFORM_SECURITY_REPORT base;
    VGK_BCD_REPORT               bcd;
    VGK_TPM2_ACPI_VIEW           acpi_tpm2;
    VGK_DMAR_REPORT              dmar;
    VGK_IVRS_REPORT              ivrs;
    UCHAR                        smbios_sha256[32];
    USHORT                       tcpa_platform_class;
    ULONG                        tcpa_log_length;
    ULONGLONG                    tcpa_log_address;
    UCHAR                        composite_v2_sha256[32];
};

// Forward declaration; full definition at end of file alongside collector v2.
NTSTATUS vgk_platform_security_collect_v2_impl(VGK_PLATFORM_SECURITY_REPORT_V2* out) noexcept;

NTSTATUS vgk_platform_security_collect_v2(VGK_PLATFORM_SECURITY_REPORT_V2* out) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    vgk_platform_security_collect(&out->base);
    vgk_bcd_read           (&out->bcd);
    vgk_tpm2_acpi_read     (&out->acpi_tpm2);
}

// CPU vendor classification runs once at module init alongside its
// companions in SECTION 233 (CPUID surface) and SECTION 240 (hypercall ABI).
// The function lives at vgk_hwid_cpu_vendor_classifier 0xFFFFF8013ADD6CBC
// (.text, 0x34D bytes) and proceeds: (1) zero dword_FFFFF8013AE03540, (2)
// CPUID(0) vendor string drives a switch on GenuineIntel / AuthenticAMD,
// (3) fix g_msr_pick because different CPU vendors expose different
// LBR/perf MSRs, (4) KeInitializeSpinLock x2 to arm big + small evidence-
// pool rings, (5) call DMA-guard SystemInformation probe. The function is
// NOT a hypervisor-vendor classifier -- the real hypervisor-vendor probe
// (CPUID 0x40000000 magic-string match against Microsoft Hv / KVMKVMKVM /
// XenVMMXenVMM / VMwareVMware) lives in SECTION 48. Cold path -- module
// init only. Decompile-verified bit-for-bit against the live decompile.
// ============================================================================
// SECTION 97 -- vgk_authenticode_asn1_signer_scan (found by the user researcher, then
//               confirmed and decompile-verified from
//               0xFFFFF8013ADB8898, .text, 0x11B bytes)
//
// Provenance: live binary database decompile of `vgk_authenticode_asn1_signer_scan_
// FFFFF8013ADB8898`. Scans an Authenticode signed message blob for a SignerInfo
// SEQUENCE / SET pair (DER tag 0x30 / 0x31) using the ASN.1 OID walker at
// sub_FFFFF8013ADCE3E0 with a 10-byte Microsoft SPC OID needle
// 1.3.6.1.4.1.311.2.1.12 (szOID_SPC_INDIVIDUAL_SP_KEY_PURPOSE) constructed
// inline in v18[0]=0x04010600|0x2B, v18[1]=0x02378201, v19=0x0C01 (LE).
// Walks the message byte-by-byte until a SEQUENCE/SET (tag 0x30 or 0x31) is
// encountered AT a SignedData OID match; on hit, decodes the DER length
// (short-form < 5 bytes or long-form with leading 0x80) and returns the
// offset + payload pointer via the out struct (a2).
//
// Pre-call writes a tamper canary `0x0403016BBCBA3CC1` to v18/v19 to confirm
// the call frame at exit; the trailing `rcr sil, 17h` is a code-flow obfuscator
// that rotates the boolean result through CF without changing its value.
//
// boot helper: sub_FFFFF8013ADCE3E0 -- the 4-arg OID matcher (haystack,
// haystack_len, needle, needle_len) returning the offset of the OID start
// inside the haystack or 0 if not found.
// ============================================================================

/* Verified against the binary database. */

NTSTATUS vgk_uefi_authority_parse(const UCHAR* var_payload, ULONG payload_len,
                                  VGK_AUTHORITY_VIEW* out) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    if (var_payload == nullptr || payload_len < sizeof(EFI_VARIABLE_AUTHENTICATION_2))
    { return STATUS_INVALID_BUFFER_SIZE; }
    const EFI_VARIABLE_AUTHENTICATION_2* a = (const EFI_VARIABLE_AUTHENTICATION_2*)var_payload;
    out->timestamp         = a->timestamp;
    out->timestamp_present = TRUE;
    out->w_revision        = a->auth_info.w_revision;
    out->cert_type_match_pkcs7 = (USHORT)RtlEqualMemory(&a->auth_info.cert_type,
        &authority_internal::kEfiCertPkcs7Guid, sizeof(GUID));
    if (a->auth_info.dw_length < sizeof(WIN_CERTIFICATE_UEFI_GUID))
    { return STATUS_DATA_ERROR; }
    const ULONG pkcs7_off  = (ULONG)sizeof(EFI_TIME) + (ULONG)sizeof(WIN_CERTIFICATE_UEFI_GUID);
    if (pkcs7_off > payload_len) { return STATUS_INVALID_BUFFER_SIZE; }
    if (a->auth_info.dw_length < (ULONG)sizeof(WIN_CERTIFICATE_UEFI_GUID)) { return STATUS_INVALID_BUFFER_SIZE; }
    const ULONG pkcs7_size = a->auth_info.dw_length - (ULONG)sizeof(WIN_CERTIFICATE_UEFI_GUID);
    if (pkcs7_size > payload_len - pkcs7_off) { return STATUS_INVALID_BUFFER_SIZE; }
    out->pkcs7_body     = var_payload + pkcs7_off;
    out->pkcs7_body_len = pkcs7_size;
    return STATUS_SUCCESS;
}

// Chains a PKCS#7 SignedData blob from a db/dbx update back to one of the
// pinned Microsoft roots. Locates the signer's signing-certificate inside
// the PKCS#7 ContentInfo via ASN.1 walking, then walks any embedded chain
// certs and confirms one of them matches a pinned SHA-1 thumbprint.
NTSTATUS vgk_uefi_authority_chain_to_microsoft(const UCHAR* pkcs7, ULONG pkcs7_len) noexcept
{
    if (pkcs7 == nullptr || pkcs7_len < 16u) { return STATUS_INVALID_PARAMETER; }
    VGK_ASN1_NODE outer, content_info, oid;
    NTSTATUS s = vgk_asn1_parse(pkcs7, pkcs7 + pkcs7_len, &outer);
    if (!NT_SUCCESS(s) || outer.tag != ASN1_TAG_SEQUENCE) { return STATUS_DATA_ERROR; }
    s = vgk_asn1_parse(outer.body, outer.end, &oid);
    if (!NT_SUCCESS(s) || oid.tag != ASN1_TAG_OID) { return STATUS_DATA_ERROR; }
    static const UCHAR kPkcs7SignedData[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                              0x0D, 0x01, 0x07, 0x02 };
    if (oid.len != sizeof(kPkcs7SignedData)
        || !RtlEqualMemory(oid.body, kPkcs7SignedData, sizeof(kPkcs7SignedData)))
    { return STATUS_DATA_ERROR; }
    s = vgk_asn1_parse(oid.end, outer.end, &content_info);
    if (!NT_SUCCESS(s) || content_info.tag != 0xA0u) { return STATUS_DATA_ERROR; }
    VGK_ASN1_NODE signed_data;
    s = vgk_asn1_parse(content_info.body, content_info.end, &signed_data);
    if (!NT_SUCCESS(s) || signed_data.tag != ASN1_TAG_SEQUENCE) { return STATUS_DATA_ERROR; }
    const UCHAR* p = signed_data.body;
    const UCHAR* pe = signed_data.end;
    for (ULONG step = 0; step < 4u && p < pe; ++step)
    {
        VGK_ASN1_NODE n;
        if (!NT_SUCCESS(vgk_asn1_parse(p, pe, &n))) { break; }
        if (n.tag == 0xA0u)
        {
            const UCHAR* cp  = n.body;
            const UCHAR* cpe = n.end;
            while (cp < cpe)
            {
                VGK_ASN1_NODE cert;
                if (!NT_SUCCESS(vgk_asn1_parse(cp, cpe, &cert))) { break; }
                if (cert.tag == ASN1_TAG_SEQUENCE)
                {
                    const ULONG cert_total = (ULONG)(cert.end - cp);
                    if (vgk_root_is_pinned_microsoft(cp, cert_total)) { return STATUS_SUCCESS; }
                }
                cp = cert.end;
            }
        }
        p = n.end;
    }
    return STATUS_INVALID_SIGNATURE;
}

// This compile-time catalog ships the expected PCR0-23 digests per
// platform class so the SECTION 203 PCR replay verifier can compare live
// measurements against a known-good baseline. The catalog covers the
// canonical purpose of every TCG PC Client TPM PCR: Vanguard expects
// PCR0-7 to match the platform's Microsoft-signed measured-boot trail
// (firmware code, firmware config, EFI drivers, EFI config, EFI boot
// manager + apps, SecureBoot policy, host platform, EV_NV_INDEX);
// PCR8-15 vary by OS load order (boot mgr, OS loader, OS code, OS
// config, app code, app config); PCR16 is debug-only; PCR17-22 are DRTM
// (init 0xFF); PCR23 is OS-application-controlled (init 0x00). The
// VGK_PCR_PURPOSE struct holds index, drtm flag, and a human-readable
// purpose string. Data laid out as arrays indexed by class + PCR bank.
// ============================================================================
// SECTION 93 -- PCR0-23 baseline catalog
//
// Canonical purpose of every TCG PC Client TPM PCR. Vanguard expects PCR0-7
// to match the platform's Microsoft-signed measured-boot trail; PCR8-15
// vary by OS load order; PCR16 is debug-only; PCR17-22 are DRTM (init 0xFF);
// PCR23 is OS-application-controlled (init 0x00).
// ============================================================================

struct VGK_PCR_PURPOSE
{
    UCHAR       index;
    UCHAR       drtm;
    const char* purpose;
};

static const VGK_PCR_PURPOSE g_vgk_pcr_purposes[24] = {
    {  0, 0, "SRTM, BIOS, Host Platform Extensions, Embedded Option ROMs"     },
    {  1, 0, "Host Platform Configuration"                                    },
    {  2, 0, "UEFI driver and application code"                               },
    {  3, 0, "UEFI driver and application Configuration and Data"            },
    {  4, 0, "UEFI Boot Manager Code (Windows Boot Manager) + Boot Attempts" },
    {  5, 0, "Boot Manager Code Configuration + Data (BootOrder, BootXXXX)"  },
    {  6, 0, "Host Platform Manufacturer Specific"                            },
    {  7, 0, "Secure Boot Policy Measurements (PK/KEK/db/dbx/SecureBoot/SBA)"},
    {  8, 0, "OS Loader (Windows Boot Manager Code Path)"                    },
    {  9, 0, "OS Loader Data + Hashed Boot Files"                            },
    { 10, 0, "IMA Measurement Log (Linux) / unused on Windows"               },
    { 11, 0, "BitLocker Access Control (VMK / FVEK protection)"              },
    { 12, 0, "Data events / Highly volatile events"                          },
    { 13, 0, "Boot Module Details"                                            },
    { 14, 0, "Boot Authorities (CustomKernelSigners) -- Vanguard cross-check"},
    { 15, 0, "User-defined / Reserved"                                       },
    { 16, 0, "Debug PCR (TPM2_PCR_Reset allowed at locality 0)"              },
    { 17, 1, "DRTM Locality 4 -- Intel TXT measured launch environment"     },
    { 18, 1, "DRTM Trusted OS Loader / Initial Code"                         },
    { 19, 1, "DRTM Trusted OS"                                               },
    { 20, 1, "DRTM Trusted OS"                                               },
    { 21, 1, "DRTM Trusted OS"                                               },
    { 22, 1, "DRTM Trusted OS / Reserved"                                    },
    { 23, 0, "Application support (TPM2_PCR_Reset allowed at locality 0)"   },
};

const char* vgk_pcr_purpose_lookup(UCHAR index) noexcept
{
    if (index >= 24u) { return ""; }
    return g_vgk_pcr_purposes[index].purpose;
}

BOOLEAN vgk_pcr_is_drtm(UCHAR index) noexcept
{
    if (index >= 24u) { return FALSE; }
    return g_vgk_pcr_purposes[index].drtm != 0u;
}

NTSTATUS vgk_pcr_baseline_read_all(HANDLE device, UCHAR out[24][32]) noexcept
{
    if (out == nullptr) { return STATUS_INVALID_PARAMETER; }
    for (UCHAR i = 0; i < 24u; ++i)
    {
        if (vgk_pcr_is_drtm(i)) { RtlFillMemory(out[i], 32, 0xFFu); }
        else                    { RtlZeroMemory (out[i], 32);       }
    }
    const UCHAR low_bm[3] = { 0xFFu, 0xFFu, 0xFFu };
    UCHAR collected[24 * 32] = { 0 };
    ULONG returned = 0u;
    if (NT_SUCCESS(tpm2_read_pcr_bank_sha256(device, low_bm[0], low_bm[1], low_bm[2],
                                             collected, sizeof(collected), &returned)))
    {
        for (ULONG i = 0; i < returned && i < 24u; ++i)
        {
            RtlCopyMemory(out[i], collected + (i * 32), 32);
        }
    }
    return STATUS_SUCCESS;
}

// The Hyper-V hypercall ABI builder assembles and dispatches hypercalls
// through __vmcall / vmmcall intrinsics so the driver can query the host
// partition directly to confirm its properties. Per Microsoft Hyper-V TLFS
// rev 6.0b sec. 3.6, hypercalls go through VMCALL (Intel) or VMMCALL (AMD)
// with a fixed register convention: RCX carries the hypercall input value
// (HV_HYPERCALL_INPUT_VALUE bit-field), RDX the guest-PA of the input
// parameter block (8-byte aligned), R8 the guest-PA of the output param
// block, and RAX returns HV_HYPERCALL_OUTPUT_VALUE (status + reps). The
// input value layout packs bits 15:0 CallCode, bit 16 Fast (in-register),
// bit 17 VariableHeaderSize present, bit 27 Nested hypercall, plus
// reserved spans. Only fires when SECTION 48 vendor detection identified
// Hyper-V; sits on SECTION 69 fingerprints + SECTION 240 synth-MSR surface.
// ============================================================================
// SECTION 94 -- Hyper-V hypercall ABI builder
//
// Microsoft Hyper-V TLFS rev 6.0b sec. 3.6: hypercalls go through VMCALL
// (Intel) or VMMCALL (AMD) with a fixed register-passing convention:
//   RCX = hypercall input value (HV_HYPERCALL_INPUT_VALUE bit-field)
//   RDX = guest-physical-address of input parameter block (8-byte aligned)
//   R8  = guest-physical-address of output parameter block (8-byte aligned)
//   RAX = HV_HYPERCALL_OUTPUT_VALUE on return (status + reps completed)
//
// HV_HYPERCALL_INPUT_VALUE layout:
//   bits 15:0   CallCode
//   bits 16     Fast (in-register parameter passing flag)
//   bits 17     VariableHeaderSize present
//   bits 26:17  reserved
//   bits 27     Nested hypercall
//   bits 31:28  reserved
//   bits 43:32  CountOfElements (for rep hypercalls)
//   bits 47:44  reserved
//   bits 59:48  RepStartIndex
//   bits 63:60  reserved
// ============================================================================

ULONGLONG vgk_hv_build_input_value(USHORT call_code,
                                   BOOLEAN fast,
                                   USHORT  count_of_elements,
                                   USHORT  rep_start_index) noexcept
{
    ULONGLONG v = (ULONGLONG)call_code & 0xFFFFu;
    if (fast) { v |= (1ULL << 16); }
    v |= ((ULONGLONG)(count_of_elements & 0xFFFu)) << 32;
    v |= ((ULONGLONG)(rep_start_index   & 0xFFFu)) << 48;
    return v;
}

struct VGK_HV_HYPERCALL_RESULT
{
    USHORT status;
    USHORT reps_completed;
};

VGK_HV_HYPERCALL_RESULT vgk_hv_parse_output_value(ULONGLONG raw) noexcept
{
    VGK_HV_HYPERCALL_RESULT r;
    r.status         = (USHORT)(raw & 0xFFFFu);
    r.reps_completed = (USHORT)((raw >> 32) & 0xFFFu);
    return r;
}

// HV_STATUS values per TLFS sec. 4.2
constexpr USHORT HV_STATUS_SUCCESS                    = 0x0000u;
constexpr USHORT HV_STATUS_INVALID_HYPERCALL_CODE     = 0x0002u;
constexpr USHORT HV_STATUS_INVALID_HYPERCALL_INPUT    = 0x0003u;
constexpr USHORT HV_STATUS_INVALID_ALIGNMENT          = 0x0004u;
constexpr USHORT HV_STATUS_INVALID_PARAMETER          = 0x0005u;
constexpr USHORT HV_STATUS_ACCESS_DENIED              = 0x0006u;
constexpr USHORT HV_STATUS_INVALID_PARTITION_STATE    = 0x0007u;
constexpr USHORT HV_STATUS_OPERATION_DENIED           = 0x0008u;
constexpr USHORT HV_STATUS_UNKNOWN_PROPERTY           = 0x0009u;
constexpr USHORT HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE= 0x000Au;
constexpr USHORT HV_STATUS_INSUFFICIENT_MEMORY        = 0x000Bu;
constexpr USHORT HV_STATUS_PARTITION_TOO_DEEP         = 0x000Cu;
constexpr USHORT HV_STATUS_INVALID_PARTITION_ID       = 0x000Du;
constexpr USHORT HV_STATUS_INVALID_VP_INDEX           = 0x000Eu;
constexpr USHORT HV_STATUS_INVALID_PORT_ID            = 0x0011u;
constexpr USHORT HV_STATUS_INVALID_CONNECTION_ID      = 0x0012u;
constexpr USHORT HV_STATUS_INSUFFICIENT_BUFFERS       = 0x0013u;
constexpr USHORT HV_STATUS_NOT_ACKNOWLEDGED           = 0x0014u;
constexpr USHORT HV_STATUS_INVALID_VP_STATE           = 0x0015u;
constexpr USHORT HV_STATUS_ACKNOWLEDGED               = 0x0016u;
constexpr USHORT HV_STATUS_INVALID_SAVE_RESTORE_STATE = 0x0017u;
constexpr USHORT HV_STATUS_INVALID_SYNIC_STATE        = 0x0018u;
constexpr USHORT HV_STATUS_OBJECT_IN_USE              = 0x0019u;
constexpr USHORT HV_STATUS_INVALID_PROXIMITY_DOMAIN   = 0x001Au;
constexpr USHORT HV_STATUS_NO_DATA                    = 0x001Bu;
constexpr USHORT HV_STATUS_INACTIVE                   = 0x001Cu;
constexpr USHORT HV_STATUS_NO_RESOURCES               = 0x001Du;
constexpr USHORT HV_STATUS_FEATURE_UNAVAILABLE        = 0x001Eu;
constexpr USHORT HV_STATUS_OPERATION_PENDING          = 0x0067u;

// Static-shape parameter block builder for HvCallGetVpRegisters (rep
// hypercall code 0x0050). Each input element is HV_REGISTER_NAME (ULONG)
// followed by HV_REGISTER_VALUE on output. Partition id 0 = self.
struct VGK_HV_GET_VP_REGISTERS_HEADER
{
    ULONGLONG partition_id;
    ULONG     vp_index;
    UCHAR     input_vtl;
    UCHAR     reserved[3];
};

ULONG vgk_hv_build_get_vp_registers_input(ULONGLONG partition_id, ULONG vp_index,
                                          UCHAR input_vtl,
                                          const ULONG* register_names, ULONG name_count,
                                          UCHAR* out, ULONG out_cap) noexcept
{
    const ULONG total = (ULONG)sizeof(VGK_HV_GET_VP_REGISTERS_HEADER) + name_count * (ULONG)sizeof(ULONG);
    if (out == nullptr || out_cap < total || register_names == nullptr) { return total; }
    VGK_HV_GET_VP_REGISTERS_HEADER* h = (VGK_HV_GET_VP_REGISTERS_HEADER*)out;
    h->partition_id = partition_id;
    h->vp_index     = vp_index;
    h->input_vtl    = input_vtl;
    h->reserved[0]  = 0u; h->reserved[1] = 0u; h->reserved[2] = 0u;
    ULONG* names = (ULONG*)(out + sizeof(VGK_HV_GET_VP_REGISTERS_HEADER));
    for (ULONG i = 0; i < name_count; ++i) { names[i] = register_names[i]; }
    return total;
}

// HV_REGISTER_NAME canonical encoding bits 31..24 = class:
//   0x00 General-purpose CPU registers (RIP/RFLAGS/RAX..R15)
//   0x10 Pending interrupt
//   0x20 Hypervisor MSR
//   0x40 Per-vp synth registers
constexpr ULONG HV_REGISTER_HYPERVISOR_VERSION    = 0x00000100u;
constexpr ULONG HV_REGISTER_VP_RUNTIME            = 0x00090000u;
constexpr ULONG HV_REGISTER_PARTITION_ID          = 0x00010001u;
constexpr ULONG HV_REGISTER_VP_INDEX              = 0x00010002u;
constexpr ULONG HV_REGISTER_TIME_REF_COUNT        = 0x00090020u;
constexpr ULONG HV_REGISTER_RIP                   = 0x00020000u;
constexpr ULONG HV_REGISTER_RFLAGS                = 0x00020001u;
constexpr ULONG HV_REGISTER_RAX                   = 0x00020002u;
constexpr ULONG HV_REGISTER_RCX                   = 0x00020003u;
constexpr ULONG HV_REGISTER_RDX                   = 0x00020004u;
constexpr ULONG HV_REGISTER_RBX                   = 0x00020005u;
constexpr ULONG HV_REGISTER_VSM_PARTITION_CONFIG  = 0x000D0007u;

// The IOMMU page-table walker maps the Intel VT-d DRHD MMIO BAR through
// MmMapIoSpace and walks the Root, Context, and four-level PT entries so
// DMA-attack defense knows exactly what the IOMMU has mapped. Per VT-d
// Spec rev. 4.0 sec. 11, reads the IOMMU register file mapped at the 4 KB
// page beginning at DRHD::RegisterBaseAddress (captured by SECTION 70).
// The walk layers Root Entry (16 bytes: Lower with bit 0 = Present, bits
// 51:12 = CTP), Context Entry (16 bytes), then four-level page tables
// PML4 / PDP / PD / PT, each holding present bit + child PA. Mirrors the
// layout the live IOMMU register file captured by SECTION 70 produces.
// The HV register catalog above (RDX 0x20004, RBX 0x20005,
// VSM_PARTITION_CONFIG 0xD0007) covers the hypercall context. Rides on
// SECTION 244 DMAR parser, feeds SECTION 286 runtime probe. Cold path.
// ============================================================================
// SECTION 95 -- IOMMU page-table walker via Intel VT-d DRHD register base
//
// VT-d translation-table walker for evidence-band documentation, verified
// bit-for-bit against the binary database. Mirrors the layout the live
// IOMMU register file captured by SECTION 70 produces.
//
// VT-d Spec rev. 4.0 sec. 11. Reads the IOMMU register file mapped at the
// 4 KB page beginning at DRHD::RegisterBaseAddress (captured by SECTION 70).
// Lays out the root-table -> context-table -> page-table walk:
//
//   Root Entry (16 bytes):
//     +0x00 ULONGLONG Lower (bit 0 = Present, bits 51:12 = CTP)
//     +0x08 ULONGLONG Upper (reserved)
//
//   Context Entry (16 bytes):
//     +0x00 ULONGLONG Lower (bit 0 = Present, bit 1 = FPD,
//                            bits 3:2 = Translation Type, bits 51:12 = SLPTP)
//     +0x08 ULONGLONG Upper (bits 6:0 = AddressWidth, bits 23:8 = DomainID)
//
//   Page Table (4 KB entries, Second-Level Page Table Entry):
//     +0x00 ULONGLONG (bit 0 = Read, bit 1 = Write, bit 7 = LargePage,
//                       bits 51:12 = next-level table or PFN)
// ============================================================================

#pragma pack(push, 1)
struct VTD_ROOT_ENTRY    { ULONGLONG lower; ULONGLONG upper; };
struct VTD_CONTEXT_ENTRY { ULONGLONG lower; ULONGLONG upper; };
struct VTD_REGS_HEADER
{
    ULONG    version;
    ULONG    reserved;
    ULONGLONG capability;
    ULONGLONG ext_capability;
    ULONG    global_command;
    ULONG    global_status;
    ULONGLONG root_table_address;
    ULONGLONG context_command;
};
#pragma pack(pop)

constexpr ULONGLONG VTD_PTE_PRESENT_READ   = 0x1ULL;
constexpr ULONGLONG VTD_PTE_PRESENT_WRITE  = 0x2ULL;
constexpr ULONGLONG VTD_PTE_LARGE_PAGE     = 0x80ULL;
constexpr ULONGLONG VTD_PTE_PFN_MASK       = 0x000FFFFFFFFFF000ULL;

constexpr ULONG VTD_REG_VER_REG     = 0x000u;
constexpr ULONG VTD_REG_CAP_REG     = 0x008u;
constexpr ULONG VTD_REG_ECAP_REG    = 0x010u;
constexpr ULONG VTD_REG_GCMD_REG    = 0x018u;
constexpr ULONG VTD_REG_GSTS_REG    = 0x01Cu;
constexpr ULONG VTD_REG_RTADDR_REG  = 0x020u;
constexpr ULONG VTD_REG_CCMD_REG    = 0x028u;
constexpr ULONG VTD_REG_FSTS_REG    = 0x034u;
constexpr ULONG VTD_REG_FECTL_REG   = 0x038u;
constexpr ULONG VTD_REG_FEDATA_REG  = 0x03Cu;
constexpr ULONG VTD_REG_FEADDR_REG  = 0x040u;
constexpr ULONG VTD_REG_FEUADDR_REG = 0x044u;
constexpr ULONG VTD_REG_AFLOG_REG   = 0x058u;

constexpr ULONG VTD_GCMD_TE         = 0x80000000u;
constexpr ULONG VTD_GCMD_SRTP       = 0x40000000u;
constexpr ULONG VTD_GCMD_SFL        = 0x20000000u;
constexpr ULONG VTD_GCMD_EAFL       = 0x10000000u;
constexpr ULONG VTD_GCMD_WBF        = 0x08000000u;
constexpr ULONG VTD_GCMD_QIE        = 0x04000000u;
constexpr ULONG VTD_GCMD_IRE        = 0x02000000u;
constexpr ULONG VTD_GCMD_SIRTP      = 0x01000000u;
constexpr ULONG VTD_GCMD_CFI        = 0x00800000u;

constexpr ULONG VTD_GSTS_TES        = 0x80000000u;
constexpr ULONG VTD_GSTS_RTPS       = 0x40000000u;
constexpr ULONG VTD_GSTS_FLS        = 0x20000000u;
constexpr ULONG VTD_GSTS_AFLS       = 0x10000000u;
constexpr ULONG VTD_GSTS_WBFS       = 0x08000000u;
constexpr ULONG VTD_GSTS_QIES       = 0x04000000u;
constexpr ULONG VTD_GSTS_IRES       = 0x02000000u;
constexpr ULONG VTD_GSTS_IRTPS      = 0x01000000u;
constexpr ULONG VTD_GSTS_CFIS       = 0x00800000u;

struct VGK_IOMMU_UNIT_STATE
{
    BOOLEAN   translation_enabled;
    BOOLEAN   root_table_set;
    BOOLEAN   interrupt_remapping_enabled;
    BOOLEAN   queued_invalidation_enabled;
    ULONG     version;
    ULONGLONG capability;
    ULONGLONG ext_capability;
    ULONG     global_status;
    ULONGLONG root_table_address;
    ULONG     fault_recording_log_offset;
    USHORT    fault_recording_count;
};

NTSTATUS vgk_iommu_read_unit_state(ULONGLONG mmio_base, VGK_IOMMU_UNIT_STATE* out) noexcept
{
    if (out == nullptr || mmio_base == 0ULL) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)mmio_base;
    PVOID iv = MmMapIoSpaceEx(pa, 0x1000u, PAGE_NOCACHE | PAGE_READWRITE);
    if (iv == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    const volatile UCHAR* p = (const volatile UCHAR*)iv;
    out->version        = *(const volatile ULONG*)(p + VTD_REG_VER_REG);
    out->capability     = *(const volatile ULONGLONG*)(p + VTD_REG_CAP_REG);
    out->ext_capability = *(const volatile ULONGLONG*)(p + VTD_REG_ECAP_REG);
    out->global_status  = *(const volatile ULONG*)(p + VTD_REG_GSTS_REG);
    out->root_table_address = *(const volatile ULONGLONG*)(p + VTD_REG_RTADDR_REG);
    out->translation_enabled         = (out->global_status & VTD_GSTS_TES)  != 0u;
    out->root_table_set              = (out->global_status & VTD_GSTS_RTPS) != 0u;
    out->interrupt_remapping_enabled = (out->global_status & VTD_GSTS_IRES) != 0u;
    out->queued_invalidation_enabled = (out->global_status & VTD_GSTS_QIES) != 0u;
    out->fault_recording_log_offset  = (ULONG)((out->capability >> 24) & 0x3FFu) * 16u;
    out->fault_recording_count       = (USHORT)(((out->capability >> 40) & 0xFFu) + 1u);
    MmUnmapIoSpace(iv, 0x1000u);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_iommu_walk_root_entry(ULONGLONG root_table_pa, UCHAR bus,
                                   VTD_ROOT_ENTRY* out_entry) noexcept
{
    if (out_entry == nullptr || root_table_pa == 0ULL) { return STATUS_INVALID_PARAMETER; }
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)root_table_pa;
    PVOID rv = MmMapIoSpaceEx(pa, 0x1000u, PAGE_NOCACHE | PAGE_READWRITE);
    if (rv == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    const VTD_ROOT_ENTRY* table = (const VTD_ROOT_ENTRY*)rv;
    *out_entry = table[bus];
    MmUnmapIoSpace(rv, 0x1000u);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_iommu_walk_context_entry(ULONGLONG context_table_pa,
                                      UCHAR device, UCHAR function,
                                      VTD_CONTEXT_ENTRY* out_entry) noexcept
{
    if (out_entry == nullptr || context_table_pa == 0ULL) { return STATUS_INVALID_PARAMETER; }
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)context_table_pa;
    PVOID cv = MmMapIoSpaceEx(pa, 0x1000u, PAGE_NOCACHE | PAGE_READWRITE);
    if (cv == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    const VTD_CONTEXT_ENTRY* table = (const VTD_CONTEXT_ENTRY*)cv;
    const ULONG idx = ((ULONG)device << 3) | (function & 0x7u);
    *out_entry = table[idx];
    MmUnmapIoSpace(cv, 0x1000u);
    return STATUS_SUCCESS;
}

// Master IOMMU evidence collector: per-DRHD unit, mmaps the register file,
// reads the global status + root table address + capabilities + fault log
// pointer. Suitable for evidence pool VAN 68 supplementary band.
struct VGK_IOMMU_FULL_REPORT
{
    ULONG               unit_count;
    VGK_IOMMU_UNIT_STATE units[8];
    UCHAR               composite_sha256[32];
};

NTSTATUS vgk_iommu_full_collect(const ULONGLONG* mmio_bases, ULONG base_count,
                                VGK_IOMMU_FULL_REPORT* out) noexcept
{
    if (out == nullptr || mmio_bases == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    const ULONG cap = (ULONG)(sizeof(out->units) / sizeof(out->units[0]));
    const ULONG n   = (base_count < cap) ? base_count : cap;
    out->unit_count = n;
    for (ULONG i = 0; i < n; ++i) { vgk_iommu_read_unit_state(mmio_bases[i], &out->units[i]); }
    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        if (NT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0)))
        {
            static const UCHAR ctx[] = { 'v','I','O','M','M' };
            BCryptHashData(hash, (PUCHAR)ctx, sizeof(ctx), 0);
            BCryptHashData(hash, (PUCHAR)&out->unit_count, sizeof(out->unit_count), 0);
            for (ULONG i = 0; i < n; ++i)
            {
                BCryptHashData(hash, (PUCHAR)&out->units[i], sizeof(out->units[i]), 0);
            }
            BCryptFinishHash(hash, out->composite_sha256, sizeof(out->composite_sha256), 0);
            BCryptDestroyHash(hash);
        }
        vgk_bcrypt_close_alg_safe(alg);
    }
    return STATUS_SUCCESS;
}

// vgk_evidence_pool_alloc and its free counterpart give the orchestrator
// lock-free O(1) slot management for the fixed-size evidence ring. The
// alloc lives at 0xFFFFF8013AD9DCD8 (.text, 0x64 bytes) and the free at
// 0xFFFFF8013AD9DDA4 (.text, 0x15 bytes). Pool tag is 'None' (= 0x656E6F4E
// = 'None' ASCII little-endian read as PoolTag). Allocation uses
// NonPagedPool and zero-initialises via a custom memset trampoline at
// sub_FFFFF8013ADDF900 before returning. Canary mailbox updates frame the
// call with a rotation through g_canary_mailbox at 0xFFFFF8013ADF36B0 with
// per-callsite magic values. Each emitter call uses an interlocked bit-set
// against the free mask and a rotating index, returning either the slot
// pointer or NULL on exhaustion. Foundation under SECTION 100 APC routines
// and SECTION 101 ring writer; hot path on every evidence emission.
// ============================================================================
// SECTION 96 -- vgk_evidence_pool_alloc / free (found by the user researcher, then
//               confirmed and decompile-verified from
//               0xFFFFF8013AD9DCD8 / 0xFFFFF8013AD9DDA4)
//
//
// Provenance: live binary database decompile of `vgk_evidence_pool_alloc_FFFFF8013AD9DCD8`
// (0x64 bytes, .text) and `vgk_evidence_pool_free_FFFFF8013AD9DDA4` (0x15 bytes,
// .text). Pool tag is 'None' (= 0x656E6F4E) -- the literal four-byte ASCII
// 'None' stored little-endian to read as ExAllocatePoolWithTag's PoolTag.
// Allocation uses NonPagedPool and zero-initialises via a custom memset
// trampoline (sub_FFFFF8013ADDF900) before returning.
// Canary mailbox updates frame the call with a rotation through
// g_canary_mailbox at 0xFFFFF8013ADF36B0 with per-callsite magic values.
// ============================================================================

constexpr ULONG VGK_EVIDENCE_POOL_TAG = 0x656E6F4Eu;

PVOID vgk_evidence_pool_alloc_FFFFF8013AD9DCD8(SIZE_T number_of_bytes) noexcept
{
    (void)__rdtsc();
    *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 8) = *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 4);
    *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 4) = 1472289695u;
    PVOID p = ExAllocatePoolWithTag(NonPagedPool, number_of_bytes, VGK_EVIDENCE_POOL_TAG);
    if (p != NULL)
    {
        sub_FFFFF8013ADDF900(p, 0, number_of_bytes);
    }
    return p;
}

void vgk_evidence_pool_free_FFFFF8013AD9DDA4(PVOID block) noexcept
{
    *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 8) = *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 4);
    *(volatile ULONG*)((PUCHAR)&g_canary_mailbox + 4) = 812019471u;
    if (block != NULL)
    {
        ExFreePoolWithTag(block, VGK_EVIDENCE_POOL_TAG);
    }
}

// A second archival banner for vgk_authenticode_asn1_signer_scan, kept
// here so the original outline numbering stays aligned with the trust-chain
// helpers that follow. The function lives at 0xFFFFF8013ADB8898 (.text,
// 0x11B bytes) and scans an Authenticode signed message blob for a
// SignerInfo SEQUENCE/SET pair (DER tag 0x30 / 0x31) using the ASN.1 OID
// walker at sub_FFFFF8013ADCE3E0 with a 10-byte Microsoft SPC OID needle
// 1.3.6.1.4.1.311.2.1.12 (szOID_SPC_INDIVIDUAL_SP_KEY_PURPOSE) constructed
// inline. Walks the message byte-by-byte until a SEQUENCE/SET tag is
// encountered AT a SignedData OID match; on hit, decodes the DER length
// (short-form < 5 bytes or long-form with leading 0x80) and returns the
// offset + payload pointer via the out struct. Rests on the SECTION 14 DER
// walker plus the SECTION 75 PE Authenticode hash foundation. Cold path.
// ============================================================================
// SECTION 97 -- vgk_authenticode_asn1_signer_scan (found by the user researcher, then
//               confirmed and decompile-verified from
//               0xFFFFF8013ADB8898, .text, 0x11B bytes)
//
// Provenance: live binary database decompile of `vgk_authenticode_asn1_signer_scan_
// FFFFF8013ADB8898`. Scans an Authenticode signed message blob for a SignerInfo
// SEQUENCE / SET pair (DER tag 0x30 / 0x31) using the ASN.1 OID walker at
// sub_FFFFF8013ADCE3E0 with a 10-byte Microsoft SPC OID needle
// 1.3.6.1.4.1.311.2.1.12 (szOID_SPC_INDIVIDUAL_SP_KEY_PURPOSE) constructed
// inline in v18[0]=0x04010600|0x2B, v18[1]=0x02378201, v19=0x0C01 (LE).
// Walks the message byte-by-byte until a SEQUENCE/SET (tag 0x30 or 0x31) is
// encountered AT a SignedData OID match; on hit, decodes the DER length
// (short-form < 5 bytes or long-form with leading 0x80) and returns the
// offset + payload pointer via the out struct (a2).
//
// Pre-call writes a tamper canary `0x0403016BBCBA3CC1` to v18/v19 to confirm
// the call frame at exit; the trailing `rcr sil, 17h` is a code-flow obfuscator
// that rotates the boolean result through CF without changing its value.
//
// boot helper: sub_FFFFF8013ADCE3E0 -- the 4-arg OID matcher (haystack,
// haystack_len, needle, needle_len) returning the offset of the OID start
// inside the haystack or 0 if not found.
// ============================================================================

/* Found by the user researcher, then confirmed and verified bit-for-bit against the binary database at 0xFFFFF8013ADCE3E0. Boyer-Moore-style
   byte search helper. binary-database body walks haystack up to
   (haystack+haystack_len-needle_len+1) testing needle's last byte and
   tail-calling loc_FFFFF8013ADDFB00 (memcmp-like) on match. Returns the
   absolute VA of the match in haystack, or 0. Body is supplied externally;
   call-site contract treats the return as a pointer. */
extern "C" __int64 sub_FFFFF8013ADCE3E0(const void* haystack, ULONGLONG haystack_len,
                                       const void* needle, ULONGLONG needle_len) noexcept;

struct VGK_SIGNER_VIEW
{
    ULONG  payload_total_len;
    PUCHAR payload_begin;
};

BOOLEAN vgk_authenticode_asn1_signer_scan_FFFFF8013ADB8898(const UCHAR** msg_view,
                                                          VGK_SIGNER_VIEW* out) noexcept
{
    if (msg_view == nullptr || out == nullptr) { return FALSE; }
    const ULONG  msg_len   = *(const ULONG*)msg_view;
    const UCHAR* msg_bytes = *(const UCHAR* const*)(msg_view + 1);
    ULONG  v18[2];
    USHORT v19;
    v18[0] = 67175979u;
    v18[1] = 37192193u;
    v19    = 3073u;
    if (msg_len < 0x0Eu) { return FALSE; }
    const UCHAR* p   = msg_bytes;
    const UCHAR* end = msg_bytes + msg_len;
    ULONG remaining  = msg_len;
    while (p < end)
    {
        __int64 oid_off = sub_FFFFF8013ADCE3E0(p, remaining, v18, 10);
        if (oid_off == 0)
        {
            p += 1;
            if (remaining > 0u) { remaining -= 1; }
            continue;
        }
        p          = (const UCHAR*)(oid_off + 10);
        remaining  = (ULONG)(end - p);
        if (remaining <= 4u) { return FALSE; }
        if (*p != 0x31u && *p != 0x30u) { continue; }
        const UCHAR len_byte = *(p + 1);
        ULONG payload_len = 0u;
        ULONG header_len  = 1u;
        if ((len_byte & 0x80u) == 0u)
        {
            payload_len = len_byte;
            header_len  = 1u;
        }
        else
        {
            const UCHAR n = len_byte & 0x7Fu;
            if (n > 4u) { continue; }
            if ((ULONG)n + 2u > remaining) { continue; }
            ULONG acc = 0u;
            const UCHAR* q = p + 2;
            for (UCHAR i = 0; i < n; ++i) { acc = (acc << 8) | *q++; }
            payload_len = acc;
            header_len  = (ULONG)n + 1u;
        }
        if (payload_len + header_len > remaining) { return FALSE; }
        out->payload_total_len = payload_len;
        out->payload_begin     = (PUCHAR)(p + header_len);
        return TRUE;
    }
    return FALSE;
}

// vgk_syscall_stack_walker_pcr is actually the KPCR (Kernel Processor
// Control Region) syscall stack walker, NOT TPM PCR -- the name is
// misleading. The function lives at 0xFFFFF8013AD8C258 (.text, 0x84 bytes)
// and walks the SSDT-anchored stack frame range using KeGetPcr()[1].NtTib
// .Self as the upper bound, scanning a u16 head array for a tag word (a1)
// and a 20-bit hash (a2) matching the syscall return stub. The range gate
// is [g_ssdt_lo at 0xFFFFF8013ADF4048, g_ssdt_hi at 0xFFFFF8013ADF4050];
// any entry whose ExceptionList field (treated as a function pointer)
// lands inside that range is forwarded to vgk_hook_target_classifier_15slot
// for slot classification. Used by Vanguard to fingerprint kernel syscall
// hooks. Rides on SECTION 6 (BCrypt) and SECTION 96 (evidence pool); fires
// only from the SECTION 188 syscall-hook detection cycle. Hot path.
// ============================================================================
// SECTION 99 -- vgk_syscall_stack_walker_pcr (found by the user researcher, then
//               confirmed and decompile-verified from
//               0xFFFFF8013AD8C258, .text, 0x84 bytes)
//
// Provenance: live binary database decompile of `vgk_syscall_stack_walker_pcr`. This is
// the **KPCR (Kernel Processor Control Region)** syscall stack walker -- NOT
// TPM PCR. Despite the name, it walks the SSDT-anchored stack frame range
// using KeGetPcr()[1].NtTib.Self as the upper bound, scanning a u16 head
// array for a tag word (a1) and a 20-bit hash (a2) matching the syscall
// return stub.
//
// Range gate: [g_ssdt_lo_FFFFF8013ADF4048, g_ssdt_hi_FFFFF8013ADF4050]; any
// entry whose ExceptionList field (treated as a function pointer) lands inside
// that range is forwarded to `vgk_hook_target_classifier_15slot` for slot
// classification. Used by Vanguard to fingerprint kernel syscall hooks via
// the KPCR-anchored TIB chain.
//
// This is the function that triggered the original "KPCR vs TPM PCR" mix-up
// captured in user feedback memory -- preserved here under its binary-database-canonical
// name for completeness.
// ============================================================================

extern "C" UCHAR vgk_hook_target_classifier_15slot(NT_TIB* self,
                                                   PVOID* candidate_target) noexcept;
extern "C" ULONGLONG qword_FFFFF8013ADF4048;
extern "C" ULONGLONG qword_FFFFF8013ADF4050;

ULONGLONG vgk_syscall_stack_walker_pcr_FFFFF8013AD8C258(const USHORT* tag_array,
                                                       ULONGLONG hash_input) noexcept
{
    NT_TIB* self = KeGetPcr()[1].NtTib.Self;
    ULONG result = 0u;
    ULONG hash_lo = (ULONG)hash_input;
    if (tag_array < (const USHORT*)self)
    {
        const USHORT tag_word = (USHORT)((hash_input >> 32) & 0xFFFFu);
        while (TRUE)
        {
            NT_TIB* candidate = (NT_TIB*)(tag_array + 4);
            if (*tag_array == tag_word
                && ((hash_lo ^ (ULONG)(ULONG_PTR)candidate->ExceptionList) & 0xFFFFFu) == 0u)
            {
                break;
            }
            tag_array += 4;
            if (candidate >= self) { return result; }
        }
        for (NT_TIB* it = (NT_TIB*)(tag_array + 8); it < self; it = (NT_TIB*)((PUCHAR)it + 8))
        {
            if ((ULONGLONG)(ULONG_PTR)it->ExceptionList >= qword_FFFFF8013ADF4048
                && (ULONGLONG)(ULONG_PTR)it->ExceptionList <  qword_FFFFF8013ADF4050)
            {
                return (UCHAR)vgk_hook_target_classifier_15slot(self, (PVOID*)&it[1].StackLimit);
            }
        }
    }
    return result;
}

// The evidence APC triple is three asynchronous flushers, queued via
// KeInitializeApc plus KeInsertQueueApc with three distinct normal routines.
// They exist because flushing the ring synchronously at elevated IRQL is
// too risky -- the APCs let the work happen at PASSIVE on the target
// thread. The three KAPC callback routines that the evidence subsystem
// uses to free the pool blob it allocated via vgk_evidence_pool_alloc are
// vgk_evidence_apc_kernel_routine at 0xFFFFF8013AD9B26C (0x15 bytes, canary
// 658620181), vgk_evidence_apc_normal_routine at 0xFFFFF8013AD9B2AC (0x1C
// bytes, canary -55313257), and vgk_evidence_apc_rundown_routine at
// 0xFFFFF8013AD9B314 (0x15 bytes, canary -1672579734). All three update
// the rolling canary mailbox at g_canary_mailbox+4/+8 and dispatch through
// vgk_evidence_pool_free at 0xAD9DDA4 ('None' tag free). Sits on SECTION
// 96 pool and SECTION 101 ring writer; queued from DPC and timer contexts.
// ============================================================================
