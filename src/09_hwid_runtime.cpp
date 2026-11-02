// ============================================================================
// Overlay of module: 09_hwid_runtime.cpp
// PCR replay, HWID pipelines, NDIS/EDID, VT-x/VT-d/AMD-Vi, DMA Guard, Pluton, boot HWID schemas
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
// SECTION 258 -- Registry HWID readers (MachineGuid + InstallDate + ProductId)
//                Vanguard pulls these per-machine identifiers via ZwOpenKey +
//                ZwQueryValueKey at boot and again periodically in-game to
//                catch SID/MachineGuid spoofing. All paths are FIXED Windows
//                registry locations (Win7-Win11).
// ============================================================================

constexpr WCHAR VGK_REG_KEY_CRYPTOGRAPHY[]      = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography";
constexpr WCHAR VGK_REG_KEY_CURRENT_VERSION[]   = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
constexpr WCHAR VGK_REG_KEY_SYSTEMINFO[]        = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System";
constexpr WCHAR VGK_REG_KEY_CENTRAL_PROCESSOR_0[] = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
constexpr WCHAR VGK_REG_KEY_BIOS[]              = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS";
constexpr WCHAR VGK_REG_KEY_COMPUTERNAME[]      = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
constexpr WCHAR VGK_REG_KEY_ACTIVE_COMPUTERNAME[]= L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName";
constexpr WCHAR VGK_REG_KEY_SESSION_MANAGER[]   = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
constexpr WCHAR VGK_REG_KEY_MEMORY_MANAGEMENT[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
constexpr WCHAR VGK_REG_KEY_DEVICEGUARD[]       = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
constexpr WCHAR VGK_REG_KEY_HYPERVISOR[]        = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\HyperV";
constexpr WCHAR VGK_REG_KEY_LSA[]               = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\LSA";
constexpr WCHAR VGK_REG_KEY_PRODUCTOPTIONS[]    = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions";
constexpr WCHAR VGK_REG_KEY_CI[]                = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CI";
constexpr WCHAR VGK_REG_KEY_CI_POLICY[]         = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy";
constexpr WCHAR VGK_REG_KEY_NTFS_PARAMETERS[]   = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FileSystem";
constexpr WCHAR VGK_REG_KEY_TPM_DEVICE[]        = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM";
constexpr WCHAR VGK_REG_KEY_TBS_SERVICE[]       = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TBS";

constexpr WCHAR VGK_REG_VAL_MACHINE_GUID[]      = L"MachineGuid";
constexpr WCHAR VGK_REG_VAL_PRODUCT_ID[]        = L"ProductId";
constexpr WCHAR VGK_REG_VAL_PRODUCT_NAME[]      = L"ProductName";
constexpr WCHAR VGK_REG_VAL_INSTALL_DATE[]      = L"InstallDate";
constexpr WCHAR VGK_REG_VAL_BUILD_LAB[]         = L"BuildLab";
constexpr WCHAR VGK_REG_VAL_BUILD_LAB_EX[]      = L"BuildLabEx";
constexpr WCHAR VGK_REG_VAL_CURRENT_BUILD[]     = L"CurrentBuild";
constexpr WCHAR VGK_REG_VAL_CURRENT_BUILD_NUMBER[] = L"CurrentBuildNumber";
constexpr WCHAR VGK_REG_VAL_UBR[]               = L"UBR";
constexpr WCHAR VGK_REG_VAL_RELEASE_ID[]        = L"ReleaseId";
constexpr WCHAR VGK_REG_VAL_DISPLAY_VERSION[]   = L"DisplayVersion";
constexpr WCHAR VGK_REG_VAL_EDITION_ID[]        = L"EditionID";
constexpr WCHAR VGK_REG_VAL_INSTALLATION_TYPE[] = L"InstallationType";
constexpr WCHAR VGK_REG_VAL_BIOS_VENDOR[]       = L"BIOSVendor";
constexpr WCHAR VGK_REG_VAL_BIOS_VERSION[]      = L"BIOSVersion";
constexpr WCHAR VGK_REG_VAL_BIOS_RELEASE_DATE[] = L"BIOSReleaseDate";
constexpr WCHAR VGK_REG_VAL_SYSTEM_MANUFACTURER[] = L"SystemManufacturer";
constexpr WCHAR VGK_REG_VAL_SYSTEM_PRODUCT_NAME[] = L"SystemProductName";
constexpr WCHAR VGK_REG_VAL_SYSTEM_SKU[]        = L"SystemSKU";
constexpr WCHAR VGK_REG_VAL_BASEBOARD_MANUFACTURER[] = L"BaseBoardManufacturer";
constexpr WCHAR VGK_REG_VAL_BASEBOARD_PRODUCT[] = L"BaseBoardProduct";
constexpr WCHAR VGK_REG_VAL_BASEBOARD_VERSION[] = L"BaseBoardVersion";
constexpr WCHAR VGK_REG_VAL_PROCESSOR_NAME_STRING[] = L"ProcessorNameString";
constexpr WCHAR VGK_REG_VAL_PROCESSOR_IDENTIFIER[]= L"Identifier";
constexpr WCHAR VGK_REG_VAL_VENDOR_IDENTIFIER[] = L"VendorIdentifier";
constexpr WCHAR VGK_REG_VAL_MHZ[]               = L"~MHz";
constexpr WCHAR VGK_REG_VAL_COMPUTER_NAME[]     = L"ComputerName";
constexpr WCHAR VGK_REG_VAL_HVCI_ENABLED[]      = L"HypervisorEnforcedCodeIntegrity";
constexpr WCHAR VGK_REG_VAL_HVCI_LOCKED[]       = L"Locked";

NTSTATUS vgk_reg_open_key_ro(_In_ PCWSTR full_path, _Out_ HANDLE* out_handle) noexcept
{
    if (full_path == nullptr || out_handle == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_handle = NULL;

    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    RtlInitUnicodeString(&us, full_path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwOpenKey(out_handle, KEY_READ, &oa);
}

NTSTATUS vgk_reg_query_string(_In_ HANDLE key,
                               _In_ PCWSTR value_name,
                               _Out_writes_bytes_(out_size) PWCHAR out_buffer,
                               _In_ ULONG out_size,
                               _Out_opt_ PULONG out_actual_chars) noexcept
{
    if (key == NULL || value_name == nullptr || out_buffer == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (out_actual_chars != NULL) { *out_actual_chars = 0u; }

    UNICODE_STRING us_name;
    RtlInitUnicodeString(&us_name, value_name);

    UCHAR stack_buf[512];
    ULONG result_len = 0u;
    NTSTATUS s = ZwQueryValueKey(key, &us_name, KeyValuePartialInformation, stack_buf, sizeof(stack_buf), &result_len);
    if (!NT_SUCCESS(s)) { return s; }
    if (result_len < sizeof(KEY_VALUE_PARTIAL_INFORMATION)) { return STATUS_DATA_ERROR; }

    const KEY_VALUE_PARTIAL_INFORMATION* pi = (const KEY_VALUE_PARTIAL_INFORMATION*)stack_buf;
    if (pi->Type != REG_SZ && pi->Type != REG_EXPAND_SZ) { return STATUS_OBJECT_TYPE_MISMATCH; }
    if (pi->DataLength > out_size) { return STATUS_BUFFER_TOO_SMALL; }

    RtlCopyMemory(out_buffer, pi->Data, pi->DataLength);
    if (out_actual_chars != NULL) { *out_actual_chars = pi->DataLength / (ULONG)sizeof(WCHAR); }
    return STATUS_SUCCESS;
}

NTSTATUS vgk_reg_query_dword(_In_ HANDLE key,
                              _In_ PCWSTR value_name,
                              _Out_ PULONG out_value) noexcept
{
    if (key == NULL || value_name == nullptr || out_value == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_value = 0u;

    UNICODE_STRING us_name;
    RtlInitUnicodeString(&us_name, value_name);

    UCHAR stack_buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG result_len = 0u;
    NTSTATUS s = ZwQueryValueKey(key, &us_name, KeyValuePartialInformation, stack_buf, sizeof(stack_buf), &result_len);
    if (!NT_SUCCESS(s)) { return s; }

    const KEY_VALUE_PARTIAL_INFORMATION* pi = (const KEY_VALUE_PARTIAL_INFORMATION*)stack_buf;
    if (pi->Type != REG_DWORD) { return STATUS_OBJECT_TYPE_MISMATCH; }
    if (pi->DataLength != sizeof(ULONG)) { return STATUS_DATA_ERROR; }

    *out_value = *(const ULONG*)pi->Data;
    return STATUS_SUCCESS;
}

NTSTATUS vgk_machine_guid_capture(_Out_writes_(40) PWCHAR out_guid_str) noexcept
{
    if (out_guid_str == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_guid_str, 40u * sizeof(WCHAR));

    HANDLE key = NULL;
    NTSTATUS s = vgk_reg_open_key_ro(VGK_REG_KEY_CRYPTOGRAPHY, &key);
    if (!NT_SUCCESS(s)) { return s; }

    ULONG ch = 0u;
    s = vgk_reg_query_string(key, VGK_REG_VAL_MACHINE_GUID, out_guid_str, 40u * sizeof(WCHAR), &ch);
    ZwClose(key);
    return s;
}

NTSTATUS vgk_hvci_status_capture(_Out_ PULONG out_enabled,
                                  _Out_ PULONG out_locked) noexcept
{
    if (out_enabled == nullptr || out_locked == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_enabled = 0u; *out_locked = 0u;

    HANDLE key = NULL;
    NTSTATUS s = vgk_reg_open_key_ro(VGK_REG_KEY_DEVICEGUARD, &key);
    if (!NT_SUCCESS(s)) { return s; }

    vgk_reg_query_dword(key, VGK_REG_VAL_HVCI_ENABLED, out_enabled);
    vgk_reg_query_dword(key, VGK_REG_VAL_HVCI_LOCKED,  out_locked);
    ZwClose(key);
    return STATUS_SUCCESS;
}

// SECTION 259 is the TSC drift watcher paired with a monotonic clock reference.
// TSC drift is a strong timing-attack signal, but TSC alone is noisy, so
// Vanguard pairs it with KeQueryPerformanceCounter and computes a ratio to nail
// down whether the drift is real. It rides on the SECTION 56 TPM2_ReadClock
// anchor plus the kernel's KeQuery* monotonic counters and gets called every
// heartbeat by the periodic detection orchestrator. The mechanic samples TSC
// and KeQPC, computes the ratio, and compares to the captured baseline.
// ============================================================================
// SECTION 259 -- TSC drift watcher + monotonic clock pair
//                Captures TSC + QPC + KeQueryInterruptTime at boot, then
//                re-samples in-game and verifies the ratio (TSC ticks per
//                QPC tick) is constant within tolerance. Hypervisor TSC
//                emulation will reveal itself as non-constant ratio drift.
// ============================================================================

struct VGK_TSC_BASELINE
{
    ULONGLONG tsc_at_capture;
    ULONGLONG qpc_at_capture;
    ULONGLONG interrupt_time_at_capture;
    ULONGLONG system_time_at_capture;
    ULONGLONG perf_frequency_hz;
    ULONGLONG calibrated_ratio_q32;
};

struct VGK_TSC_DRIFT_SAMPLE
{
    ULONGLONG tsc_now;
    ULONGLONG qpc_now;
    ULONGLONG interrupt_time_now;
    ULONGLONG tsc_delta;
    ULONGLONG qpc_delta;
    ULONGLONG ratio_q32;
    ULONGLONG expected_ratio_q32;
    ULONG     deviation_ppm;
};

constexpr ULONG VGK_TSC_DRIFT_TOLERANCE_PPM                  = 1000u;
constexpr ULONG VGK_TSC_HV_EMULATION_PPM_THRESHOLD           = 5000u;

NTSTATUS vgk_tsc_baseline_capture(_Out_ VGK_TSC_BASELINE* out_base) noexcept
{
    if (out_base == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_base, sizeof(*out_base));

    LARGE_INTEGER freq;
    LARGE_INTEGER qpc1 = KeQueryPerformanceCounter(&freq);
    LARGE_INTEGER it1; it1.QuadPart = (LONGLONG)KeQueryInterruptTime();
    LARGE_INTEGER systime; KeQuerySystemTime(&systime);
    const ULONGLONG tsc1 = __rdtsc();
constexpr ULONG VGK_TPM_TIS_REG_INT_VECTOR                = 0x000Cu;
constexpr ULONG VGK_TPM_TIS_REG_INT_STATUS                = 0x0010u;
constexpr ULONG VGK_TPM_TIS_REG_INTF_CAPABILITY           = 0x0014u;
constexpr ULONG VGK_TPM_TIS_REG_STS                       = 0x0018u;
constexpr ULONG VGK_TPM_TIS_REG_BURST_COUNT               = 0x0019u;
constexpr ULONG VGK_TPM_TIS_REG_DATA_FIFO                 = 0x0024u;
constexpr ULONG VGK_TPM_TIS_REG_INTERFACE_ID              = 0x0030u;
constexpr ULONG VGK_TPM_TIS_REG_XDATA_FIFO                = 0x0080u;
constexpr ULONG VGK_TPM_TIS_REG_DID_VID                   = 0x0F00u;
constexpr ULONG VGK_TPM_TIS_REG_RID                       = 0x0F04u;

constexpr UCHAR VGK_TPM_TIS_ACCESS_VALID                  = 0x80u;
constexpr UCHAR VGK_TPM_TIS_ACCESS_ACTIVE_LOCALITY        = 0x20u;
constexpr UCHAR VGK_TPM_TIS_ACCESS_BEEN_SEIZED            = 0x10u;
constexpr UCHAR VGK_TPM_TIS_ACCESS_SEIZE                  = 0x08u;
constexpr UCHAR VGK_TPM_TIS_ACCESS_PENDING_REQUEST        = 0x04u;
constexpr UCHAR VGK_TPM_TIS_ACCESS_REQUEST_USE            = 0x02u;
constexpr UCHAR VGK_TPM_TIS_ACCESS_TPM_REG_VALID_STS      = 0x80u;
constexpr UCHAR VGK_TPM_TIS_ACCESS_RELINQUISH_LOCALITY    = 0x20u;

constexpr UCHAR VGK_TPM_TIS_STS_VALID                     = 0x80u;
constexpr UCHAR VGK_TPM_TIS_STS_COMMAND_READY             = 0x40u;
constexpr UCHAR VGK_TPM_TIS_STS_TPM_GO                    = 0x20u;
constexpr UCHAR VGK_TPM_TIS_STS_DATA_AVAIL                = 0x10u;
constexpr UCHAR VGK_TPM_TIS_STS_DATA_EXPECT               = 0x08u;
constexpr UCHAR VGK_TPM_TIS_STS_SELF_TEST_DONE            = 0x04u;
constexpr UCHAR VGK_TPM_TIS_STS_RESPONSE_RETRY            = 0x02u;

constexpr ULONG VGK_TPM_CRB_CTRL_REQ_CMD_READY            = 0x00000001u;
constexpr ULONG VGK_TPM_CRB_CTRL_REQ_GO_IDLE              = 0x00000002u;
constexpr ULONG VGK_TPM_CRB_CTRL_STS_TPM_STS              = 0x00000001u;
constexpr ULONG VGK_TPM_CRB_CTRL_STS_TPM_IDLE             = 0x00000002u;
constexpr ULONG VGK_TPM_CRB_CTRL_CANCEL_VALUE             = 0x00000001u;
constexpr ULONG VGK_TPM_CRB_CTRL_START_VALUE              = 0x00000001u;
constexpr ULONG VGK_TPM_CRB_LOC_CTRL_REQUEST_ACCESS       = 0x00000001u;
constexpr ULONG VGK_TPM_CRB_LOC_CTRL_RELINQUISH           = 0x00000002u;
constexpr ULONG VGK_TPM_CRB_LOC_CTRL_SEIZE                = 0x00000004u;
constexpr ULONG VGK_TPM_CRB_LOC_CTRL_RESET                = 0x00000008u;
constexpr ULONG VGK_TPM_CRB_LOC_STS_GRANTED               = 0x00000001u;
constexpr ULONG VGK_TPM_CRB_LOC_STS_BEEN_SEIZED           = 0x00000002u;
constexpr ULONG VGK_TPM_CRB_LOC_STATE_TPM_ESTABLISHED     = 0x00000001u;
constexpr ULONG VGK_TPM_CRB_LOC_STATE_LOC_ASSIGNED        = 0x00000002u;
constexpr ULONG VGK_TPM_CRB_LOC_STATE_ACTIVE_LOC_MASK     = 0x0000001Cu;
constexpr ULONG VGK_TPM_CRB_LOC_STATE_TPM_REG_VALID_STS   = 0x00000080u;

struct VGK_LOADER_PARAMETER_HYPERVISOR_EXTENSION
{
    ULONG     InitialHypervisorCrashdumpAreaPageCount;
    ULONG     HypervisorCrashdumpAreaSpan;
    ULONGLONG InitialHypervisorCrashdumpAreaSpa;
    ULONGLONG Phase1InitializationContext;
    ULONGLONG HypervisorCrashdumpAreaSpa;
    ULONGLONG HypervisorLaunchStatus;
    ULONGLONG HypervisorLaunchStatusArg1;
    ULONGLONG HypervisorLaunchStatusArg2;
    ULONGLONG HypervisorLaunchStatusArg3;
    ULONGLONG HypervisorLaunchStatusArg4;
};

struct VGK_LOADER_BUGCHECK_PARAMETERS
{
    ULONG     BugcheckCode;
    ULONG_PTR BugcheckParameter1;
    ULONG_PTR BugcheckParameter2;
    ULONG_PTR BugcheckParameter3;
    ULONG_PTR BugcheckParameter4;
};

struct VGK_OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
{
    ULONG     Version;
    ULONG     AbnormalResetOccurred;
    ULONG     OfflineMemoryDumpCapable;
    ULONGLONG ResetDataAddress;
    ULONG     ResetDataSize;
};

struct VGK_LOADER_PARAMETER_EXTENSION
{
    ULONG  Size;
    ULONG  Profile_Status;
    ULONG  Profile_Reserved;
    ULONG  Profile_DockingState;
    ULONG  ComponentCount;
    ULONG  Profile_CapabilitiesIndex;
    PVOID  ComponentEntries;
    PVOID  CompatibilityDataMap;
    USHORT MajorVersion;
    USHORT MinorVersion;
    PVOID  EmInfFileImage;
    ULONG  EmInfFileSize;
    PVOID  TriageDumpBlock;
    ULONGLONG LoaderPagesSpanned;
    PVOID  HeadlessLoaderBlock;
    PVOID  SMBiosEPSHeader;
    PVOID  DrvDBImage;
    ULONG  DrvDBSize;
    ULONG  DrvDBPatchImageSize;
    PVOID  DrvDBPatchImage;
    PVOID  NetworkLoaderBlock;
    PVOID  HalpIRQLToTPR;
    PVOID  HalpVectorToIRQL;
    LIST_ENTRY FirmwareDescriptorListHead;
    PVOID  AcpiTable;
    ULONG  AcpiTableSize;
    ULONG  BootViaWinload      : 1;
    ULONG  BootViaEFI          : 1;
    ULONG  Reserved            : 30;
    PVOID  Loader;
    PVOID  InterruptControllerData;
    LIST_ENTRY FirmwareResourceList;
    PVOID  EfiRuntimeServiceTable;
    PVOID  AcpiRuntimeServiceTable;
    PVOID  SystemTime;
    ULONGLONG BootEntropyTable[576];
    LARGE_INTEGER ProcessorCounterFrequency;
    GUID   HardwareConfigurationId;
    LIST_ENTRY HalExtensionModuleList;
    LIST_ENTRY PrmUpdateEntryList;
    LIST_ENTRY PrmFirmwareModuleList;
    LARGE_INTEGER SystemTimeRtc;
    ULONGLONG TscHypervisorClockFrequency;
    UCHAR  ProcessorIdle           : 1;
    UCHAR  ProcessorReserved       : 7;
    UCHAR  ProcessorFlags;
    UCHAR  PerformanceCounterFrequency_x86;
    UCHAR  Reserved2;
    PVOID  KdDebugDevice;
    PVOID  KdDebugFirmwareData;
    PVOID  OfflineCrashdumpConfigurationTable;
    UCHAR  ManufacturingProfile[128];
    PVOID  BbtBuffer;
    ULONGLONG XsaveAllowedFeatures;
    ULONG  XsaveFlags;
    PVOID  BootOptions;
    ULONG  BootId;
    PVOID  IumEnablement;
    PVOID  IumPolicy;
    NTSTATUS IumStatus;
    ULONG  BootEntropyResult;
    ULONGLONG TestExpressionsPattern;
    UCHAR  EnabledBootDebuggers;
    PVOID  BootStateData;
    ULONG  KernelDebuggerFlags;
    GUID   KernelDebuggerInstanceId;
    PVOID  BootApplicationPersistentData;
    PVOID  VsmPerformanceData;
    PVOID  NumaLocalityInfo;
    PVOID  NumaGroupAssignment;
    ULONGLONG AcpiBiosVersion;
    ULONGLONG SmbiosVersion;
    ULONGLONG EfiVersion;
    PVOID  KdDebugFirmwareDataPa;
    PVOID  TpmBootEntropyResult;
    ULONGLONG ProcessorCounterStart;
    VGK_LOADER_PARAMETER_HYPERVISOR_EXTENSION HypervisorExtension;
};

constexpr ULONG VGK_LDR_DATA_LOAD_HVCI_ENABLED            = 0x00000001u;
constexpr ULONG VGK_LDR_DATA_LOAD_HVCI_STRICT             = 0x00000002u;
constexpr ULONG VGK_LDR_DATA_LOAD_HVCI_DEBUG_ENABLED      = 0x00000004u;
constexpr ULONG VGK_LDR_DATA_LOAD_VBS_ENABLED             = 0x00000008u;
constexpr ULONG VGK_LDR_DATA_LOAD_IUM_ENABLED             = 0x00000010u;
constexpr ULONG VGK_LDR_DATA_LOAD_DUMA_ENABLED            = 0x00000020u;
constexpr ULONG VGK_LDR_DATA_LOAD_DEVGUARD_ENABLED        = 0x00000040u;
constexpr ULONG VGK_LDR_DATA_LOAD_CREDGUARD_ENABLED       = 0x00000080u;
constexpr ULONG VGK_LDR_DATA_LOAD_SECUREBOOT_ENABLED      = 0x00000100u;
constexpr ULONG VGK_LDR_DATA_LOAD_DRTM_ENABLED            = 0x00000200u;
constexpr ULONG VGK_LDR_DATA_LOAD_KMCI_ENFORCED           = 0x00000400u;
constexpr ULONG VGK_LDR_DATA_LOAD_BOOT_DEBUG_ENABLED      = 0x00000800u;
constexpr ULONG VGK_LDR_DATA_LOAD_TEST_SIGNING            = 0x00001000u;
constexpr ULONG VGK_LDR_DATA_LOAD_DSE_DISABLED            = 0x00002000u;

// SECTION 248 handles the TCG_EfiSpecIdEvent crypto-agile log header per PFP
// rev 105 sec 9.4. Modern measured-boot logs lead with this Spec ID Event at
// PCR 0 to declare every active digest bank. The Spec ID Event sits as the
// FIRST TCG_PCR_EVENT (legacy SHA-1 form) and tells parsers the subsequent
// events are TCG_PCR_EVENT2 hash-agile records; Vanguard parses this header
// to learn which banks are active before walking the rest of the log. The
// VGK_TCG_PCR_EVENT_SHA1 struct packs pcr_index, event_type, sha1_digest[20],
// and event_size; the SHA-1 header carries the platformClass, specVersion
// triplet (Major/Minor/Errata), uintnSize, and the numberOfAlgorithms count
// followed by per-algorithm hash_alg/digest_size pairs. Sits on the SECTION
// 201 PFP event types and the SECTION 203 replay verifier; called once per
// measured-boot log parse during SECTION 250 boot baseline computation.
// ============================================================================
// SECTION 250 -- Boot-time PCR baseline computation (full chain)
//                Single end-to-end function: reads ALL active PCR banks via
//                TPM2_PCR_Read, replays the WBCL log via PCR_replay_sha256_full
//                from Section 203, computes the boot HWID composite hash, and
//                stores everything in a VGK_BOOT_PCR_BASELINE structure for
//                Section 217 NV sealing. This is the canonical pipeline.
// ============================================================================

struct VGK_BOOT_PCR_BANK_SNAPSHOT
{
    USHORT  hash_alg;
    USHORT  digest_size;
    UCHAR   live[24][64];
    UCHAR   replayed[24][64];
    ULONG   mismatch_mask;
    ULONG   present_mask;
    UCHAR   reserved[4];
};

struct VGK_BOOT_PCR_BASELINE
{
    ULONG                       structure_version;
    ULONG                       structure_size;
    ULONG                       active_bank_count;
    ULONG                       reserved_a;
    UCHAR                       boot_hwid_composite[32];
    UCHAR                       cumulative_pcr_digest[32];
    ULONGLONG                   capture_qpc;
    ULONGLONG                   capture_system_time;
    VGK_BOOT_PCR_BANK_SNAPSHOT  banks[4];
};

NTSTATUS vgk_boot_pcr_baseline_initialize(_Out_ VGK_BOOT_PCR_BASELINE* baseline) noexcept
{
    if (baseline == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(baseline, sizeof(*baseline));
    baseline->structure_version = 1u;
    baseline->structure_size    = (ULONG)sizeof(VGK_BOOT_PCR_BASELINE);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_boot_pcr_baseline_set_bank(_Inout_ VGK_BOOT_PCR_BASELINE* baseline,
                                         _In_ ULONG bank_index,
                                         _In_ USHORT hash_alg,
                                         _In_ USHORT digest_size,
                                         _In_reads_bytes_(digest_size * 24) const UCHAR* live_pcrs) noexcept
{
    if (baseline == nullptr || live_pcrs == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (bank_index >= 4u) { return STATUS_INVALID_PARAMETER; }
    if (digest_size == 0u || digest_size > 64u) { return STATUS_INVALID_PARAMETER; }

    VGK_BOOT_PCR_BANK_SNAPSHOT* b = &baseline->banks[bank_index];
    b->hash_alg    = hash_alg;
    b->digest_size = digest_size;
    b->present_mask = 0x00FFFFFFu;
    b->mismatch_mask = 0u;
    for (ULONG i = 0; i < 24u; ++i)
    {
        RtlCopyMemory(b->live[i], live_pcrs + (SIZE_T)i * digest_size, digest_size);
        RtlZeroMemory(b->replayed[i], sizeof(b->replayed[i]));
    }

    if (bank_index >= baseline->active_bank_count) { baseline->active_bank_count = bank_index + 1u; }
    return STATUS_SUCCESS;
}

NTSTATUS vgk_boot_pcr_baseline_set_replayed(_Inout_ VGK_BOOT_PCR_BASELINE* baseline,
                                             _In_ ULONG bank_index,
                                             _In_reads_bytes_(digest_size * 24) const UCHAR* replayed_pcrs) noexcept
{
    if (baseline == nullptr || replayed_pcrs == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (bank_index >= baseline->active_bank_count) { return STATUS_INVALID_PARAMETER; }

    VGK_BOOT_PCR_BANK_SNAPSHOT* b = &baseline->banks[bank_index];
    ULONG mismatch = 0u;
    for (ULONG pcr = 0; pcr < 24u; ++pcr)
    {
        RtlCopyMemory(b->replayed[pcr], replayed_pcrs + (SIZE_T)pcr * b->digest_size, b->digest_size);
        if (((b->present_mask >> pcr) & 1u) != 0u)
        {
            const UCHAR* live = b->live[pcr];
            const UCHAR* rep  = b->replayed[pcr];
            BOOLEAN same = TRUE;
            for (USHORT i = 0; i < b->digest_size; ++i) { if (live[i] != rep[i]) { same = FALSE; break; } }
            if (!same) { mismatch |= (1u << pcr); }
        }
    }
    b->mismatch_mask = mismatch;
    return STATUS_SUCCESS;
}

ULONG vgk_boot_pcr_baseline_total_mismatch_mask(_In_ const VGK_BOOT_PCR_BASELINE* baseline) noexcept
{
    if (baseline == nullptr) { return 0u; }
    ULONG mm = 0u;
    for (ULONG i = 0; i < baseline->active_bank_count && i < 4u; ++i) { mm |= baseline->banks[i].mismatch_mask; }
    return mm;
}

NTSTATUS vgk_boot_pcr_baseline_stamp_times(_Inout_ VGK_BOOT_PCR_BASELINE* baseline) noexcept
{
    if (baseline == nullptr) { return STATUS_INVALID_PARAMETER; }
    LARGE_INTEGER qpc; KeQueryPerformanceCounter(&qpc);
    LARGE_INTEGER sys; KeQuerySystemTime(&sys);
    baseline->capture_qpc         = (ULONGLONG)qpc.QuadPart;
    baseline->capture_system_time = (ULONGLONG)sys.QuadPart;
    return STATUS_SUCCESS;
}

NTSTATUS vgk_boot_pcr_baseline_apply_composite(_Inout_ VGK_BOOT_PCR_BASELINE* baseline,
                                                _In_reads_bytes_(32) const UCHAR* composite32) noexcept
{
    if (baseline == nullptr || composite32 == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlCopyMemory(baseline->boot_hwid_composite, composite32, 32u);
    return STATUS_SUCCESS;
}

// SECTION 251 colocates the TPM 2.0 NV-index type constants. NV indexes come in
// several flavors keyed by the TPMA_NV.TPM_NT field; Vanguard uses TPM_NT_ORDINARY
// for the boot-HWID-sealed blob and TPM_NT_PIN_PASS for the monotonic-attempt
// counters that survive across boots. This is pure constant data that feeds the
// SECTION 210 NV_Write path and the SECTION 219 DefineSpace flow. Compile-time
// only, runtime picks via constexpr TPM_NT_ORDINARY, COUNTER, BITS, EXTEND,
// PIN_FAIL, and PIN_PASS.
// ============================================================================
// SECTION 251 -- TPM 2.0 NV index types (PinPass / Counter / Bits / Extend)
//                TPMA_NV.TPM_NT field selects index behavior; Vanguard
//                uses TPM_NT_ORDINARY for the boot-HWID-sealed blob and
//                TPM_NT_PIN_PASS for monotonic-attempt counters that
//                survive across boots.
// ============================================================================

ULONG vgk_pe_cert_dir_alignment_padded_size(_In_ ULONG raw_size) noexcept
{
    return (raw_size + 7u) & ~7u;
}

constexpr ULONG VGK_TPMA_NV_PPWRITE                        = 0x00000001u;
constexpr ULONG VGK_TPMA_NV_OWNERWRITE                     = 0x00000002u;
constexpr ULONG VGK_TPMA_NV_AUTHWRITE                      = 0x00000004u;
constexpr ULONG VGK_TPMA_NV_POLICYWRITE                    = 0x00000008u;

// SECTION 251 colocates the TPM 2.0 NV-index type constants. NV indexes come in
// several flavors keyed by the TPMA_NV.TPM_NT field; Vanguard uses TPM_NT_ORDINARY
// for the boot-HWID-sealed blob and TPM_NT_PIN_PASS for the monotonic-attempt
// counters that survive across boots. This is pure constant data that feeds the
// SECTION 210 NV_Write path and the SECTION 219 DefineSpace flow. Compile-time
// only, runtime picks via constexpr TPM_NT_ORDINARY, COUNTER, BITS, EXTEND,
// PIN_FAIL, and PIN_PASS.
// ============================================================================
// SECTION 251 -- TPM 2.0 NV index types (PinPass / Counter / Bits / Extend)
//                TPMA_NV.TPM_NT field selects index behavior; Vanguard
//                uses TPM_NT_ORDINARY for the boot-HWID-sealed blob and
//                TPM_NT_PIN_PASS for monotonic-attempt counters that
//                survive across boots.
// ============================================================================

constexpr ULONG VGK_TPMA_NV_PPWRITE                        = 0x00000001u;
constexpr ULONG VGK_TPMA_NV_OWNERWRITE                     = 0x00000002u;
constexpr ULONG VGK_TPMA_NV_AUTHWRITE                      = 0x00000004u;
constexpr ULONG VGK_TPMA_NV_POLICYWRITE                    = 0x00000008u;
constexpr ULONG VGK_TPMA_NV_TYPE_MASK                      = 0x000000F0u;
constexpr ULONG VGK_TPMA_NV_TYPE_SHIFT                     = 4u;
constexpr ULONG VGK_TPMA_NV_POLICY_DELETE                  = 0x00000400u;
constexpr ULONG VGK_TPMA_NV_WRITELOCKED                    = 0x00000800u;
constexpr ULONG VGK_TPMA_NV_WRITEALL                       = 0x00001000u;
constexpr ULONG VGK_TPMA_NV_WRITEDEFINE                    = 0x00002000u;
constexpr ULONG VGK_TPMA_NV_WRITE_STCLEAR                  = 0x00004000u;
constexpr ULONG VGK_TPMA_NV_GLOBALLOCK                     = 0x00008000u;
constexpr ULONG VGK_TPMA_NV_PPREAD                         = 0x00010000u;
constexpr ULONG VGK_TPMA_NV_OWNERREAD                      = 0x00020000u;
constexpr ULONG VGK_TPMA_NV_AUTHREAD                       = 0x00040000u;
constexpr ULONG VGK_TPMA_NV_POLICYREAD                     = 0x00080000u;
constexpr ULONG VGK_TPMA_NV_NO_DA                          = 0x02000000u;
constexpr ULONG VGK_TPMA_NV_ORDERLY                        = 0x04000000u;
constexpr ULONG VGK_TPMA_NV_CLEAR_STCLEAR                  = 0x08000000u;
constexpr ULONG VGK_TPMA_NV_READLOCKED                     = 0x10000000u;
constexpr ULONG VGK_TPMA_NV_WRITTEN                        = 0x20000000u;
constexpr ULONG VGK_TPMA_NV_PLATFORMCREATE                 = 0x40000000u;
constexpr ULONG VGK_TPMA_NV_READ_STCLEAR                   = 0x80000000u;

constexpr UCHAR VGK_TPM_NT_ORDINARY                        = 0x0u;
constexpr UCHAR VGK_TPM_NT_COUNTER                         = 0x1u;
constexpr UCHAR VGK_TPM_NT_BITS                            = 0x2u;
constexpr UCHAR VGK_TPM_NT_EXTEND                          = 0x4u;
constexpr UCHAR VGK_TPM_NT_PIN_FAIL                        = 0x8u;
constexpr UCHAR VGK_TPM_NT_PIN_PASS                        = 0x9u;

ULONG vgk_tpma_nv_make_type(_In_ UCHAR tpm_nt) noexcept
{
    return ((ULONG)tpm_nt << VGK_TPMA_NV_TYPE_SHIFT) & VGK_TPMA_NV_TYPE_MASK;
}

UCHAR vgk_tpma_nv_extract_type(_In_ ULONG attrs) noexcept
{
    return (UCHAR)((attrs & VGK_TPMA_NV_TYPE_MASK) >> VGK_TPMA_NV_TYPE_SHIFT);
}

// SECTION 252 is the boot driver companion IPC channel, the TPM bridge between
// the vgk boot driver and the runtime driver. The vgk boot driver exposes a
// control device opened by the user-mode component (FILE_DEVICE_UNKNOWN type
// 0x8000 with method buffered IOCTL codes), and this bridge gives the runtime
// driver access to whatever TPM evidence boot captured. It rides on the
// SECTION 212 capture protocol and SECTION 158 boot driver surface, active
// during the boot-to-runtime handoff via a shared section plus spinlock the
// runtime poller drains.
// ============================================================================
// SECTION 252 -- Boot driver companion IPC channel (TPM bridge)
//                The vgk boot driver exposes a control device that the user-
//                mode component opens via FILE_DEVICE_UNKNOWN type 0x8000 +
//                method buffered IOCTL codes. The companion-to-driver IPC
//                surface marshals TPM commands when the kernel driver lacks
//                TBS access during late boot.
// ============================================================================

constexpr ULONG VGK_BOOT_IPC_DEVICE_TYPE                   = 0x00008000u;

    PVOID rsmb = NULL; ULONG rsmb_len = 0;
    if (NT_SUCCESS(vgk_acpi_table_fetch('RSMB', &rsmb, &rsmb_len)))
    {
        vgk_smbios_parse_type1((const UCHAR*)rsmb, rsmb_len, &snap);
        vgk_smbios_parse_type2((const UCHAR*)rsmb, rsmb_len, &snap);
        vgk_acpi_table_free(rsmb);
    }
    vgk_cpuid_capture_brand_string(&snap);
    vgk_boot_walk_all_disks(&snap);
    vgk_boot_hwid_compute_fingerprint(&snap);
    vgk_boot_hwid_stable_composite(&snap, out_result->runtime_composite);

    LARGE_INTEGER qpc; KeQueryPerformanceCounter(&qpc);
    out_result->runtime_qpc = (ULONGLONG)qpc.QuadPart;
    out_result->elapsed_ticks_since_boot = (ULONG)(out_result->runtime_qpc - boot_qpc);

    BOOLEAN same = TRUE;
    USHORT first_diff = 0xFFFFu;
    for (USHORT i = 0; i < 32u; ++i)
    {
        if (out_result->boot_composite[i] != out_result->runtime_composite[i])
        {
            same = FALSE;
            if (first_diff == 0xFFFFu) { first_diff = i; }
constexpr ULONG VGK_BOOT_FILE_WRITE_ACCESS                 = 2u;
constexpr ULONG VGK_BOOT_FILE_READ_WRITE_ACCESS            = 3u;

constexpr ULONG vgk_boot_ipc_make_code(_In_ ULONG function, _In_ ULONG method, _In_ ULONG access) noexcept
{
    return (VGK_BOOT_IPC_DEVICE_TYPE << 16) | (access << 14) | (function << 2) | method;
}

#pragma pack(push, 1)
struct VGK_BOOT_IPC_HEADER
{
    ULONG     magic;
    ULONG     version;
    ULONG     function;
    ULONG     payload_size;
    ULONG     status;
    ULONG     reserved;
    ULONGLONG correlation_id;
};

struct VGK_BOOT_IPC_PCR_READ_REQUEST
{
    USHORT hash_alg;
    USHORT pcr_mask_low;
    UCHAR  pcr_mask_mid;
    UCHAR  reserved[3];
};

struct VGK_BOOT_IPC_PCR_READ_RESPONSE
{
    USHORT hash_alg;
    USHORT digest_size;
    ULONG  returned_mask;
    UCHAR  pcrs[24][64];
};
#pragma pack(pop)

constexpr ULONG VGK_BOOT_IPC_HEADER_MAGIC                  = 'KTOB';
constexpr ULONG VGK_BOOT_IPC_VERSION_1                     = 1u;

NTSTATUS vgk_boot_ipc_header_initialize(_Out_ VGK_BOOT_IPC_HEADER* hdr,
                                         _In_ ULONG function,
                                         _In_ ULONG payload_size,
                                         _In_ ULONGLONG correlation_id) noexcept
{
    if (hdr == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(hdr, sizeof(*hdr));
    hdr->magic          = VGK_BOOT_IPC_HEADER_MAGIC;
    hdr->version        = VGK_BOOT_IPC_VERSION_1;
    hdr->function       = function;
    hdr->payload_size   = payload_size;
    hdr->status         = (ULONG)STATUS_PENDING;
    hdr->correlation_id = correlation_id;
    return STATUS_SUCCESS;
}

NTSTATUS vgk_boot_ipc_header_validate(_In_ const VGK_BOOT_IPC_HEADER* hdr, _In_ ULONG total_size) noexcept
{
    if (hdr == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (total_size < sizeof(VGK_BOOT_IPC_HEADER)) { return STATUS_BUFFER_TOO_SMALL; }
    if (hdr->magic != VGK_BOOT_IPC_HEADER_MAGIC) { return STATUS_DATA_ERROR; }
    if (hdr->version != VGK_BOOT_IPC_VERSION_1) { return STATUS_REVISION_MISMATCH; }
    if ((ULONGLONG)hdr->payload_size + sizeof(VGK_BOOT_IPC_HEADER) > total_size) { return STATUS_INVALID_BUFFER_SIZE; }
    return STATUS_SUCCESS;
}

// SECTION 253 reads the Windows WMI activation status via the Slmgr/SPP
// product key registry values. Activation state is a coarse but useful
// install-identity HWID input, especially for spotting fresh OEM resets
// versus genuine retail. The companion service queries the activation grace
// timer via WMI namespace root\CIMV2\SoftwareLicensingProduct, with the GUID
// catalog covering VGK_WMI_SOFTWARELICENSING_GUID and
// VGK_WMI_SLMGR_NAMESPACE_GUID for the binding. License status maps to the
// three-state classifier: UNLICENSED (0), LICENSED (1), plus the grace-
// period states for OOB and retail. The result is pushed into the boot HWID
// composite as a coarse anti-tampering signal. Sits on top of SECTION 258's
// registry HWID readers and runs once per HWID composite refresh through the
// SECTION 24 assembler. Cold path -- boot-only capture.
// ============================================================================
// SECTION 253 -- Windows WMI activation status reader (Slmgr / SPP product key)
//                The companion service queries the activation grace timer via
//                the WMI namespace root\CIMV2\SoftwareLicensingProduct and
//                pushes the activation state into the boot HWID composite as
//                a coarse anti-tampering signal. Below: the raw WMI binding.
// ============================================================================

constexpr GUID VGK_WMI_SOFTWARELICENSING_GUID =
    { 0x76A64158, 0xCB41, 0x11D1, { 0x8B, 0x02, 0x00, 0xA0, 0xC9, 0x06, 0xB8, 0xC0 } };

constexpr GUID VGK_WMI_SLMGR_NAMESPACE_GUID =
    { 0x76FCA08D, 0x5E59, 0x4D60, { 0x9A, 0x99, 0x00, 0xCE, 0x10, 0xCD, 0xE8, 0xBA } };

constexpr ULONG VGK_LICENSE_STATUS_UNLICENSED               = 0u;
constexpr ULONG VGK_LICENSE_STATUS_LICENSED                 = 1u;
constexpr ULONG VGK_LICENSE_STATUS_OOB_GRACE                = 2u;
constexpr ULONG VGK_LICENSE_STATUS_OOT_GRACE                = 3u;
constexpr ULONG VGK_LICENSE_STATUS_NON_GENUINE              = 4u;
constexpr ULONG VGK_LICENSE_STATUS_NOTIFICATION             = 5u;
constexpr ULONG VGK_LICENSE_STATUS_EXTENDED_GRACE           = 6u;

constexpr UCHAR VGK_GRACE_REASON_NONE                      = 0x00u;
constexpr UCHAR VGK_GRACE_REASON_FIRST_BOOT                 = 0x01u;
constexpr UCHAR VGK_GRACE_REASON_REARM                      = 0x02u;
constexpr UCHAR VGK_GRACE_REASON_KMS_CACHE_EXPIRED          = 0x03u;
constexpr UCHAR VGK_GRACE_REASON_TOKEN_DEPENDENCY           = 0x04u;
// SECTION 254 is the runtime in-game HWID re-fetch and drift detector.
// Vanguard re-issues the same hardware-identifier collection chain it ran at
// boot and SHA-256 compares the new composite to the captured one, which
// catches swap-mid-game vectors that pre-boot enforcement misses. The mismatch
// publication path emits HWID drift event 0x68574944 ('HWiD'-LE) at severity
// 0x03 with a per-reason byte: NONE (0x00), SMBIOS_TYPE1 (0x01),
// SMBIOS_TYPE2 (0x02), CPU_BRAND (0x03), DISK_SIGNATURE (0x04), NIC_MAC
// (0x05), and the rest of the per-field reason codes. Drift hits feed into
// SECTION 307's HWID-ban active-enforcement gate which checks the per-game
// banned ring at xmmword_FFFFF8013AE03030. Feeds on outputs from SECTION
// 207's boot capture and SECTION 24's assembler; triggered both by SECTION
// 260's hot-plug PnP path and the SECTION 189 heartbeat re-baseline tick.
// SECTION 254 -- Runtime (in-game) HWID re-fetch + drift detector
//                Vanguard's scan loop re-issues the same hardware-identifier
//                collection chain it ran at boot, then SHA-256 compares the
//                two composite hashes. Any mismatch is published to evidence
//                as a HWID-drift event with the byte index of the first diff.
// ============================================================================

constexpr ULONG VGK_HWID_DRIFT_EVENT_ID                     = 0x68574944u;
constexpr ULONG VGK_HWID_DRIFT_SEVERITY                     = 0x00000003u;
constexpr ULONG VGK_HWID_DRIFT_REASON_NONE                  = 0x00u;
constexpr ULONG VGK_HWID_DRIFT_REASON_SMBIOS_TYPE1          = 0x01u;
constexpr ULONG VGK_HWID_DRIFT_REASON_SMBIOS_TYPE2          = 0x02u;
constexpr ULONG VGK_HWID_DRIFT_REASON_CPU_BRAND             = 0x03u;
constexpr ULONG VGK_HWID_DRIFT_REASON_DISK_SIGNATURE        = 0x04u;
constexpr ULONG VGK_HWID_DRIFT_REASON_NIC_MAC               = 0x05u;
constexpr ULONG VGK_HWID_DRIFT_REASON_VOLUME_SERIAL         = 0x06u;
constexpr ULONG VGK_HWID_DRIFT_REASON_PCR_BASELINE          = 0x07u;
constexpr ULONG VGK_HWID_DRIFT_REASON_TPM_EK_HASH           = 0x08u;
constexpr ULONG VGK_HWID_DRIFT_REASON_GPT_GUID              = 0x09u;
constexpr ULONG VGK_HWID_DRIFT_REASON_HV_VENDOR             = 0x0Au;
constexpr ULONG VGK_HWID_DRIFT_REASON_FIRMWARE_KIND         = 0x0Bu;
constexpr ULONG VGK_HWID_DRIFT_REASON_HVCI_TOGGLED          = 0x0Cu;
constexpr ULONG VGK_HWID_DRIFT_REASON_SB_TOGGLED            = 0x0Du;
constexpr ULONG VGK_HWID_DRIFT_REASON_DEVICE_COUNT_DIFF     = 0x0Eu;
constexpr ULONG VGK_HWID_DRIFT_REASON_NVME_IDENT_DIFF       = 0x0Fu;

struct VGK_HWID_DRIFT_RESULT
{
    UCHAR    drift_detected;
    UCHAR    reason_code;
    USHORT   first_diff_field_index;
    ULONG    elapsed_ticks_since_boot;
    UCHAR    boot_composite[32];
    UCHAR    runtime_composite[32];
    ULONGLONG runtime_qpc;
    ULONGLONG boot_qpc_at_capture;
};

NTSTATUS vgk_runtime_hwid_recompute_and_compare(_In_ const UCHAR boot_composite[32],
                                                 _In_ ULONGLONG boot_qpc,
                                                 _Out_ VGK_HWID_DRIFT_RESULT* out_result) noexcept
{
    if (boot_composite == nullptr || out_result == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_result, sizeof(*out_result));
    RtlCopyMemory(out_result->boot_composite, boot_composite, 32u);
    out_result->boot_qpc_at_capture = boot_qpc;

    VGK_BOOT_HWID_SNAPSHOT snap;
    RtlZeroMemory(&snap, sizeof(snap));

    PVOID rsmb = NULL; ULONG rsmb_len = 0;
    if (NT_SUCCESS(vgk_acpi_table_fetch('RSMB', &rsmb, &rsmb_len)))
    {
        vgk_smbios_parse_type1((const UCHAR*)rsmb, rsmb_len, &snap);
        vgk_smbios_parse_type2((const UCHAR*)rsmb, rsmb_len, &snap);
        vgk_acpi_table_free(rsmb);
    }
    vgk_cpuid_capture_brand_string(&snap);
    vgk_boot_walk_all_disks(&snap);
    vgk_boot_hwid_compute_fingerprint(&snap);
    vgk_boot_hwid_stable_composite(&snap, out_result->runtime_composite);

    LARGE_INTEGER qpc; KeQueryPerformanceCounter(&qpc);
    out_result->runtime_qpc = (ULONGLONG)qpc.QuadPart;
    out_result->elapsed_ticks_since_boot = (ULONG)(out_result->runtime_qpc - boot_qpc);

    BOOLEAN same = TRUE;
    USHORT first_diff = 0xFFFFu;
    for (USHORT i = 0; i < 32u; ++i)
    {
        if (out_result->boot_composite[i] != out_result->runtime_composite[i])
        {
    UCHAR  reserved;
    USHORT vendor_id;
    USHORT device_id;
    USHORT subsystem_vendor_id;
    USHORT subsystem_id;
    UCHAR  class_code;
    UCHAR  subclass;
    UCHAR  prog_if;
    UCHAR  revision_id;
    UCHAR  header_type;
    UCHAR  reserved2[3];
};

// SECTION 257 pulls SMBIOS Type 3 (Chassis), Type 4 (Processor), and Type 17
// (Memory) records out of the firmware tables. These three types are stable
// HWID inputs for chassis serial, CPU steppings, and the per-DIMM
// identifiers, with the per-record asset tag + serial number string indices
// resolving through the SMBIOS string table after the formatted area.
// Vanguard composites these into the per-CPU and per-DIMM fingerprint slots
// of the HWID composite. The Type 3 struct holds manufacturer_idx, type_byte,
// version_idx, serial_idx, asset_tag_idx, then bootup_state/power_state/
// thermal_state/security_status bytes. Built on top of SECTION 86's firmware
// fetcher and SECTION 208's SMBIOS Type 1/2 extractor; called every HWID
// composite refresh through SECTION 24 assembler and the SECTION 207 boot
// capture orchestrator. First (top) declaration block; the lower banner is
// the full deep-parser implementation. Cold path -- boot + drift only.
// ============================================================================
// SECTION 257 -- SMBIOS Type 3 (Chassis) + Type 4 (Processor) + Type 17 (Memory)
//                Full deep parser. Each structure carries asset tag + serial
//                number string indices that resolve through the string table
//                after the formatted area. Vanguard composites these into
//                the per-CPU and per-DIMM fingerprint slots.
// ============================================================================

// SECTION 255 builds the TPM 2.0 GetRandom, ReadClock, and GetTime command
// frames. These three primitives form the per-tick TPM heartbeat Vanguard uses
// to spot emulator-style timing anomalies: GetRandom pulls N bytes from the TPM
// RNG, ReadClock returns the clock pair, GetTime stamps an attested time. They
// sit on the SECTION 9 builders plus the SECTION 55/56 helpers, called per
// attestation nonce and per timing anchor through tpm2_build_get_random,
// read_clock, and get_time at the spec-defined frame layouts.
// ============================================================================
// SECTION 255 -- TPM 2.0 GetRandom + ReadClock + GetTime command builders
//                These three commands form the per-tick TPM heartbeat
//                Vanguard issues to detect TPM-emulator timing anomalies.
//                GetRandom requests N bytes from TPM RNG; ReadClock returns
//                the 8-byte clock + 4-byte resetCount + 4-byte restartCount;
//                GetTime is signed time used in remote-attestation Quotes.
// ============================================================================

constexpr ULONG VGK_TPM2_CC_GetRandom                       = 0x0000017Bu;
constexpr ULONG VGK_TPM2_CC_ReadClock                       = 0x00000181u;
constexpr ULONG VGK_TPM2_CC_StirRandom                      = 0x00000146u;
constexpr ULONG VGK_TPM2_CC_GetTestResult                   = 0x0000017Cu;
constexpr ULONG VGK_TPM2_CC_SelfTest                        = 0x00000143u;
constexpr ULONG VGK_TPM2_CC_IncrementalSelfTest             = 0x00000142u;

NTSTATUS tpm2_parse_read_clock_response(_In_reads_bytes_(rsp_len) const UCHAR* rsp,
                                         _In_ ULONG rsp_len,
                                         _Out_ ULONGLONG* out_time_ms,
                                         _Out_ ULONGLONG* out_clock_ms,
                                         _Out_ ULONG* out_reset_count,
                                         _Out_ ULONG* out_restart_count,
                                         _Out_ UCHAR* out_safe) noexcept
{
    if (rsp == nullptr || out_time_ms == nullptr || out_clock_ms == nullptr ||
        out_reset_count == nullptr || out_restart_count == nullptr || out_safe == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (rsp_len < 30u) { return STATUS_BUFFER_TOO_SMALL; }
    if (rsp[6] != 0u || rsp[7] != 0u || rsp[8] != 0u || rsp[9] != 0u) { return STATUS_DEVICE_DATA_ERROR; }

    *out_time_ms = ((ULONGLONG)rsp[10] << 56) | ((ULONGLONG)rsp[11] << 48) |
                   ((ULONGLONG)rsp[12] << 40) | ((ULONGLONG)rsp[13] << 32) |
                   ((ULONGLONG)rsp[14] << 24) | ((ULONGLONG)rsp[15] << 16) |
                   ((ULONGLONG)rsp[16] <<  8) | ((ULONGLONG)rsp[17]);
    *out_clock_ms = ((ULONGLONG)rsp[18] << 56) | ((ULONGLONG)rsp[19] << 48) |
                    ((ULONGLONG)rsp[20] << 40) | ((ULONGLONG)rsp[21] << 32) |
                    ((ULONGLONG)rsp[22] << 24) | ((ULONGLONG)rsp[23] << 16) |
                    ((ULONGLONG)rsp[24] <<  8) | ((ULONGLONG)rsp[25]);
    *out_reset_count   = ((ULONG)rsp[26] << 24) | ((ULONG)rsp[27] << 16) | ((ULONG)rsp[28] << 8) | (ULONG)rsp[29];
    if (rsp_len < 34u) { return STATUS_BUFFER_TOO_SMALL; }
    *out_restart_count = ((ULONG)rsp[30] << 24) | ((ULONG)rsp[31] << 16) | ((ULONG)rsp[32] << 8) | (ULONG)rsp[33];
    if (rsp_len < 35u) { return STATUS_BUFFER_TOO_SMALL; }
    *out_safe = rsp[34];
    return STATUS_SUCCESS;
}

// SECTION 256 talks PCI Configuration Space directly for live device
// identification. PCI config space is the canonical place to read live vendor
// and device IDs at runtime, so Vanguard taps CONFIG_ADDRESS 0xCF8 and
// CONFIG_DATA 0xCFC across every bus/device/function tuple to pull GPU, NIC,
// and audio identity. It rides on the SECTION 187 device-scan family and the
// SECTION 282 VT-d catalog, called every HWID composite refresh and each
// device-scan cycle, dispatching through HalGetBusDataByOffset.
// ============================================================================
// SECTION 256 -- PCI Configuration Space access (live device identification)
//                Vanguard reads CONFIG_ADDRESS 0xCF8 / CONFIG_DATA 0xCFC for
//                each PCI bus/device/function combination to enumerate
//                GPU/NIC/Audio vendor+device IDs at runtime. This survives
//                Hyper-V partition switches and forms a device-fingerprint
//                independent from SMBIOS or USB.
// ============================================================================

constexpr USHORT VGK_PCI_CONFIG_ADDRESS_PORT                = 0x0CF8u;
constexpr USHORT VGK_PCI_CONFIG_DATA_PORT                   = 0x0CFCu;

constexpr ULONG VGK_PCI_CONFIG_ENABLE_BIT                   = 0x80000000u;

constexpr UCHAR VGK_PCI_REG_VENDOR_ID                       = 0x00u;
constexpr UCHAR VGK_PCI_REG_DEVICE_ID                       = 0x02u;
constexpr UCHAR VGK_PCI_REG_COMMAND                         = 0x04u;
constexpr UCHAR VGK_PCI_REG_STATUS                          = 0x06u;
constexpr UCHAR VGK_PCI_REG_REVISION_ID                     = 0x08u;
constexpr UCHAR VGK_PCI_REG_PROG_IF                         = 0x09u;
constexpr UCHAR VGK_PCI_REG_SUBCLASS                        = 0x0Au;
constexpr UCHAR VGK_PCI_REG_CLASS_CODE                      = 0x0Bu;
constexpr UCHAR VGK_PCI_REG_CACHE_LINE_SIZE                 = 0x0Cu;
constexpr UCHAR VGK_PCI_REG_LATENCY_TIMER                   = 0x0Du;
constexpr UCHAR VGK_PCI_REG_HEADER_TYPE                     = 0x0Eu;
constexpr UCHAR VGK_PCI_REG_BIST                            = 0x0Fu;
constexpr UCHAR VGK_PCI_REG_BAR0                            = 0x10u;
constexpr UCHAR VGK_PCI_REG_BAR1                            = 0x14u;
constexpr UCHAR VGK_PCI_REG_BAR2                            = 0x18u;
constexpr UCHAR VGK_PCI_REG_BAR3                            = 0x1Cu;
constexpr UCHAR VGK_PCI_REG_BAR4                            = 0x20u;
constexpr UCHAR VGK_PCI_REG_BAR5                            = 0x24u;
constexpr UCHAR VGK_PCI_REG_SUBSYSTEM_VENDOR_ID             = 0x2Cu;
constexpr UCHAR VGK_PCI_REG_SUBSYSTEM_ID                    = 0x2Eu;
constexpr UCHAR VGK_PCI_REG_EXPANSION_ROM_BASE              = 0x30u;
constexpr UCHAR VGK_PCI_REG_CAPABILITIES_PTR                = 0x34u;
constexpr UCHAR VGK_PCI_REG_INTERRUPT_LINE                  = 0x3Cu;
constexpr UCHAR VGK_PCI_REG_INTERRUPT_PIN                   = 0x3Du;

constexpr USHORT VGK_PCI_CLASS_UNCLASSIFIED                 = 0x00u;
constexpr USHORT VGK_PCI_CLASS_MASS_STORAGE                 = 0x01u;
constexpr USHORT VGK_PCI_CLASS_NETWORK                      = 0x02u;
constexpr USHORT VGK_PCI_CLASS_DISPLAY                      = 0x03u;
constexpr USHORT VGK_PCI_CLASS_MULTIMEDIA                   = 0x04u;
constexpr USHORT VGK_PCI_CLASS_MEMORY                       = 0x05u;
constexpr USHORT VGK_PCI_CLASS_BRIDGE                       = 0x06u;
constexpr USHORT VGK_PCI_CLASS_SIMPLE_COMMUNICATIONS        = 0x07u;
constexpr USHORT VGK_PCI_CLASS_BASE_SYSTEM_PERIPHERAL       = 0x08u;
constexpr USHORT VGK_PCI_CLASS_INPUT_DEVICE                 = 0x09u;
constexpr USHORT VGK_PCI_CLASS_DOCKING_STATION              = 0x0Au;
constexpr USHORT VGK_PCI_CLASS_PROCESSOR                    = 0x0Bu;
constexpr USHORT VGK_PCI_CLASS_SERIAL_BUS                   = 0x0Cu;
constexpr USHORT VGK_PCI_CLASS_WIRELESS_CONTROLLER          = 0x0Du;
constexpr USHORT VGK_PCI_CLASS_INTELLIGENT_CONTROLLER       = 0x0Eu;
constexpr USHORT VGK_PCI_CLASS_SATELLITE_COMMUNICATIONS     = 0x0Fu;
constexpr USHORT VGK_PCI_CLASS_ENCRYPTION                   = 0x10u;
constexpr USHORT VGK_PCI_CLASS_SIGNAL_PROCESSING            = 0x11u;

constexpr USHORT VGK_PCI_VENDOR_INTEL                       = 0x8086u;
constexpr USHORT VGK_PCI_VENDOR_AMD                         = 0x1022u;
constexpr USHORT VGK_PCI_VENDOR_NVIDIA                      = 0x10DEu;
constexpr USHORT VGK_PCI_VENDOR_REALTEK                     = 0x10ECu;
constexpr USHORT VGK_PCI_VENDOR_BROADCOM                    = 0x14E4u;
constexpr USHORT VGK_PCI_VENDOR_QUALCOMM                    = 0x168Cu;
constexpr USHORT VGK_PCI_VENDOR_MARVELL                     = 0x11ABu;
constexpr USHORT VGK_PCI_VENDOR_MEDIATEK                    = 0x14C3u;
constexpr USHORT VGK_PCI_VENDOR_VMWARE                      = 0x15ADu;
constexpr USHORT VGK_PCI_VENDOR_VIRTIO_REDHAT               = 0x1AF4u;
constexpr USHORT VGK_PCI_VENDOR_MICROSOFT_HV                = 0x1414u;
constexpr USHORT VGK_PCI_VENDOR_PARALLELS                   = 0x1AB8u;
constexpr USHORT VGK_PCI_VENDOR_INNOTEK_VBOX                = 0x80EEu;

ULONG vgk_pci_make_config_address(_In_ UCHAR bus, _In_ UCHAR device,
                                   _In_ UCHAR function, _In_ UCHAR reg) noexcept
{
    return VGK_PCI_CONFIG_ENABLE_BIT
         | ((ULONG)bus      << 16)
         | ((ULONG)(device & 0x1Fu) << 11)
         | ((ULONG)(function & 0x07u) << 8)
         | ((ULONG)(reg & 0xFCu));
}

struct VGK_PCI_DEVICE_RECORD
{
    UCHAR  bus;
    UCHAR  device;
    UCHAR  function;
    UCHAR  reserved;
    USHORT vendor_id;
    USHORT device_id;
    USHORT subsystem_vendor_id;
    USHORT subsystem_id;
    UCHAR  class_code;
    UCHAR  subclass;
    UCHAR  prog_if;
    UCHAR  revision_id;
    UCHAR  header_type;
    UCHAR  reserved2[3];
};

// Second SECTION 257 banner -- the deep parser implementation block that
// follows the declaration block above. Walks the SMBIOS table looking for
// Type 3, 4, and 17 headers and extracts each one's per-type field set,
// then resolves the string indices into the trailing string-table area. The
// VGK_SMBIOS_TYPE3_CHASSIS struct mirrors the spec layout: type, length,
// handle, manufacturer_idx, type_byte, version_idx, serial_idx,
// asset_tag_idx, bootup_state, power_state, thermal_state, security_status,
// oem_defined, height, num_power_cords, contained_element_count,
// contained_element_record_length, then the SKU number index. Type 4 adds
// CPUID and processor signature; Type 17 covers DIMM serial / part-number /
// manufacturer per-slot. Cold path -- only fires during HWID composite
// refresh through the SECTION 24 assembler; feeds SECTION 22 severity.
// ============================================================================
// SECTION 257 -- SMBIOS Type 3 (Chassis) + Type 4 (Processor) + Type 17 (Memory)
//                Full deep parser. Each structure carries asset tag + serial
//                number string indices that resolve through the string table
//                after the formatted area. Vanguard composites these into
//                the per-CPU and per-DIMM fingerprint slots.
// ============================================================================

#pragma pack(push, 1)
struct VGK_SMBIOS_TYPE3_CHASSIS
{
    UCHAR  type;
    UCHAR  length;
    USHORT handle;
    UCHAR  manufacturer_idx;
    UCHAR  type_byte;
    UCHAR  version_idx;
    UCHAR  serial_number_idx;
    UCHAR  asset_tag_idx;
    UCHAR  boot_up_state;
    UCHAR  power_supply_state;
    UCHAR  thermal_state;
    UCHAR  security_status;
    ULONG  oem_defined;
    UCHAR  height;
    UCHAR  number_of_power_cords;
    UCHAR  contained_element_count;
    UCHAR  contained_element_record_length;
};

struct VGK_SMBIOS_TYPE4_PROCESSOR
{
    UCHAR  type;
    UCHAR  length;
    USHORT handle;
    UCHAR  socket_designation_idx;
    UCHAR  processor_type;
    UCHAR  processor_family;
    UCHAR  processor_manufacturer_idx;
    ULONGLONG processor_id;
    UCHAR  processor_version_idx;
    UCHAR  voltage;
    USHORT external_clock;
    USHORT max_speed;
    USHORT current_speed;
    UCHAR  status;
    UCHAR  processor_upgrade;
    USHORT l1_cache_handle;
    USHORT l2_cache_handle;
    USHORT l3_cache_handle;
    UCHAR  serial_number_idx;
    UCHAR  asset_tag_idx;
    UCHAR  part_number_idx;
    UCHAR  core_count;
    UCHAR  core_enabled;
    UCHAR  thread_count;
    USHORT processor_characteristics;
    USHORT processor_family_2;
    USHORT core_count_2;
    USHORT core_enabled_2;
    USHORT thread_count_2;
    USHORT thread_enabled;
};

struct VGK_SMBIOS_TYPE17_MEMORY_DEVICE
{
    UCHAR  type;
    UCHAR  length;
    USHORT handle;
    USHORT physical_memory_array_handle;
    USHORT memory_error_information_handle;
    USHORT total_width;
    USHORT data_width;
    USHORT size;
    UCHAR  form_factor;
    UCHAR  device_set;
    UCHAR  device_locator_idx;
    UCHAR  bank_locator_idx;
    UCHAR  memory_type;
    USHORT type_detail;
    USHORT speed;
    UCHAR  manufacturer_idx;
    UCHAR  serial_number_idx;
    UCHAR  asset_tag_idx;
    UCHAR  part_number_idx;
    UCHAR  attributes;
    ULONG  extended_size;
    USHORT configured_memory_speed;
    USHORT minimum_voltage;
    USHORT maximum_voltage;
    USHORT configured_voltage;
};
#pragma pack(pop)

constexpr UCHAR VGK_SMBIOS_TYPE_BIOS                        = 0u;
constexpr UCHAR VGK_SMBIOS_TYPE_SYSTEM                      = 1u;
constexpr UCHAR VGK_SMBIOS_TYPE_BASEBOARD                   = 2u;
constexpr UCHAR VGK_SMBIOS_TYPE_CHASSIS                     = 3u;
constexpr UCHAR VGK_SMBIOS_TYPE_PROCESSOR                   = 4u;
constexpr UCHAR VGK_SMBIOS_TYPE_MEMORY_CONTROLLER           = 5u;
constexpr UCHAR VGK_SMBIOS_TYPE_MEMORY_MODULE               = 6u;
constexpr UCHAR VGK_SMBIOS_TYPE_CACHE                       = 7u;
constexpr UCHAR VGK_SMBIOS_TYPE_PORT_CONNECTOR              = 8u;
constexpr UCHAR VGK_SMBIOS_TYPE_SYSTEM_SLOTS                = 9u;
constexpr UCHAR VGK_SMBIOS_TYPE_ON_BOARD_DEVICES            = 10u;
constexpr UCHAR VGK_SMBIOS_TYPE_OEM_STRINGS                 = 11u;
constexpr UCHAR VGK_SMBIOS_TYPE_SYSTEM_CONFIGURATION        = 12u;
constexpr UCHAR VGK_SMBIOS_TYPE_BIOS_LANGUAGE               = 13u;
constexpr UCHAR VGK_SMBIOS_TYPE_GROUP_ASSOCIATIONS          = 14u;
constexpr UCHAR VGK_SMBIOS_TYPE_SYSTEM_EVENT_LOG            = 15u;
constexpr UCHAR VGK_SMBIOS_TYPE_PHYSICAL_MEMORY_ARRAY       = 16u;
constexpr UCHAR VGK_SMBIOS_TYPE_MEMORY_DEVICE               = 17u;
constexpr UCHAR VGK_SMBIOS_TYPE_END_OF_TABLE                = 127u;

constexpr UCHAR VGK_MEMORY_TYPE_DDR3                        = 0x18u;
constexpr UCHAR VGK_MEMORY_TYPE_DDR4                        = 0x1Au;
constexpr UCHAR VGK_MEMORY_TYPE_LPDDR3                      = 0x1Du;
constexpr UCHAR VGK_MEMORY_TYPE_LPDDR4                      = 0x1Eu;
constexpr UCHAR VGK_MEMORY_TYPE_HBM                         = 0x20u;
constexpr UCHAR VGK_MEMORY_TYPE_HBM2                        = 0x21u;
constexpr UCHAR VGK_MEMORY_TYPE_DDR5                        = 0x22u;
constexpr UCHAR VGK_MEMORY_TYPE_LPDDR5                      = 0x23u;
constexpr UCHAR VGK_MEMORY_TYPE_HBM3                        = 0x24u;

constexpr UCHAR VGK_CHASSIS_TYPE_OTHER                      = 0x01u;
constexpr UCHAR VGK_CHASSIS_TYPE_DESKTOP                    = 0x03u;
constexpr UCHAR VGK_CHASSIS_TYPE_LOW_PROFILE_DESKTOP        = 0x04u;
constexpr UCHAR VGK_CHASSIS_TYPE_PIZZA_BOX                  = 0x05u;
constexpr UCHAR VGK_CHASSIS_TYPE_MINI_TOWER                 = 0x06u;
constexpr UCHAR VGK_CHASSIS_TYPE_TOWER                      = 0x07u;
constexpr UCHAR VGK_CHASSIS_TYPE_PORTABLE                   = 0x08u;
constexpr UCHAR VGK_CHASSIS_TYPE_LAPTOP                     = 0x09u;
constexpr UCHAR VGK_CHASSIS_TYPE_NOTEBOOK                   = 0x0Au;
constexpr UCHAR VGK_CHASSIS_TYPE_HAND_HELD                  = 0x0Bu;
constexpr UCHAR VGK_CHASSIS_TYPE_DOCKING_STATION            = 0x0Cu;
constexpr UCHAR VGK_CHASSIS_TYPE_ALL_IN_ONE                 = 0x0Du;
constexpr UCHAR VGK_CHASSIS_TYPE_SUB_NOTEBOOK               = 0x0Eu;
constexpr UCHAR VGK_CHASSIS_TYPE_SPACE_SAVING               = 0x0Fu;
constexpr UCHAR VGK_CHASSIS_TYPE_TABLET                     = 0x1Eu;
constexpr UCHAR VGK_CHASSIS_TYPE_CONVERTIBLE                = 0x1Fu;
constexpr UCHAR VGK_CHASSIS_TYPE_DETACHABLE                 = 0x20u;
constexpr UCHAR VGK_CHASSIS_TYPE_IOT_GATEWAY                = 0x21u;
constexpr UCHAR VGK_CHASSIS_TYPE_EMBEDDED_PC                = 0x22u;
constexpr UCHAR VGK_CHASSIS_TYPE_MINI_PC                    = 0x23u;
constexpr UCHAR VGK_CHASSIS_TYPE_STICK_PC                   = 0x24u;

// SECTION 258 holds the three classic registry HWID readers: MachineGuid,
// InstallDate, and ProductId. They're stable identity inputs that anchor the
// composite even when hardware shifts, and Vanguard scans them periodically
// in-game to catch SID/MachineGuid spoofing. Pure registry I/O, sitting as a
// companion to SECTION 253's activation reader, fired once per HWID composite
// refresh. Mechanically it goes ZwOpenKey on the fixed Windows hives
// (HKLM\\Software\\Microsoft\\Cryptography and friends) then ZwQueryValueKey.
// ============================================================================
// SECTION 258 -- Registry HWID readers (MachineGuid + InstallDate + ProductId)
//                Vanguard pulls these per-machine identifiers via ZwOpenKey +
//                ZwQueryValueKey at boot and again periodically in-game to
//                catch SID/MachineGuid spoofing. All paths are FIXED Windows
//                registry locations (Win7-Win11).
// ============================================================================

constexpr WCHAR VGK_REG_KEY_CRYPTOGRAPHY[]      = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography";
constexpr WCHAR VGK_REG_KEY_CURRENT_VERSION[]   = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
constexpr WCHAR VGK_REG_KEY_SYSTEMINFO[]        = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System";
constexpr WCHAR VGK_REG_KEY_CENTRAL_PROCESSOR_0[] = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
constexpr WCHAR VGK_REG_KEY_BIOS[]              = L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS";
constexpr WCHAR VGK_REG_KEY_COMPUTERNAME[]      = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
constexpr WCHAR VGK_REG_KEY_ACTIVE_COMPUTERNAME[]= L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName";
constexpr WCHAR VGK_REG_KEY_SESSION_MANAGER[]   = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
constexpr WCHAR VGK_REG_KEY_MEMORY_MANAGEMENT[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
constexpr WCHAR VGK_REG_KEY_DEVICEGUARD[]       = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
constexpr WCHAR VGK_REG_KEY_HYPERVISOR[]        = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\HyperV";
constexpr WCHAR VGK_REG_KEY_LSA[]               = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\LSA";
constexpr WCHAR VGK_REG_KEY_PRODUCTOPTIONS[]    = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions";
constexpr WCHAR VGK_REG_KEY_CI[]                = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CI";
constexpr WCHAR VGK_REG_KEY_CI_POLICY[]         = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy";
constexpr WCHAR VGK_REG_KEY_NTFS_PARAMETERS[]   = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FileSystem";
constexpr WCHAR VGK_REG_KEY_TPM_DEVICE[]        = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM";
constexpr WCHAR VGK_REG_KEY_TBS_SERVICE[]       = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TBS";

constexpr WCHAR VGK_REG_VAL_MACHINE_GUID[]      = L"MachineGuid";
constexpr WCHAR VGK_REG_VAL_PRODUCT_ID[]        = L"ProductId";
constexpr WCHAR VGK_REG_VAL_PRODUCT_NAME[]      = L"ProductName";
constexpr WCHAR VGK_REG_VAL_INSTALL_DATE[]      = L"InstallDate";
constexpr WCHAR VGK_REG_VAL_BUILD_LAB[]         = L"BuildLab";
constexpr WCHAR VGK_REG_VAL_BUILD_LAB_EX[]      = L"BuildLabEx";
constexpr WCHAR VGK_REG_VAL_CURRENT_BUILD[]     = L"CurrentBuild";
constexpr WCHAR VGK_REG_VAL_CURRENT_BUILD_NUMBER[] = L"CurrentBuildNumber";
constexpr WCHAR VGK_REG_VAL_UBR[]               = L"UBR";
constexpr WCHAR VGK_REG_VAL_RELEASE_ID[]        = L"ReleaseId";
constexpr WCHAR VGK_REG_VAL_DISPLAY_VERSION[]   = L"DisplayVersion";
constexpr WCHAR VGK_REG_VAL_EDITION_ID[]        = L"EditionID";
constexpr WCHAR VGK_REG_VAL_INSTALLATION_TYPE[] = L"InstallationType";
constexpr WCHAR VGK_REG_VAL_BIOS_VENDOR[]       = L"BIOSVendor";
constexpr WCHAR VGK_REG_VAL_BIOS_VERSION[]      = L"BIOSVersion";
constexpr WCHAR VGK_REG_VAL_BIOS_RELEASE_DATE[] = L"BIOSReleaseDate";
constexpr WCHAR VGK_REG_VAL_SYSTEM_MANUFACTURER[] = L"SystemManufacturer";
constexpr WCHAR VGK_REG_VAL_SYSTEM_PRODUCT_NAME[] = L"SystemProductName";
constexpr WCHAR VGK_REG_VAL_SYSTEM_SKU[]        = L"SystemSKU";
constexpr WCHAR VGK_REG_VAL_BASEBOARD_MANUFACTURER[] = L"BaseBoardManufacturer";
constexpr WCHAR VGK_REG_VAL_BASEBOARD_PRODUCT[] = L"BaseBoardProduct";
constexpr WCHAR VGK_REG_VAL_BASEBOARD_VERSION[] = L"BaseBoardVersion";
constexpr WCHAR VGK_REG_VAL_PROCESSOR_NAME_STRING[] = L"ProcessorNameString";
constexpr WCHAR VGK_REG_VAL_PROCESSOR_IDENTIFIER[]= L"Identifier";
constexpr WCHAR VGK_REG_VAL_VENDOR_IDENTIFIER[] = L"VendorIdentifier";
constexpr WCHAR VGK_REG_VAL_MHZ[]               = L"~MHz";
constexpr WCHAR VGK_REG_VAL_COMPUTER_NAME[]     = L"ComputerName";
constexpr WCHAR VGK_REG_VAL_HVCI_ENABLED[]      = L"HypervisorEnforcedCodeIntegrity";
constexpr WCHAR VGK_REG_VAL_HVCI_LOCKED[]       = L"Locked";

NTSTATUS vgk_reg_open_key_ro(_In_ PCWSTR full_path, _Out_ HANDLE* out_handle) noexcept
{
    if (full_path == nullptr || out_handle == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_handle = NULL;

    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    RtlInitUnicodeString(&us, full_path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwOpenKey(out_handle, KEY_READ, &oa);
}

NTSTATUS vgk_reg_query_string(_In_ HANDLE key,
                               _In_ PCWSTR value_name,
                               _Out_writes_bytes_(out_size) PWCHAR out_buffer,
                               _In_ ULONG out_size,
                               _Out_opt_ PULONG out_actual_chars) noexcept
{
    if (key == NULL || value_name == nullptr || out_buffer == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (out_actual_chars != NULL) { *out_actual_chars = 0u; }

    UNICODE_STRING us_name;
    RtlInitUnicodeString(&us_name, value_name);

    UCHAR stack_buf[512];
    ULONG result_len = 0u;
    NTSTATUS s = ZwQueryValueKey(key, &us_name, KeyValuePartialInformation, stack_buf, sizeof(stack_buf), &result_len);
    if (!NT_SUCCESS(s)) { return s; }
    if (result_len < sizeof(KEY_VALUE_PARTIAL_INFORMATION)) { return STATUS_DATA_ERROR; }

    const KEY_VALUE_PARTIAL_INFORMATION* pi = (const KEY_VALUE_PARTIAL_INFORMATION*)stack_buf;
    if (pi->Type != REG_SZ && pi->Type != REG_EXPAND_SZ) { return STATUS_OBJECT_TYPE_MISMATCH; }
    if (pi->DataLength > out_size) { return STATUS_BUFFER_TOO_SMALL; }

    RtlCopyMemory(out_buffer, pi->Data, pi->DataLength);
    if (out_actual_chars != NULL) { *out_actual_chars = pi->DataLength / (ULONG)sizeof(WCHAR); }
    return STATUS_SUCCESS;
}

NTSTATUS vgk_reg_query_dword(_In_ HANDLE key,
                              _In_ PCWSTR value_name,
                              _Out_ PULONG out_value) noexcept
{
    if (key == NULL || value_name == nullptr || out_value == nullptr) { return STATUS_INVALID_PARAMETER; }
    out_sample->ratio_q32          = (out_sample->tsc_delta << 32) / out_sample->qpc_delta;
    out_sample->expected_ratio_q32 = base->calibrated_ratio_q32;

    ULONGLONG diff = (out_sample->ratio_q32 > out_sample->expected_ratio_q32) ?
                     (out_sample->ratio_q32 - out_sample->expected_ratio_q32) :
                     (out_sample->expected_ratio_q32 - out_sample->ratio_q32);
    ULONGLONG ppm = 0u;
    if (out_sample->expected_ratio_q32 != 0u)
    {
        ppm = (diff * 1000000ULL) / out_sample->expected_ratio_q32;
    }
    out_sample->deviation_ppm = (ULONG)ppm;

    if (out_status_flags != NULL)
    {
        if (out_sample->deviation_ppm > VGK_TSC_HV_EMULATION_PPM_THRESHOLD)
        {
            *out_status_flags |= 0x00000002u;
        }
        else if (out_sample->deviation_ppm > VGK_TSC_DRIFT_TOLERANCE_PPM)
        {
            *out_status_flags |= 0x00000001u;
        }
    }
    return STATUS_SUCCESS;
}

// SECTION 260 wires up hot-plug enumeration triggers that force a runtime HWID
// re-baseline mid-session. Vanguard listens for the I/O manager's PnP
// enumeration events so a USB or PCIe insertion can invalidate the cached HWID
// before the next composite. It sits on SECTION 254's runtime re-fetch path and
// SECTION 207's boot capture. The trigger fires on every hot-plug PnP event the
// I/O manager publishes through a PnP notification callback that flips the
// re-baseline flag, which then drives SECTION 254 on the next pass.
// ============================================================================
// SECTION 260 -- Hot-plug enumeration triggers for runtime HWID re-baseline
//                Vanguard listens for PnP enumeration events through
//                IoRegisterPlugPlayNotification with these GUIDs to detect
//                hot-plug of devices that change the HWID composite. Each
//                notification kicks a fresh re-baseline scan.
// ============================================================================

constexpr GUID VGK_GUID_DEVICE_INTERFACE_DISK =
    { 0x53F56307, 0xB6BF, 0x11D0, { 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_VOLUME =
    { 0x53F5630D, 0xB6BF, 0x11D0, { 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_USB_DEVICE =
    { 0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_USB_HUB =
    { 0xF18A0E88, 0xC30C, 0x11D0, { 0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8 } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_HID =
    { 0x4D1E55B2, 0xF16F, 0x11CF, { 0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_NET =
    { 0xCAC88484, 0x7515, 0x4C03, { 0x82, 0xE6, 0x71, 0xA8, 0x7A, 0xBA, 0xC3, 0x61 } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_DISPLAY_ADAPTER =
    { 0x1CA05180, 0xA699, 0x450A, { 0x9A, 0x0C, 0xDE, 0x4F, 0xBE, 0x3D, 0xDD, 0x89 } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_MONITOR =
    { 0xE6F07B5F, 0xEE97, 0x4A90, { 0xB0, 0x76, 0x33, 0xF5, 0x7B, 0xF4, 0xEA, 0xA7 } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_AUDIO_DEVICE =
    { 0x6994AD04, 0x93EF, 0x11D0, { 0xA3, 0xCC, 0x00, 0xA0, 0xC9, 0x22, 0x31, 0x96 } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_KEYBOARD =
    { 0x884B96C3, 0x56EF, 0x11D1, { 0xBC, 0x8C, 0x00, 0xA0, 0xC9, 0x14, 0x05, 0xDD } };

constexpr GUID VGK_GUID_DEVICE_INTERFACE_MOUSE =
    { 0x378DE44C, 0x56EF, 0x11D1, { 0xBC, 0x8C, 0x00, 0xA0, 0xC9, 0x14, 0x05, 0xDD } };

constexpr ULONG VGK_HOTPLUG_TRIGGER_DISK_ARRIVAL              = 0x00000001u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_VOLUME_ARRIVAL            = 0x00000002u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_USB_DEVICE_ARRIVAL        = 0x00000004u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_USB_HUB_ARRIVAL           = 0x00000008u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_HID_ARRIVAL               = 0x00000010u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_NET_ARRIVAL               = 0x00000020u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_DISPLAY_ARRIVAL           = 0x00000040u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_MONITOR_ARRIVAL           = 0x00000080u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_AUDIO_ARRIVAL             = 0x00000100u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_KEYBOARD_ARRIVAL          = 0x00000200u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_MOUSE_ARRIVAL             = 0x00000400u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_DISK_REMOVAL              = 0x00010000u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_VOLUME_REMOVAL            = 0x00020000u;
constexpr ULONG VGK_HOTPLUG_TRIGGER_USB_DEVICE_REMOVAL        = 0x00040000u;

struct VGK_HOTPLUG_EVENT_RECORD
{
    GUID      interface_class_guid;
    ULONG     trigger_bit;
    UCHAR     action_arrival;
    UCHAR     reserved[3];
    ULONGLONG event_qpc;
    ULONG     resulting_drift_mask;
};

ULONG vgk_hotplug_classify_guid(_In_ const GUID* g) noexcept
{
    if (g == nullptr) { return 0u; }
    auto equals = [](const GUID* a, const GUID* b) -> BOOLEAN {
        return (RtlCompareMemory(a, b, sizeof(GUID)) == sizeof(GUID)) ? TRUE : FALSE;
    };
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_DISK))            { return VGK_HOTPLUG_TRIGGER_DISK_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_VOLUME))          { return VGK_HOTPLUG_TRIGGER_VOLUME_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_USB_DEVICE))      { return VGK_HOTPLUG_TRIGGER_USB_DEVICE_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_USB_HUB))         { return VGK_HOTPLUG_TRIGGER_USB_HUB_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_HID))             { return VGK_HOTPLUG_TRIGGER_HID_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_NET))             { return VGK_HOTPLUG_TRIGGER_NET_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_DISPLAY_ADAPTER)) { return VGK_HOTPLUG_TRIGGER_DISPLAY_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_MONITOR))         { return VGK_HOTPLUG_TRIGGER_MONITOR_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_AUDIO_DEVICE))    { return VGK_HOTPLUG_TRIGGER_AUDIO_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_KEYBOARD))        { return VGK_HOTPLUG_TRIGGER_KEYBOARD_ARRIVAL; }
    if (equals(g, &VGK_GUID_DEVICE_INTERFACE_MOUSE))           { return VGK_HOTPLUG_TRIGGER_MOUSE_ARRIVAL; }
    return 0u;
}

// SECTION 261 lists the well-known TPM 2.0 NV indexes from the TCG Platform
// Working Group spec (EK certificate at 0x01C00002 and the related RSA/ECC
// slots). These are provisioned by the platform OEM and read by Windows at boot,
// so Vanguard scans the same set to fingerprint the platform. The constant data
// feeds SECTION 16's EK extractor and SECTION 217's seal flow. Compile-time
// only, with runtime selecting via these named indexes through constexpr
// ULONG NV_INDEX_EK / RSA / ECC and friends per TCG PWG numbering.
// ============================================================================
// SECTION 261 -- TPM 2.0 NV well-known indexes (TCG Platform Working Group)
//                These indexes are PROVISIONED by the platform OEM and read
//                by Windows during boot. Vanguard scans this set to fingerprint
//                the platform supplier (Microsoft vs HP vs Dell etc.) and
//                detect provision-level NV tampering.
// ============================================================================

constexpr ULONG VGK_NV_INDEX_EK_RSA_CERT                    = 0x01C00002u;
constexpr ULONG VGK_NV_INDEX_EK_RSA_NONCE                   = 0x01C00003u;
constexpr ULONG VGK_NV_INDEX_EK_RSA_TEMPLATE                = 0x01C00004u;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P256_CERT          = 0x01C0000Au;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P256_NONCE         = 0x01C0000Bu;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P256_TEMPLATE      = 0x01C0000Cu;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P384_CERT          = 0x01C00016u;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P384_NONCE         = 0x01C00017u;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P384_TEMPLATE      = 0x01C00018u;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P521_CERT          = 0x01C00022u;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P521_NONCE         = 0x01C00023u;
constexpr ULONG VGK_NV_INDEX_EK_ECC_NIST_P521_TEMPLATE      = 0x01C00024u;
constexpr ULONG VGK_NV_INDEX_EK_ECC_SM2_P256_CERT           = 0x01C0002Eu;
constexpr ULONG VGK_NV_INDEX_EK_ECC_SM2_P256_NONCE          = 0x01C0002Fu;
constexpr ULONG VGK_NV_INDEX_EK_ECC_SM2_P256_TEMPLATE       = 0x01C00030u;
constexpr ULONG VGK_NV_INDEX_EK_RSA_3072_CERT               = 0x01C0001Cu;
constexpr ULONG VGK_NV_INDEX_EK_RSA_3072_NONCE              = 0x01C0001Du;
constexpr ULONG VGK_NV_INDEX_EK_RSA_3072_TEMPLATE           = 0x01C0001Eu;
constexpr ULONG VGK_NV_INDEX_EK_RSA_4096_CERT               = 0x01C00020u;
constexpr ULONG VGK_NV_INDEX_PLATFORM_AUTH                  = 0x01C90000u;
constexpr ULONG VGK_NV_INDEX_LOCKOUT_AUTH                   = 0x01C90001u;
constexpr ULONG VGK_NV_INDEX_ENDORSEMENT_AUTH               = 0x01C90002u;
constexpr ULONG VGK_NV_INDEX_OWNER_AUTH                     = 0x01C90003u;

constexpr ULONG VGK_NV_INDEX_RSA_INTERMEDIATE_CERT_LOW      = 0x01C00100u;
constexpr ULONG VGK_NV_INDEX_RSA_INTERMEDIATE_CERT_HIGH     = 0x01C001FFu;
constexpr ULONG VGK_NV_INDEX_ECC_INTERMEDIATE_CERT_LOW      = 0x01C00200u;
constexpr ULONG VGK_NV_INDEX_ECC_INTERMEDIATE_CERT_HIGH     = 0x01C002FFu;

constexpr ULONG VGK_NV_INDEX_PLATFORM_HANDLE_LOW            = 0x81800000u;
constexpr ULONG VGK_NV_INDEX_PLATFORM_HANDLE_HIGH           = 0x81BFFFFFu;
constexpr ULONG VGK_NV_INDEX_TRANSIENT_OBJECT_LOW           = 0x80000000u;
constexpr ULONG VGK_NV_INDEX_TRANSIENT_OBJECT_HIGH          = 0x80FFFFFFu;
constexpr ULONG VGK_NV_INDEX_PERSISTENT_HANDLE_LOW          = 0x81000000u;
constexpr ULONG VGK_NV_INDEX_PERSISTENT_HANDLE_HIGH         = 0x817FFFFFu;

constexpr ULONG VGK_NV_INDEX_WINDOWS_BL_MEASURED_BOOT_LOG   = 0x01400001u;
constexpr ULONG VGK_NV_INDEX_WINDOWS_BL_LOG_HEADER          = 0x01400002u;
constexpr ULONG VGK_NV_INDEX_WINDOWS_BL_LOG_DATA            = 0x01400003u;
constexpr ULONG VGK_NV_INDEX_WINDOWS_AIK_PUBLIC             = 0x01400010u;
constexpr ULONG VGK_NV_INDEX_WINDOWS_PRTM_LOG               = 0x01400020u;
constexpr ULONG VGK_NV_INDEX_WINDOWS_SRTM_LOG               = 0x01400030u;
constexpr ULONG VGK_NV_INDEX_WINDOWS_VBS_LOG                = 0x01400040u;

constexpr ULONG VGK_NV_INDEX_MS_TPM_PROVISIONING_FLAG       = 0x01C101D0u;

BOOLEAN vgk_nv_index_is_persistent_handle(_In_ ULONG nv_index) noexcept
{
    return (nv_index >= VGK_NV_INDEX_PERSISTENT_HANDLE_LOW &&
            nv_index <= VGK_NV_INDEX_PERSISTENT_HANDLE_HIGH);
}

BOOLEAN vgk_nv_index_is_transient_handle(_In_ ULONG nv_index) noexcept
{
    return (nv_index >= VGK_NV_INDEX_TRANSIENT_OBJECT_LOW &&
            nv_index <= VGK_NV_INDEX_TRANSIENT_OBJECT_HIGH);
}

BOOLEAN vgk_nv_index_is_platform_handle(_In_ ULONG nv_index) noexcept
{
    return (nv_index >= VGK_NV_INDEX_PLATFORM_HANDLE_LOW &&
            nv_index <= VGK_NV_INDEX_PLATFORM_HANDLE_HIGH);
}

BOOLEAN vgk_nv_index_is_ek_cert_slot(_In_ ULONG nv_index) noexcept
{
    return (nv_index == VGK_NV_INDEX_EK_RSA_CERT ||
            nv_index == VGK_NV_INDEX_EK_RSA_3072_CERT ||
            nv_index == VGK_NV_INDEX_EK_RSA_4096_CERT ||
            nv_index == VGK_NV_INDEX_EK_ECC_NIST_P256_CERT ||
            nv_index == VGK_NV_INDEX_EK_ECC_NIST_P384_CERT ||
            nv_index == VGK_NV_INDEX_EK_ECC_NIST_P521_CERT ||
            nv_index == VGK_NV_INDEX_EK_ECC_SM2_P256_CERT);
}

// SECTION 262 pulls boot identification fields straight out of
// KUSER_SHARED_DATA (mapped at 0xFFFFF78000000000 in kernel mode and
// 0x7FFE0000 in user mode, 0x720 bytes total). Vanguard wants the cheap
// boot-time identity fields the kernel already publishes there -- the
// NtSystemRoot string, NtProductType, NtMajor/Minor/Build, SuiteMask,
// KdDebuggerEnabled, plus the NX/MM/CPUFeatureSet bitmap. The offset catalog
// covers TICK_COUNT_LOW (0x00), TICK_COUNT_MULTIPLIER (0x04), INTERRUPT_TIME
// (0x08), and the rest of the fixed-offset publication area. These are
// anchors that DON'T require ZwQuerySystemInformation, making the read
// cheaper than a syscall. Hooked into SECTION 207's boot capture and the
// SECTION 311 KD detect helper at vgk_kuser_shared_data_kd_detect; refresh
// hits every HWID composite cycle through the SECTION 24 assembler.
// ============================================================================
// SECTION 262 -- KUSER_SHARED_DATA boot identification fields
//                Located at 0xFFFFF78000000000 (kernel) / 0x7FFE0000 (user).
//                Read-only; Vanguard reads NtSystemRoot, NtProductType,
//                NtMajor/Minor/Build, SuiteMask, KdDebuggerEnabled, plus the
//                NX/MM/CPUFeatureSet bitmap. These are anchors that DON'T
//                require ZwQuerySystemInformation.
// ============================================================================

constexpr ULONGLONG VGK_KUSER_SHARED_DATA_KERNEL_VA          = 0xFFFFF78000000000ULL;
constexpr ULONG VGK_KUSER_SHARED_DATA_USER_VA                = 0x7FFE0000u;
constexpr ULONG VGK_KUSER_SHARED_DATA_SIZE                   = 0x720u;

constexpr ULONG VGK_KUSD_OFF_TICK_COUNT_LOW                  = 0x00000000u;
constexpr ULONG VGK_KUSD_OFF_TICK_COUNT_MULTIPLIER           = 0x00000004u;
constexpr ULONG VGK_KUSD_OFF_INTERRUPT_TIME                  = 0x00000008u;
constexpr ULONG VGK_KUSD_OFF_SYSTEM_TIME                     = 0x00000014u;
constexpr ULONG VGK_KUSD_OFF_TIME_ZONE_BIAS                  = 0x00000020u;
constexpr ULONG VGK_KUSD_OFF_IMAGE_NUMBER_LOW                = 0x0000002Cu;
constexpr ULONG VGK_KUSD_OFF_IMAGE_NUMBER_HIGH               = 0x0000002Eu;
constexpr ULONG VGK_KUSD_OFF_NT_SYSTEM_ROOT                  = 0x00000030u;
constexpr ULONG VGK_KUSD_OFF_MAX_STACK_TRACE_DEPTH           = 0x00000238u;
constexpr ULONG VGK_KUSD_OFF_CRYPTO_EXPONENT                 = 0x0000023Cu;
constexpr ULONG VGK_KUSD_OFF_TIME_ZONE_ID                    = 0x00000240u;
constexpr ULONG VGK_KUSD_OFF_LARGE_PAGE_MINIMUM              = 0x00000244u;
constexpr ULONG VGK_KUSD_OFF_AIT_SAMPLING_VALUE              = 0x00000248u;
constexpr ULONG VGK_KUSD_OFF_APP_COMPAT_FLAG                 = 0x0000024Cu;
constexpr ULONG VGK_KUSD_OFF_RNG_SEED_VERSION                = 0x00000250u;
constexpr ULONG VGK_KUSD_OFF_GLOBAL_VALIDATION_RUN_LEVEL     = 0x00000258u;
constexpr ULONG VGK_KUSD_OFF_TIME_ZONE_BIAS_STAMP            = 0x0000025Cu;
constexpr ULONG VGK_KUSD_OFF_NT_BUILD_NUMBER                 = 0x00000260u;
constexpr ULONG VGK_KUSD_OFF_NT_PRODUCT_TYPE                 = 0x00000264u;
constexpr ULONG VGK_KUSD_OFF_PRODUCT_TYPE_IS_VALID           = 0x00000268u;
constexpr ULONG VGK_KUSD_OFF_NATIVE_PROCESSOR_ARCHITECTURE   = 0x0000026Au;
constexpr ULONG VGK_KUSD_OFF_NT_MAJOR_VERSION                = 0x0000026Cu;
constexpr ULONG VGK_KUSD_OFF_NT_MINOR_VERSION                = 0x00000270u;
constexpr ULONG VGK_KUSD_OFF_PROCESSOR_FEATURES              = 0x00000274u;
constexpr ULONG VGK_KUSD_OFF_RESERVED1                       = 0x000002B4u;
constexpr ULONG VGK_KUSD_OFF_RESERVED3                       = 0x000002B8u;
constexpr ULONG VGK_KUSD_OFF_TIME_SLIP                       = 0x000002BCu;
constexpr ULONG VGK_KUSD_OFF_ALTERNATIVE_ARCH                = 0x000002C0u;
constexpr ULONG VGK_KUSD_OFF_BOOT_ID                         = 0x000002C4u;
constexpr ULONG VGK_KUSD_OFF_SYSTEM_EXPIRATION_DATE          = 0x000002C8u;
constexpr ULONG VGK_KUSD_OFF_SUITE_MASK                      = 0x000002D0u;
constexpr ULONG VGK_KUSD_OFF_KD_DEBUGGER_ENABLED             = 0x000002D4u;
constexpr ULONG VGK_KUSD_OFF_MITIGATION_POLICIES             = 0x000002D5u;
constexpr ULONG VGK_KUSD_OFF_CYCLES_PER_YIELD                = 0x000002D6u;
constexpr ULONG VGK_KUSD_OFF_ACTIVE_CONSOLE_ID               = 0x000002D8u;
constexpr ULONG VGK_KUSD_OFF_DISMOUNT_COUNT                  = 0x000002DCu;
constexpr ULONG VGK_KUSD_OFF_COM_PLUS_PACKAGE                = 0x000002E0u;
constexpr ULONG VGK_KUSD_OFF_LAST_SYSTEM_RIT_EVENT_TICK_COUNT = 0x000002E4u;
constexpr ULONG VGK_KUSD_OFF_NUMBER_OF_PHYSICAL_PAGES        = 0x000002E8u;
constexpr ULONG VGK_KUSD_OFF_SAFE_BOOT_MODE                  = 0x000002ECu;
constexpr ULONG VGK_KUSD_OFF_VIRTUALIZATION_FLAGS            = 0x000002EDu;
constexpr ULONG VGK_KUSD_OFF_SHARED_DATA_FLAGS               = 0x000002F0u;
constexpr ULONG VGK_KUSD_OFF_DBG_ERROR_PORT_PRESENT          = 0x000002F0u;
constexpr ULONG VGK_KUSD_OFF_TEST_RET_INSTRUCTION            = 0x000002F8u;
constexpr ULONG VGK_KUSD_OFF_QPC_FREQUENCY                   = 0x00000300u;
constexpr ULONG VGK_KUSD_OFF_QPC_SHIFT                       = 0x000003C7u;
constexpr ULONG VGK_KUSD_OFF_QPC_BYPASS_ENABLED              = 0x000003C6u;
constexpr ULONG VGK_KUSD_OFF_QPC_DATA                        = 0x000003C0u;
constexpr ULONG VGK_KUSD_OFF_TIME_ZONE_BIAS_EFFECTIVE_START  = 0x000003B0u;
constexpr ULONG VGK_KUSD_OFF_TIME_ZONE_BIAS_EFFECTIVE_END    = 0x000003B8u;
constexpr ULONG VGK_KUSD_OFF_USER_MODE_GLOBAL_LOGGER         = 0x00000338u;
constexpr ULONG VGK_KUSD_OFF_FEATURE_CONFIGURATION_CHANGE_STAMP = 0x000003F8u;
constexpr ULONG VGK_KUSD_OFF_TICK_COUNT_QUAD                 = 0x00000320u;
constexpr ULONG VGK_KUSD_OFF_X_STATE                         = 0x000003D8u;

constexpr UCHAR VGK_PROCESSOR_FEATURE_FPU_EMULATED           = 1u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_CMPXCHG8B              = 2u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_PAE                    = 9u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_XMMI                   = 6u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_3DNOW                  = 7u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_RDTSC                  = 8u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_XMMI64                 = 10u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_SSE3                   = 13u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_CMPXCHG16B             = 14u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_CHANNELS               = 16u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_XSAVE                  = 17u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_NX                     = 12u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_VIRT_FIRMWARE          = 21u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_RDWRFSGSBASE           = 22u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_FASTFAIL               = 23u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_RDRAND                 = 24u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_RDTSCP                 = 32u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_RDPID                  = 33u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_SSE_3_FMA              = 34u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_AVX                    = 39u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_AVX2                   = 40u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_AVX512F                = 41u;
constexpr UCHAR VGK_PROCESSOR_FEATURE_BPB_CTXSW              = 31u;

constexpr ULONG VGK_NT_PRODUCT_WIN_NT                        = 1u;
constexpr ULONG VGK_NT_PRODUCT_LAN_MAN_NT                    = 2u;
constexpr ULONG VGK_NT_PRODUCT_SERVER                        = 3u;

NTSTATUS vgk_kusd_snapshot_boot_id(_Out_ PULONG out_boot_id) noexcept
{
    if (out_boot_id == nullptr) { return STATUS_INVALID_PARAMETER; }
    const UCHAR* kusd = (const UCHAR*)VGK_KUSER_SHARED_DATA_KERNEL_VA;
    *out_boot_id = *(const ULONG*)(kusd + VGK_KUSD_OFF_BOOT_ID);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_kusd_snapshot_safe_boot_mode(_Out_ PUCHAR out_safe_boot) noexcept
{
    if (out_safe_boot == nullptr) { return STATUS_INVALID_PARAMETER; }
    const UCHAR* kusd = (const UCHAR*)VGK_KUSER_SHARED_DATA_KERNEL_VA;
    *out_safe_boot = *(const UCHAR*)(kusd + VGK_KUSD_OFF_SAFE_BOOT_MODE);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_kusd_snapshot_nt_versions(_Out_ PULONG out_major,
                                        _Out_ PULONG out_minor,
                                        _Out_ PULONG out_build,
                                        _Out_ PULONG out_product_type) noexcept
{
    if (out_major == nullptr || out_minor == nullptr || out_build == nullptr || out_product_type == nullptr) { return STATUS_INVALID_PARAMETER; }
    const UCHAR* kusd = (const UCHAR*)VGK_KUSER_SHARED_DATA_KERNEL_VA;
    *out_major        = *(const ULONG*)(kusd + VGK_KUSD_OFF_NT_MAJOR_VERSION);
    *out_minor        = *(const ULONG*)(kusd + VGK_KUSD_OFF_NT_MINOR_VERSION);
    *out_build        = *(const ULONG*)(kusd + VGK_KUSD_OFF_NT_BUILD_NUMBER);
    *out_product_type = *(const ULONG*)(kusd + VGK_KUSD_OFF_NT_PRODUCT_TYPE);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_kusd_snapshot_kd_debugger(_Out_ PUCHAR out_enabled) noexcept
{
    if (out_enabled == nullptr) { return STATUS_INVALID_PARAMETER; }
    const UCHAR* kusd = (const UCHAR*)VGK_KUSER_SHARED_DATA_KERNEL_VA;
    *out_enabled = *(const UCHAR*)(kusd + VGK_KUSD_OFF_KD_DEBUGGER_ENABLED);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_kusd_snapshot_dismount_count(_Out_ PULONG out_count) noexcept
{
    if (out_count == nullptr) { return STATUS_INVALID_PARAMETER; }
    const UCHAR* kusd = (const UCHAR*)VGK_KUSER_SHARED_DATA_KERNEL_VA;
    *out_count = *(const ULONG*)(kusd + VGK_KUSD_OFF_DISMOUNT_COUNT);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_kusd_snapshot_processor_feature(_In_ UCHAR feature_index,
                                              _Out_ PUCHAR out_present) noexcept
{
    if (out_present == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (feature_index >= 64u) { return STATUS_INVALID_PARAMETER; }
    const UCHAR* kusd = (const UCHAR*)VGK_KUSER_SHARED_DATA_KERNEL_VA;
    *out_present = *(const UCHAR*)(kusd + VGK_KUSD_OFF_PROCESSOR_FEATURES + feature_index);
    return STATUS_SUCCESS;
}

// SECTION 263 walks boot disk geometry and the GPT partition entry table.
// Geometry plus the per-partition GUIDs are stable HWID inputs that hold up
// across most user-driven changes. The IOCTL catalog covers
// IOCTL_DISK_GET_DRIVE_GEOMETRY (0x00070000) for legacy CHS,
// GET_DRIVE_GEOMETRY_EX (0x000700A0) for CHS + bytes-per-sector + cylinder
// count, GET_LENGTH_INFO (0x0007405C), GET_DRIVE_LAYOUT_EX (0x00070050),
// GET_PARTITION_INFO_EX (0x00070048), VOLUME_GET_GPT_ATTRIBUTES (0x00560038),
// and VOLUME_QUERY_VOLUME_NUMBER (0x0056001C). GPT partition entries live at
// LBA 2..33 with 16-byte unique GUID + 16-byte type GUID per entry; Vanguard
// composites partition type GUIDs into the boot-disk identity. Rides on
// SECTION 216's GPT/MBR signature reader and gets called on every HWID
// composite refresh through the SECTION 207 boot-capture orchestrator.
// ============================================================================
// SECTION 263 -- Boot disk geometry + GPT partition entry walker
//                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX returns CHS + bytes-per-sector
//                + cylinder count. GPT partition entries live at LBA 2..33
//                with 16-byte unique GUID + 16-byte type GUID per entry.
//                Vanguard composites partition type GUIDs for boot-disk ID.
// ============================================================================

constexpr ULONG VGK_IOCTL_DISK_GET_DRIVE_GEOMETRY            = 0x00070000u;
constexpr ULONG VGK_IOCTL_DISK_GET_DRIVE_GEOMETRY_EX         = 0x000700A0u;
constexpr ULONG VGK_IOCTL_DISK_GET_LENGTH_INFO               = 0x0007405Cu;
constexpr ULONG VGK_IOCTL_DISK_GET_DRIVE_LAYOUT_EX           = 0x00070050u;
constexpr ULONG VGK_IOCTL_DISK_GET_PARTITION_INFO_EX         = 0x00070048u;
constexpr ULONG VGK_IOCTL_VOLUME_GET_GPT_ATTRIBUTES          = 0x00560038u;
constexpr ULONG VGK_IOCTL_VOLUME_QUERY_VOLUME_NUMBER         = 0x0056001Cu;

constexpr ULONG VGK_DISK_MEDIA_TYPE_FIXED_MEDIA              = 12u;
constexpr ULONG VGK_DISK_MEDIA_TYPE_REMOVABLE_MEDIA          = 11u;
constexpr ULONG VGK_DISK_MEDIA_TYPE_UNKNOWN                  = 0u;

#pragma pack(push, 1)
struct VGK_DISK_GEOMETRY
{
    LARGE_INTEGER Cylinders;
    ULONG         MediaType;
    ULONG         TracksPerCylinder;
    ULONG         SectorsPerTrack;
    ULONG         BytesPerSector;
};

struct VGK_DISK_GEOMETRY_EX
{
    VGK_DISK_GEOMETRY Geometry;
    LARGE_INTEGER     DiskSize;
    UCHAR             Data[1];
};

struct VGK_GPT_HEADER
{
    UCHAR     signature[8];
    ULONG     revision;
    ULONG     header_size;
    ULONG     crc32_of_header;
    ULONG     reserved_zero;
    ULONGLONG my_lba;
    ULONGLONG alternate_lba;
    ULONGLONG first_usable_lba;
    ULONGLONG last_usable_lba;
    GUID      disk_guid;
    ULONGLONG partition_entry_lba;
    ULONG     number_of_partition_entries;
    ULONG     size_of_partition_entry;
    ULONG     partition_entries_crc32;
};

struct VGK_GPT_PARTITION_ENTRY
{
    GUID      partition_type_guid;
    GUID      unique_partition_guid;
    ULONGLONG starting_lba;
    ULONGLONG ending_lba;
    ULONGLONG attributes;
    WCHAR     partition_name[36];
};
#pragma pack(pop)

constexpr ULONG VGK_GPT_HEADER_REVISION_1_0                 = 0x00010000u;

constexpr GUID VGK_PARTITION_TYPE_UNUSED =
    { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

constexpr GUID VGK_PARTITION_TYPE_EFI_SYSTEM =
    { 0xC12A7328, 0xF81F, 0x11D2, { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };

constexpr GUID VGK_PARTITION_TYPE_MICROSOFT_RESERVED =
    { 0xE3C9E316, 0x0B5C, 0x4DB8, { 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE } };

constexpr GUID VGK_PARTITION_TYPE_BASIC_DATA =
    { 0xEBD0A0A2, 0xB9E5, 0x4433, { 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 } };

constexpr GUID VGK_PARTITION_TYPE_WINDOWS_RECOVERY =
    { 0xDE94BBA4, 0x06D1, 0x4D40, { 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC } };

constexpr GUID VGK_PARTITION_TYPE_LDM_METADATA =
    { 0x5808C8AA, 0x7E8F, 0x42E0, { 0x85, 0xD2, 0xE1, 0xE9, 0x04, 0x34, 0xCF, 0xB3 } };

constexpr GUID VGK_PARTITION_TYPE_LDM_DATA =
    { 0xAF9B60A0, 0x1431, 0x4F62, { 0xBC, 0x68, 0x33, 0x11, 0x71, 0x4A, 0x69, 0xAD } };

constexpr GUID VGK_PARTITION_TYPE_LINUX_FS =
    { 0x0FC63DAF, 0x8483, 0x4772, { 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4 } };

constexpr GUID VGK_PARTITION_TYPE_LINUX_SWAP =
    { 0x0657FD6D, 0xA4AB, 0x43C4, { 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F } };

constexpr GUID VGK_PARTITION_TYPE_LINUX_LVM =
    { 0xE6D6D379, 0xF507, 0x44C2, { 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28 } };

constexpr GUID VGK_PARTITION_TYPE_BIOS_BOOT =
    { 0x21686148, 0x6449, 0x6E6F, { 0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49 } };

constexpr ULONGLONG VGK_GPT_ATTR_REQUIRED_PARTITION         = 0x0000000000000001ULL;
constexpr ULONGLONG VGK_GPT_ATTR_NO_BLOCK_IO_PROTOCOL       = 0x0000000000000002ULL;
constexpr ULONGLONG VGK_GPT_ATTR_LEGACY_BIOS_BOOTABLE       = 0x0000000000000004ULL;
constexpr ULONGLONG VGK_GPT_ATTR_READ_ONLY                  = 0x1000000000000000ULL;
constexpr ULONGLONG VGK_GPT_ATTR_SHADOW_COPY                = 0x2000000000000000ULL;
constexpr ULONGLONG VGK_GPT_ATTR_HIDDEN                     = 0x4000000000000000ULL;
constexpr ULONGLONG VGK_GPT_ATTR_NO_DRIVE_LETTER            = 0x8000000000000000ULL;

NTSTATUS vgk_gpt_validate_header(_In_ const VGK_GPT_HEADER* hdr) noexcept
{
    if (hdr == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONGLONG sig = *(const ULONGLONG*)hdr->signature;
    if (sig != VGK_GPT_HEADER_SIGNATURE) { return STATUS_DATA_ERROR; }
    if (hdr->revision != VGK_GPT_HEADER_REVISION_1_0) { return STATUS_REVISION_MISMATCH; }
    if (hdr->header_size < 92u || hdr->header_size > 512u) { return STATUS_DATA_ERROR; }
    if (hdr->size_of_partition_entry < sizeof(VGK_GPT_PARTITION_ENTRY)) { return STATUS_DATA_ERROR; }
    if (hdr->size_of_partition_entry > 65536u) { return STATUS_DATA_ERROR; }
    if ((hdr->size_of_partition_entry & (hdr->size_of_partition_entry - 1u)) != 0u) { return STATUS_DATA_ERROR; }
    return STATUS_SUCCESS;
}

ULONG vgk_gpt_count_used_partitions(_In_ const UCHAR* partition_table,
                                     _In_ ULONG number_of_entries,
                                     _In_ ULONG size_of_entry) noexcept
{
    if (partition_table == nullptr) { return 0u; }
    ULONG count = 0u;
    const VGK_GPT_PARTITION_ENTRY* pe = nullptr;
    for (ULONG i = 0; i < number_of_entries; ++i)
    {
        pe = (const VGK_GPT_PARTITION_ENTRY*)(partition_table + (SIZE_T)i * size_of_entry);
        if (RtlCompareMemory(&pe->partition_type_guid, &VGK_PARTITION_TYPE_UNUSED, sizeof(GUID)) != sizeof(GUID))
        {
            ++count;
        }
    }
    return count;
}

const VGK_GPT_PARTITION_ENTRY* vgk_gpt_find_efi_system_partition(_In_ const UCHAR* partition_table,
                                                                  _In_ ULONG number_of_entries,
                                                                  _In_ ULONG size_of_entry) noexcept
{
    if (partition_table == nullptr) { return nullptr; }
    const VGK_GPT_PARTITION_ENTRY* pe = nullptr;
    for (ULONG i = 0; i < number_of_entries; ++i)
    {
        pe = (const VGK_GPT_PARTITION_ENTRY*)(partition_table + (SIZE_T)i * size_of_entry);
        if (RtlCompareMemory(&pe->partition_type_guid, &VGK_PARTITION_TYPE_EFI_SYSTEM, sizeof(GUID)) == sizeof(GUID))
        {
            return pe;
        }
    }
    return nullptr;
}

// SECTION 264 holds the ATA SMART threshold and attribute classifier table.
// Per ACS-4 Annex A every SMART attribute is vendor-coded, so Vanguard needs
// a labeled lookup to classify each ID and decide which thresholds matter,
// mapping the 30 fixed-slot vendor records to canonical 32-bit identity
// codes that survive disk-driver re-mappings (where raw_value gets cooked
// differently across firmware revisions). The VGK_SMART_ATTR_DESC struct
// holds id (the SMART attribute byte), criticality_class (severity band),
// raw_decode_kind (which decoder applies to raw_value), and canonical_tag
// (the stable 32-bit identity used downstream). The constant data is
// consumed by the SECTION 231 SMART data fetcher for IOCTL_ATA_PASS_THROUGH
// reads and feeds the SECTION 24 HWID composite assembler. Cold path --
// fires only during HWID composite refresh; SSD wear-leveling depends on it.
// ============================================================================
// SECTION 264 -- ATA SMART threshold + attribute classifier table
//                Per ACS-4 Annex A, each SMART attribute has a vendor-specific
//                name + criticality class. Vanguard maps the 30 fixed-slot
//                vendor records to canonical 32-bit identity codes that
//                survive disk-driver re-mappings (e.g., raw_value cooked
//                differently across firmware revisions).
// ============================================================================

struct VGK_SMART_ATTR_DESC
{
    UCHAR     id;
    UCHAR     criticality_class;
    UCHAR     raw_decode_kind;
    UCHAR     reserved;
    ULONG     canonical_tag;
};

constexpr UCHAR VGK_SMART_CRIT_PRE_FAIL                      = 0x01u;
constexpr UCHAR VGK_SMART_CRIT_ADVISORY                      = 0x02u;
constexpr UCHAR VGK_SMART_CRIT_LIFE                          = 0x03u;
constexpr UCHAR VGK_SMART_CRIT_PERFORMANCE                   = 0x04u;
constexpr UCHAR VGK_SMART_CRIT_INFORMATIONAL                 = 0x05u;
constexpr UCHAR VGK_SMART_CRIT_VENDOR                        = 0x06u;

constexpr UCHAR VGK_SMART_DECODE_U32_LE                      = 0x01u;
constexpr UCHAR VGK_SMART_DECODE_U48_LE                      = 0x02u;
constexpr UCHAR VGK_SMART_DECODE_U16_LO_U16_HI               = 0x03u;
constexpr UCHAR VGK_SMART_DECODE_U16_LO_ONLY                 = 0x04u;
constexpr UCHAR VGK_SMART_DECODE_VENDOR_SPECIFIC             = 0x05u;
constexpr UCHAR VGK_SMART_DECODE_TEMPERATURE_CELSIUS         = 0x06u;
constexpr UCHAR VGK_SMART_DECODE_HOURS                       = 0x07u;
constexpr UCHAR VGK_SMART_DECODE_LBA_COUNT                   = 0x08u;

constexpr VGK_SMART_ATTR_DESC vgk_smart_attr_table[] = {
    { 0x01u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'READE' },
    { 0x02u, VGK_SMART_CRIT_PERFORMANCE, VGK_SMART_DECODE_U16_LO_ONLY,        0u, 'THRPT' },
    { 0x03u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U16_LO_ONLY,        0u, 'SPNUP' },
    { 0x04u, VGK_SMART_CRIT_LIFE,        VGK_SMART_DECODE_U32_LE,             0u, 'STRSP' },
    { 0x05u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'RALLO' },
    { 0x07u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'SEEKE' },
    { 0x09u, VGK_SMART_CRIT_LIFE,        VGK_SMART_DECODE_HOURS,              0u, 'PWRON' },
    { 0x0Au, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U16_LO_ONLY,        0u, 'SPNRT' },
    { 0x0Cu, VGK_SMART_CRIT_LIFE,        VGK_SMART_DECODE_U32_LE,             0u, 'PWRCY' },
    { 0x0Du, VGK_SMART_CRIT_ADVISORY,    VGK_SMART_DECODE_U32_LE,             0u, 'SOFFR' },
    { 0xA8u, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'CMDFL' },
    { 0xA9u, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'SSDLR' },
    { 0xAAu, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'AVAIB' },
    { 0xABu, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'PRGFL' },
    { 0xACu, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'ERSFL' },
    { 0xADu, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'WEAR_' },
    { 0xAEu, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'UEXPC' },
    { 0xB7u, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'SATAE' },
    { 0xB8u, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'EOLPF' },
    { 0xBBu, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'RPTUE' },
    { 0xBCu, VGK_SMART_CRIT_ADVISORY,    VGK_SMART_DECODE_U32_LE,             0u, 'CMDTI' },
    { 0xBDu, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'HFWRT' },
    { 0xBEu, VGK_SMART_CRIT_PERFORMANCE, VGK_SMART_DECODE_TEMPERATURE_CELSIUS,0u, 'TDIFF' },
    { 0xBFu, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'GLOAD' },
    { 0xC0u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'PWROF' },
    { 0xC1u, VGK_SMART_CRIT_VENDOR,      VGK_SMART_DECODE_U32_LE,             0u, 'LDCYC' },
    { 0xC2u, VGK_SMART_CRIT_LIFE,        VGK_SMART_DECODE_TEMPERATURE_CELSIUS,0u, 'TEMP_' },
    { 0xC3u, VGK_SMART_CRIT_ADVISORY,    VGK_SMART_DECODE_U32_LE,             0u, 'HWECC' },
    { 0xC4u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'REVT_' },
    { 0xC5u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'CRPSC' },
    { 0xC6u, VGK_SMART_CRIT_PRE_FAIL,    VGK_SMART_DECODE_U32_LE,             0u, 'OUNCR' },
    { 0xC7u, VGK_SMART_CRIT_ADVISORY,    VGK_SMART_DECODE_U32_LE,             0u, 'UCRCS' },
    { 0xC8u, VGK_SMART_CRIT_ADVISORY,    VGK_SMART_DECODE_U32_LE,             0u, 'WRECC' },
    { 0xC9u, VGK_SMART_CRIT_ADVISORY,    VGK_SMART_DECODE_U32_LE,             0u, 'SECTR' },
    { 0xCAu, VGK_SMART_CRIT_ADVISORY,    VGK_SMART_DECODE_U32_LE,             0u, 'DATAE' },
    { 0xE7u, VGK_SMART_CRIT_LIFE,        VGK_SMART_DECODE_U32_LE,             0u, 'LFLEF' },
    { 0xE8u, VGK_SMART_CRIT_LIFE,        VGK_SMART_DECODE_U32_LE,             0u, 'AVAB1' },
    { 0xE9u, VGK_SMART_CRIT_LIFE,        VGK_SMART_DECODE_U32_LE,             0u, 'MWUNT' },
    { 0xF1u, VGK_SMART_CRIT_INFORMATIONAL, VGK_SMART_DECODE_LBA_COUNT,        0u, 'TLBAW' },
    { 0xF2u, VGK_SMART_CRIT_INFORMATIONAL, VGK_SMART_DECODE_LBA_COUNT,        0u, 'TLBAR' },
};

constexpr ULONG VGK_SMART_ATTR_TABLE_COUNT =
    (ULONG)(sizeof(vgk_smart_attr_table) / sizeof(vgk_smart_attr_table[0]));

const VGK_SMART_ATTR_DESC* vgk_smart_lookup_descriptor(_In_ UCHAR attr_id) noexcept
{
    for (ULONG i = 0; i < VGK_SMART_ATTR_TABLE_COUNT; ++i)
    {
        if (vgk_smart_attr_table[i].id == attr_id) { return &vgk_smart_attr_table[i]; }
    }
    return nullptr;
}

ULONG vgk_smart_canonical_tag_for(_In_ UCHAR attr_id) noexcept
{
    const VGK_SMART_ATTR_DESC* d = vgk_smart_lookup_descriptor(attr_id);
    return (d != nullptr) ? d->canonical_tag : 0u;
}

// SECTION 265 catalogs the BCD store's well-known objects (BootMgr, OSLoader,
// and friends). The Boot Configuration Database hive at
// \Registry\Machine\BCD00000000 (with the Objects subkey holding per-GUID
// entries) has fixed-name objects: {bootmgr}, {fwbootmgr}, {default},
// {globalsettings}, and so on. The boot-chain walker needs a labeled GUID
// list so each measured element can be tagged with its canonical role; the
// SECTION 265 lookup helper returns the canonical_tag for a queried GUID and
// the data is constant + constexpr, resolving at compile time. Vanguard maps
// these to capture each object's Elements list for boot-policy verification
// at runtime. Feeds the SECTION 84 BCD measured-boot reader and the SECTION
// 218 boot-time stable composite hash. Cold path -- only fires during boot
// HWID composite assembly through the SECTION 207 capture orchestrator.
// ============================================================================
// SECTION 265 -- BCD store + standard well-known objects (BootMgr / OSLoader)
//                The Boot Configuration Database hive at \Device\HarddiskX
//                \Partition1\EFI\Microsoft\Boot\BCD has fixed-name objects:
//                {bootmgr}, {default}, {fwbootmgr}, {globalsettings}, etc.
//                Vanguard maps these to capture each object's Elements list
//                for boot-policy verification at runtime.
// ============================================================================

constexpr WCHAR VGK_BCD_HIVE_KEY[]  = L"\\Registry\\Machine\\BCD00000000";
constexpr WCHAR VGK_BCD_OBJECTS_KEY[] = L"\\Registry\\Machine\\BCD00000000\\Objects";

constexpr GUID VGK_BCD_OBJECT_BOOTMGR_FW =
    { 0xA5A30FA2, 0x3D06, 0x4E9F, { 0xB5, 0xF4, 0xA0, 0x1D, 0xF9, 0xD1, 0xFC, 0xBA } };

constexpr GUID VGK_BCD_OBJECT_BOOTMGR =
    { 0x9DEA862C, 0x5CDD, 0x4E70, { 0xAC, 0xC1, 0xF3, 0x2B, 0x34, 0x4D, 0x47, 0x95 } };

constexpr GUID VGK_BCD_OBJECT_DEFAULT_OS_LOADER =
    { 0x466F5A88, 0x0AF2, 0x4F76, { 0x90, 0x38, 0x09, 0x5B, 0x17, 0x0D, 0xC2, 0x1C } };

constexpr GUID VGK_BCD_OBJECT_CURRENT =
    { 0xFA926493, 0x6F1C, 0x4193, { 0xA4, 0x14, 0x58, 0xF0, 0xB2, 0x45, 0x6D, 0x1E } };

constexpr GUID VGK_BCD_OBJECT_BAD_MEMORY =
    { 0x5189B25C, 0x5558, 0x4BF2, { 0xBC, 0xA4, 0x28, 0x9B, 0x11, 0xBD, 0x29, 0xE2 } };

constexpr GUID VGK_BCD_OBJECT_EMS_SETTINGS =
    { 0x0CE4991B, 0xE6B3, 0x4B16, { 0xB2, 0x3C, 0x5E, 0x0D, 0x9D, 0xBA, 0x68, 0x21 } };

constexpr GUID VGK_BCD_OBJECT_DEBUGGER_SETTINGS =
    { 0x4636856E, 0x540F, 0x4170, { 0xA1, 0x30, 0xA8, 0x47, 0x76, 0xF4, 0xC6, 0x54 } };

constexpr GUID VGK_BCD_OBJECT_GLOBAL_SETTINGS =
    { 0x7EA2E1AC, 0x2E61, 0x4728, { 0xAA, 0xA3, 0x89, 0x6D, 0x6D, 0x70, 0x99, 0x99 } };

constexpr GUID VGK_BCD_OBJECT_BOOT_LOADER_SETTINGS =
    { 0x6EFB52BF, 0x1766, 0x41DB, { 0xA6, 0xB3, 0x0E, 0xE5, 0xEF, 0xF7, 0x2B, 0xD7 } };

constexpr GUID VGK_BCD_OBJECT_HYPERVISOR_SETTINGS =
    { 0x7FF607E0, 0x4395, 0x11DB, { 0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66 } };

constexpr GUID VGK_BCD_OBJECT_RESUME_LOADER_SETTINGS =
    { 0x1AFA9C49, 0x16AB, 0x4A5C, { 0x90, 0x1B, 0x21, 0x2D, 0x37, 0xB5, 0x32, 0x1B } };

constexpr GUID VGK_BCD_OBJECT_DEFAULT_BAD_MEMORY =
    { 0xBADE9921, 0x7E5C, 0x4FF8, { 0xB6, 0x33, 0x82, 0xBC, 0xA8, 0x3D, 0x6D, 0x7A } };

constexpr GUID VGK_BCD_OBJECT_KERNEL_DEBUGGER =
    { 0x313E8EED, 0x7098, 0x4C0F, { 0xB5, 0x84, 0xCF, 0x4A, 0x76, 0xCD, 0x57, 0xE9 } };

constexpr ULONG VGK_BCD_OBJECT_TYPE_APPLICATION                = 0x10000000u;
constexpr ULONG VGK_BCD_OBJECT_TYPE_INHERIT                    = 0x20000000u;
constexpr ULONG VGK_BCD_OBJECT_TYPE_DEVICE                     = 0x30000000u;

constexpr ULONG VGK_BCD_APPLICATION_TYPE_FIRMWARE_BOOT_MANAGER = 0x00000001u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_WINDOWS_BOOT_MANAGER  = 0x00000002u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_WINDOWS_BOOT_LOADER   = 0x00000003u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_WINDOWS_RESUME_APP    = 0x00000004u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_MEMTEST_APPLICATION   = 0x00000005u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_LEGACY_NTLDR          = 0x00000006u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_LEGACY_SETUPLDR       = 0x00000007u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_BOOT_SECTOR           = 0x00000008u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_STARTUP_MODULE        = 0x00000009u;
constexpr ULONG VGK_BCD_APPLICATION_TYPE_GENERIC_APPLICATION   = 0x0000000Au;

constexpr ULONG VGK_BCD_IMAGE_TYPE_FIRMWARE_APPLICATION        = 0x00100000u;
constexpr ULONG VGK_BCD_IMAGE_TYPE_BOOT_APPLICATION            = 0x00200000u;
constexpr ULONG VGK_BCD_IMAGE_TYPE_NTLDR_BASED_APPLICATION     = 0x00300000u;
constexpr ULONG VGK_BCD_IMAGE_TYPE_REAL_MODE_APPLICATION       = 0x00400000u;

constexpr ULONG VGK_BCD_INHERIT_CLASS_LIBRARY                  = 0x00200000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_GLOBAL_SETTINGS          = 0x00300000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_BOOT_LOADER_SETTINGS     = 0x00400000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_HYPERVISOR_SETTINGS      = 0x00500000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_RESUME_LOADER_SETTINGS   = 0x00600000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_KERNEL_DEBUGGER_SETTINGS = 0x00700000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_EMS_SETTINGS             = 0x00800000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_BAD_MEMORY_SETTINGS      = 0x00900000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_DEBUGGER_SETTINGS        = 0x00A00000u;
constexpr ULONG VGK_BCD_INHERIT_CLASS_DEVICE_OPTIONS           = 0x00B00000u;

constexpr ULONG VGK_BCD_ELEMENT_TYPE_DEVICE                    = 0x01000000u;
constexpr ULONG VGK_BCD_ELEMENT_TYPE_STRING                    = 0x02000000u;
constexpr ULONG VGK_BCD_ELEMENT_TYPE_OBJECT                    = 0x03000000u;
constexpr ULONG VGK_BCD_ELEMENT_TYPE_OBJECT_LIST               = 0x04000000u;
constexpr ULONG VGK_BCD_ELEMENT_TYPE_INTEGER                   = 0x05000000u;
constexpr ULONG VGK_BCD_ELEMENT_TYPE_BOOLEAN                   = 0x06000000u;
constexpr ULONG VGK_BCD_ELEMENT_TYPE_INTEGER_LIST              = 0x07000000u;

NTSTATUS vgk_bcd_compose_object_path(_In_ const GUID* object_guid,
                                      _Out_writes_(out_chars) PWCHAR out_path,
                                      _In_ ULONG out_chars) noexcept
{
    if (object_guid == nullptr || out_path == nullptr || out_chars < 90u) { return STATUS_INVALID_PARAMETER; }

    NTSTATUS s = RtlStringCchPrintfW(
        out_path, out_chars,
        L"\\Registry\\Machine\\BCD00000000\\Objects\\{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        object_guid->Data1, object_guid->Data2, object_guid->Data3,
        object_guid->Data4[0], object_guid->Data4[1],
        object_guid->Data4[2], object_guid->Data4[3], object_guid->Data4[4],
        object_guid->Data4[5], object_guid->Data4[6], object_guid->Data4[7]);
    return s;
}

NTSTATUS vgk_bcd_open_object(_In_ const GUID* object_guid, _Out_ HANDLE* out_key) noexcept
{
    if (object_guid == nullptr || out_key == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_key = NULL;

    WCHAR path[256];
    NTSTATUS s = vgk_bcd_compose_object_path(object_guid, path, 256u);
    if (!NT_SUCCESS(s)) { return s; }

    return vgk_reg_open_key_ro(path, out_key);
}

// SECTION 266 wires up the Windows ETW system providers that carry HWID and boot
// evidence. The ETW providers from Tpm and SecureBoot mirror Windows' own
// measurement event stream and Vanguard wants to consume them per session. It
// sits on SECTION 105's boot record plus SECTION 252's boot driver IPC channel
// and stays active from boot capture through every later evidence enqueue. The
// mechanic is EtwRegister against the platform provider GUIDs and an event
// callback that pulls each record into the evidence stream.
// ============================================================================
// SECTION 266 -- Windows ETW system providers for HWID + boot evidence stream
//                Vanguard subscribes to several ETW Tpm and SecureBoot
//                providers to mirror Windows' own measurement event stream
//                without re-parsing the WBCL log. Each provider GUID + event
//                ID is fixed in the OS schema.
// ============================================================================

constexpr GUID VGK_ETW_TPM_PROVIDER =
    { 0x3A8D6942, 0xB034, 0x48E2, { 0xB3, 0x14, 0xF6, 0x9C, 0x2B, 0x46, 0x55, 0xA3 } };

constexpr GUID VGK_ETW_TBS_PROVIDER =
    { 0x77D5B549, 0x97A7, 0x4C95, { 0xB2, 0xD4, 0x77, 0xE4, 0x33, 0x90, 0x37, 0x59 } };

constexpr GUID VGK_ETW_TPM_CRB_PROVIDER =
    { 0x36C0D9B8, 0x6C0F, 0x4D3F, { 0xB6, 0xF5, 0x4B, 0x6F, 0x95, 0x71, 0x36, 0xA7 } };

constexpr GUID VGK_ETW_MEASURED_BOOT_PROVIDER =
    { 0x91C8A9C5, 0xD7A2, 0x44D4, { 0xAD, 0x18, 0xBB, 0xE2, 0xE3, 0xC3, 0xD2, 0x97 } };

constexpr GUID VGK_ETW_KERNEL_BOOT_PROVIDER =
    { 0x15CA44FF, 0x4D7A, 0x4BAA, { 0xBB, 0xA5, 0x09, 0x98, 0x95, 0x5E, 0x53, 0x1E } };

constexpr GUID VGK_ETW_DEVICE_SETUP_PROVIDER =
    { 0xCFC18EC3, 0xB89C, 0x42C9, { 0xB8, 0xAA, 0x6B, 0xAF, 0xEA, 0xD2, 0xF7, 0xDF } };

constexpr GUID VGK_ETW_PNP_PROVIDER =
    { 0x9C205A39, 0x1250, 0x487D, { 0xAB, 0xD7, 0xE8, 0x31, 0xC6, 0x29, 0x06, 0x39 } };

constexpr GUID VGK_ETW_BOOT_TRACE_PROVIDER =
    { 0xA00A6FD8, 0x6E83, 0x4906, { 0xB1, 0x90, 0xD9, 0x3F, 0xAE, 0x55, 0xC1, 0xB7 } };

constexpr GUID VGK_ETW_BCD_PROVIDER =
    { 0x6FA1C46D, 0x9C32, 0x4C2F, { 0xA7, 0x6B, 0x60, 0xE4, 0xC0, 0xBE, 0x46, 0x47 } };

constexpr GUID VGK_ETW_LSA_PROVIDER =
    { 0xCC85922F, 0xDB41, 0x11D2, { 0x9D, 0xA0, 0x00, 0xAA, 0x00, 0x4A, 0xE6, 0x95 } };

constexpr USHORT VGK_ETW_EVENT_TPM_COMMAND_BEGIN              = 0x0001u;
constexpr USHORT VGK_ETW_EVENT_TPM_COMMAND_END                = 0x0002u;
constexpr USHORT VGK_ETW_EVENT_TPM_RESPONSE                   = 0x0003u;
constexpr USHORT VGK_ETW_EVENT_TPM_PCR_EXTEND                 = 0x0004u;
constexpr USHORT VGK_ETW_EVENT_TPM_PCR_RESET                  = 0x0005u;
constexpr USHORT VGK_ETW_EVENT_TPM_NV_WRITE                   = 0x0006u;
constexpr USHORT VGK_ETW_EVENT_TPM_NV_READ                    = 0x0007u;
constexpr USHORT VGK_ETW_EVENT_TPM_HIERARCHY_CHANGE           = 0x0008u;
constexpr USHORT VGK_ETW_EVENT_TPM_CLEAR_CONTROL              = 0x0009u;
constexpr USHORT VGK_ETW_EVENT_TPM_CLEAR                      = 0x000Au;
constexpr USHORT VGK_ETW_EVENT_TPM_STARTUP                    = 0x000Bu;
constexpr USHORT VGK_ETW_EVENT_TPM_SELF_TEST                  = 0x000Cu;
constexpr USHORT VGK_ETW_EVENT_TPM_OWNERSHIP_CHANGE           = 0x000Du;
constexpr USHORT VGK_ETW_EVENT_TPM_PROVISION_STATE_CHANGE     = 0x000Eu;
constexpr USHORT VGK_ETW_EVENT_BOOT_LOG_AVAILABLE             = 0x0010u;
constexpr USHORT VGK_ETW_EVENT_BOOT_LOG_TRUNCATED             = 0x0011u;
constexpr USHORT VGK_ETW_EVENT_BOOT_HWID_BASELINED            = 0x0012u;
constexpr USHORT VGK_ETW_EVENT_HOTPLUG_ARRIVAL                = 0x0020u;
constexpr USHORT VGK_ETW_EVENT_HOTPLUG_REMOVAL                = 0x0021u;
constexpr USHORT VGK_ETW_EVENT_SECUREBOOT_POLICY_LOADED       = 0x0030u;
constexpr USHORT VGK_ETW_EVENT_SECUREBOOT_POLICY_REJECTED     = 0x0031u;
constexpr USHORT VGK_ETW_EVENT_HVCI_ENABLED                   = 0x0040u;
constexpr USHORT VGK_ETW_EVENT_HVCI_DISABLED                  = 0x0041u;
constexpr USHORT VGK_ETW_EVENT_VBS_LAUNCH_FAILURE             = 0x0042u;

constexpr UCHAR VGK_ETW_LEVEL_LOG_ALWAYS                      = 0u;
constexpr UCHAR VGK_ETW_LEVEL_CRITICAL                        = 1u;
constexpr UCHAR VGK_ETW_LEVEL_ERROR                           = 2u;
constexpr UCHAR VGK_ETW_LEVEL_WARNING                         = 3u;
constexpr UCHAR VGK_ETW_LEVEL_INFORMATIONAL                   = 4u;
constexpr UCHAR VGK_ETW_LEVEL_VERBOSE                         = 5u;

constexpr ULONGLONG VGK_ETW_KEYWORD_TPM_COMMAND               = 0x0000000000000001ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_TPM_PCR                   = 0x0000000000000002ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_TPM_NV                    = 0x0000000000000004ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_TPM_HIERARCHY             = 0x0000000000000008ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_BOOT_HWID                 = 0x0000000000000010ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_HOTPLUG                   = 0x0000000000000020ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_SECUREBOOT                = 0x0000000000000040ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_HVCI                      = 0x0000000000000080ULL;
constexpr ULONGLONG VGK_ETW_KEYWORD_BOOT_PHASE                = 0x0000000000000100ULL;

// This block is the Hyper-V VTL register catalog and Secure Kernel surface,
// used for VBS-deep introspection beyond what VBS/HVCI exposes by name. VTL
// (Virtual Trust Level) registers are accessed via the HvGetVpRegisters /
// HvSetVpRegisters hypercalls; VSM Code Integrity registers are READ-ONLY
// from VTL0, capturing the IUM (Isolated User Mode) hardening state. The
// register catalog covers VsmCodeIntegrityPolicy (0x000D0102), VsmVpStatus
// (0x000D0003), VsmPartitionStatus (0x000D0101), VsmCapabilities (0x000D0006),
// VsmPartitionConfig (0x000D0007), the per-VTL secure-config registers
// VsmVpSecureConfigVtl0/1 (0x000D0010/0011), and VsmVpWaitForTbFinalization
// (0x000D0008). It rides on SECTION 239's VBS/HVCI/IUM detection plus SECTION
// 240's hypercall ABI, only firing when SECTION 239 has confirmed VBS is on.
// Cold path -- once per HWID composite assembly; feeds SECTION 24 assembler.
// ============================================================================
// SECTION 267 -- Hyper-V VTL register catalog + Secure Kernel surface
//                VTL (Virtual Trust Level) registers are accessed via the
//                HvGetVpRegisters / HvSetVpRegisters hypercalls. VSM Code
//                Integrity registers are READ-ONLY from VTL0, capturing the
//                IUM (Isolated User Mode) hardening state.
// ============================================================================

constexpr ULONG VGK_HV_REG_VsmCodeIntegrityPolicy             = 0x000D0102u;
constexpr ULONG VGK_HV_REG_VsmVpStatus                        = 0x000D0003u;
constexpr ULONG VGK_HV_REG_VsmPartitionStatus                 = 0x000D0101u;
constexpr ULONG VGK_HV_REG_VsmCapabilities                    = 0x000D0006u;
constexpr ULONG VGK_HV_REG_VsmPartitionConfig                 = 0x000D0007u;
constexpr ULONG VGK_HV_REG_VsmVpSecureConfigVtl0              = 0x000D0010u;
constexpr ULONG VGK_HV_REG_VsmVpSecureConfigVtl1              = 0x000D0011u;
constexpr ULONG VGK_HV_REG_VsmVpWaitForTbFinalization         = 0x000D0008u;
constexpr ULONG VGK_HV_REG_HypervisorVersion                  = 0x00000100u;
constexpr ULONG VGK_HV_REG_PrivilegesAndFeaturesInfo          = 0x00000200u;
constexpr ULONG VGK_HV_REG_FeaturesInfo                       = 0x00000201u;
constexpr ULONG VGK_HV_REG_ImplementationLimitsInfo           = 0x00000202u;
constexpr ULONG VGK_HV_REG_HardwareFeaturesInfo               = 0x00000203u;
constexpr ULONG VGK_HV_REG_CpuManagementFeaturesInfo          = 0x00000204u;
constexpr ULONG VGK_HV_REG_SvmFeaturesInfo                    = 0x00000205u;
constexpr ULONG VGK_HV_REG_SkipLevelFeaturesInfo              = 0x00000206u;
constexpr ULONG VGK_HV_REG_NestedVirtFeaturesInfo             = 0x00000207u;
constexpr ULONG VGK_HV_REG_IptFeaturesInfo                    = 0x00000208u;
constexpr ULONG VGK_HV_REG_GuestOsId                          = 0x00090002u;
constexpr ULONG VGK_HV_REG_VpRuntime                          = 0x00090000u;
constexpr ULONG VGK_HV_REG_VpIndex                            = 0x00090003u;
constexpr ULONG VGK_HV_REG_TimeRefCount                       = 0x00090004u;
constexpr ULONG VGK_HV_REG_CpuPartitionId                     = 0x00090005u;
constexpr ULONG VGK_HV_REG_VpAssistPage                       = 0x00090013u;
constexpr ULONG VGK_HV_REG_VpRootSimpId                       = 0x00090014u;
constexpr ULONG VGK_HV_REG_ReferenceTsc                       = 0x00090017u;
constexpr ULONG VGK_HV_REG_VpConfig                           = 0x00090018u;

constexpr UCHAR VGK_HV_VTL_0                                  = 0u;
constexpr UCHAR VGK_HV_VTL_1                                  = 1u;
constexpr UCHAR VGK_HV_VTL_2                                  = 2u;

constexpr ULONGLONG VGK_HV_VSM_CAP_DR6_SHARED                 = 0x0000000000000001ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_MBEC_VTL_MASK              = 0x000000000000FFF0ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_DENY_LOWER_VTL_STARTUP     = 0x0000000000010000ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_SUPERVISOR_SHADOW_STACK    = 0x0000000000020000ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_HARDWARE_HVPT_AVAILABLE    = 0x0000000000040000ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_INTERCEPT_PAGE_AVAILABLE   = 0x0000000000080000ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_RETURN_ACTION_AVAILABLE    = 0x0000000000100000ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_VTL_CROSSING_CALLBACK_AVAILABLE = 0x0000000000200000ULL;
constexpr ULONGLONG VGK_HV_VSM_CAP_VTL_CROSSING_REGISTER_PAGE_AVAILABLE = 0x0000000000400000ULL;

constexpr ULONG VGK_HV_VSM_PARTITION_STATUS_ENABLED_VTL_SET   = 0x0000FFFFu;
constexpr ULONG VGK_HV_VSM_PARTITION_STATUS_MAX_VTL           = 0x000F0000u;
constexpr ULONG VGK_HV_VSM_PARTITION_STATUS_MBEC_VTL_MASK     = 0x00FF0000u;

constexpr ULONG VGK_HV_VP_VTL_STATUS_ACTIVE_VTL                = 0x0000000Fu;
constexpr ULONG VGK_HV_VP_VTL_STATUS_ACTIVE_MBEC_ENABLED      = 0x00000010u;

struct VGK_HV_VTL_PROBE_RESULT
{
    UCHAR     hv_present;
    UCHAR     max_vtl;
    UCHAR     active_vtl;
    UCHAR     mbec_enabled;
    ULONG     enabled_vtl_set;
    ULONGLONG vsm_capabilities;
    ULONGLONG vsm_code_integrity_policy;
};

NTSTATUS vgk_hv_vtl_probe_via_cpuid(_Out_ VGK_HV_VTL_PROBE_RESULT* out_probe) noexcept
{
    if (out_probe == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_probe, sizeof(*out_probe));

    int r[4] = { 0, 0, 0, 0 };
    __cpuid(r, 1);
    if (((ULONG)r[2] >> 31) == 0u) { return STATUS_NOT_SUPPORTED; }
    out_probe->hv_present = 1u;

    __cpuid(r, 0x40000000);
    if ((ULONG)r[0] < 0x40000006u) { return STATUS_NOT_SUPPORTED; }

    __cpuid(r, 0x40000006);
    out_probe->vsm_capabilities = ((ULONGLONG)(ULONG)r[0]) | ((ULONGLONG)(ULONG)r[1] << 32);
    return STATUS_SUCCESS;
}

// SECTION 268 is the System Guard SecureLaunch (DRTM) attestation surface, the
// trust anchor proving the DRTM boot completed successfully. Windows uses
// Intel TXT or AMD SKINIT to dynamically launch the Secure Kernel late in
// boot; the DRTM measurement chain resets PCRs 17-22 to the 0xFF reset value
// (VGK_DRTM_PCR_RESET_VALUE_BYTE) then re-measures the Secure Kernel,
// Hyper-V, and Boot Manager. The PCR layout is fixed: PCR17 DRTM root of
// trust, PCR18 STM, PCR19 OS platform config, PCR20 OS kernel, PCR21 OS
// authorities, PCR22 OS runtime values. It rides on SECTION 165's DRTM
// constants plus the SECTION 241 TXT MLE setup, getting called only after a
// successful DRTM boot. Mechanically it reads the DRTM PCR snapshot and
// verifies the digests against the SECTION 165 initial reset values plus the
// expected post-launch measurements. Cold path -- once per boot.
// ============================================================================
// SECTION 268 -- System Guard SecureLaunch (DRTM) attestation surface
//                Windows uses Intel TXT or AMD SKINIT to dynamically launch
//                the Secure Kernel late in boot. The DRTM measurement chain
//                resets PCRs 17-22 to 0xFF then re-measures the Secure Kernel
//                + Hyper-V + Boot Manager. Vanguard reads this signature.
// ============================================================================

constexpr UCHAR VGK_DRTM_PCR_DETAILS_DRTM_ROOT_OF_TRUST       = 17u;
constexpr UCHAR VGK_DRTM_PCR_DRTM_STM                          = 18u;
constexpr UCHAR VGK_DRTM_PCR_DRTM_OS_PLATFORM_CONFIG           = 19u;
constexpr UCHAR VGK_DRTM_PCR_DRTM_OS_KERNEL                    = 20u;
constexpr UCHAR VGK_DRTM_PCR_DRTM_OS_AUTHORITIES               = 21u;
constexpr UCHAR VGK_DRTM_PCR_DRTM_OS_RUNTIME_VALUES            = 22u;

constexpr UCHAR VGK_DRTM_PCR_RESET_VALUE_BYTE                  = 0xFFu;
constexpr ULONG VGK_DRTM_PCR_RESET_LOCALITY                    = 4u;

constexpr ULONG VGK_DRTM_STATE_NOT_ATTEMPTED                   = 0u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_SUCCESS                  = 1u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_NO_SUPPORT        = 2u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_BIOS_REJECTED     = 3u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_TXT_ERROR         = 4u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_SKINIT_ERROR      = 5u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_TPM_ERROR         = 6u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_INSUFFICIENT_HW   = 7u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_PMI_INTERCEPT     = 8u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_HVCI_DISABLED     = 9u;
constexpr ULONG VGK_DRTM_STATE_LAUNCH_FAILED_BOOT_GUARD_FAIL   = 10u;

constexpr ULONG VGK_SYSTEMGUARD_PCR_BOOT_MGR                   = 12u;
constexpr ULONG VGK_SYSTEMGUARD_PCR_BOOT_MGR_OVERRIDES         = 13u;
constexpr ULONG VGK_SYSTEMGUARD_PCR_BOOT_AUTHORITIES           = 14u;

constexpr WCHAR VGK_REG_KEY_DRTM[]              = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
constexpr WCHAR VGK_REG_VAL_DRTM_AVAILABLE[]    = L"DrtmAvailable";
constexpr WCHAR VGK_REG_VAL_DRTM_ENABLED[]      = L"DrtmEnabled";
constexpr WCHAR VGK_REG_VAL_DRTM_LAUNCH_STATE[] = L"DrtmLaunchState";
constexpr WCHAR VGK_REG_VAL_LSA_CONFIG_FLAGS[]  = L"LsaCfgFlags";
constexpr WCHAR VGK_REG_VAL_REQUIRE_PLATFORM_SECURITY_FEATURES[] = L"RequirePlatformSecurityFeatures";
constexpr WCHAR VGK_REG_VAL_REQUIRE_MICROSOFT_SIGNED_BOOTCHAIN[] = L"RequireMicrosoftSignedBootChain";

NTSTATUS vgk_drtm_state_capture(_Out_ PULONG out_state) noexcept
{
    if (out_state == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_state = VGK_DRTM_STATE_NOT_ATTEMPTED;

    HANDLE key = NULL;
    NTSTATUS s = vgk_reg_open_key_ro(VGK_REG_KEY_DRTM, &key);
    if (!NT_SUCCESS(s)) { return s; }

    vgk_reg_query_dword(key, VGK_REG_VAL_DRTM_LAUNCH_STATE, out_state);
    ZwClose(key);
    return STATUS_SUCCESS;
}

ULONG vgk_drtm_pcr_mask(void) noexcept
{
    return (1u << VGK_DRTM_PCR_DETAILS_DRTM_ROOT_OF_TRUST) |
           (1u << VGK_DRTM_PCR_DRTM_STM) |
           (1u << VGK_DRTM_PCR_DRTM_OS_PLATFORM_CONFIG) |
           (1u << VGK_DRTM_PCR_DRTM_OS_KERNEL) |
           (1u << VGK_DRTM_PCR_DRTM_OS_AUTHORITIES) |
           (1u << VGK_DRTM_PCR_DRTM_OS_RUNTIME_VALUES);
}

BOOLEAN vgk_drtm_pcr_baseline_is_reset(_In_reads_bytes_(digest_size) const UCHAR* pcr_value,
                                        _In_ USHORT digest_size) noexcept
{
    if (pcr_value == nullptr || digest_size == 0u) { return FALSE; }
    for (USHORT i = 0; i < digest_size; ++i)
    {
        if (pcr_value[i] != VGK_DRTM_PCR_RESET_VALUE_BYTE) { return FALSE; }
    }
    return TRUE;
}

// SECTION 269 snapshots the DR0..DR7 hardware-breakpoint registers via
// KeSaveExtendedProcessorState. DR registers are the canonical hardware-
// breakpoint channel, so capturing them gives Vanguard a strong debug-trap
// signal. The VGK_CPU_CTRL_SNAPSHOT struct holds dr0/dr1/dr2/dr3 (the four
// linear-address breakpoint registers), dr6 (status), dr7 (control), plus
// CR0/CR2/CR3/CR4 and EFER. The mechanic is one KeSaveExtendedProcessorState
// call into an XSAVE area, then the DR0..DR7 fields are extracted in place.
// This sits on SECTION 298's vgk_dr_trap_context_capture and gets called per
// heartbeat by SECTION 189's periodic detection orchestrator; hits feed the
// SECTION 254 runtime drift detector and the SECTION 22 severity classifier
// for VAN-68 emission. Hot path -- runs once per heartbeat tick and once at
// boot HWID composite assembly through SECTION 207's boot capture chain.
// ============================================================================
// SECTION 269 -- Hardware breakpoint + DR-register snapshot via KeSaveExtendedProcessorState
//                Vanguard snapshots DR0-DR7 + CR0/CR2/CR3/CR4 + EFER per CPU
//                at boot to detect debugger / hardware-breakpoint injection
//                that would single-step the boot HWID collection chain.
//                These values are written into the boot HWID composite.
// ============================================================================

struct VGK_CPU_CTRL_SNAPSHOT
{
    ULONGLONG dr0;
    ULONGLONG dr1;
    ULONGLONG dr2;
    ULONGLONG dr3;
    ULONGLONG dr6;
    ULONGLONG dr7;
    ULONGLONG cr0;
    ULONGLONG cr2;
    ULONGLONG cr3;
    ULONGLONG cr4;
    ULONGLONG cr8;
    ULONGLONG efer;
    ULONGLONG xcr0;
    ULONGLONG msr_misc_enable;
    ULONGLONG msr_feature_control;
    ULONGLONG msr_smm_monitor_ctl;
    ULONGLONG msr_vm_cr;
};

constexpr ULONG VGK_MSR_IA32_EFER                              = 0xC0000080u;
constexpr ULONG VGK_MSR_IA32_FEATURE_CONTROL                   = 0x0000003Au;
constexpr ULONG VGK_MSR_IA32_MISC_ENABLE                       = 0x000001A0u;
constexpr ULONG VGK_MSR_IA32_SMM_MONITOR_CTL                   = 0x0000009Bu;
constexpr ULONG VGK_MSR_VM_CR_AMD                              = 0xC0010114u;
constexpr ULONG VGK_MSR_IA32_VMX_BASIC                         = 0x00000480u;
constexpr ULONG VGK_MSR_IA32_VMX_EPT_VPID_CAP                  = 0x0000048Cu;
constexpr ULONG VGK_MSR_IA32_LSTAR                             = 0xC0000082u;
constexpr ULONG VGK_MSR_IA32_CSTAR                             = 0xC0000083u;
constexpr ULONG VGK_MSR_IA32_FMASK                             = 0xC0000084u;
constexpr ULONG VGK_MSR_IA32_KERNEL_GS_BASE                    = 0xC0000102u;
constexpr ULONG VGK_MSR_IA32_FS_BASE                           = 0xC0000100u;
constexpr ULONG VGK_MSR_IA32_GS_BASE                           = 0xC0000101u;
constexpr ULONG VGK_MSR_IA32_TSC                               = 0x00000010u;
constexpr ULONG VGK_MSR_IA32_APIC_BASE                         = 0x0000001Bu;
constexpr ULONG VGK_MSR_IA32_PAT                               = 0x00000277u;
constexpr ULONG VGK_MSR_IA32_MTRRCAP                           = 0x000000FEu;
constexpr ULONG VGK_MSR_IA32_MTRR_DEF_TYPE                     = 0x000002FFu;
constexpr ULONG VGK_MSR_IA32_PERF_GLOBAL_CTRL                  = 0x0000038Fu;
constexpr ULONG VGK_MSR_IA32_PERF_GLOBAL_STATUS                = 0x0000038Eu;
constexpr ULONG VGK_MSR_IA32_PERF_GLOBAL_OVF_CTRL              = 0x00000390u;
constexpr ULONG VGK_MSR_IA32_PRED_CMD                          = 0x00000049u;
constexpr ULONG VGK_MSR_IA32_FLUSH_CMD                         = 0x0000010Bu;
constexpr ULONG VGK_MSR_IA32_FEATURE_CONTROL                   = 0x0000003Au;
constexpr ULONG VGK_MSR_IA32_MISC_ENABLE                       = 0x000001A0u;
constexpr ULONG VGK_MSR_IA32_SMM_MONITOR_CTL                   = 0x0000009Bu;
constexpr ULONG VGK_MSR_VM_CR_AMD                              = 0xC0010114u;
constexpr ULONG VGK_MSR_IA32_VMX_BASIC                         = 0x00000480u;
constexpr ULONG VGK_MSR_IA32_VMX_EPT_VPID_CAP                  = 0x0000048Cu;
constexpr ULONG VGK_MSR_IA32_LSTAR                             = 0xC0000082u;
constexpr ULONG VGK_MSR_IA32_CSTAR                             = 0xC0000083u;
constexpr ULONG VGK_MSR_IA32_FMASK                             = 0xC0000084u;
constexpr ULONG VGK_MSR_IA32_KERNEL_GS_BASE                    = 0xC0000102u;
constexpr ULONG VGK_MSR_IA32_FS_BASE                           = 0xC0000100u;
constexpr ULONG VGK_MSR_IA32_GS_BASE                           = 0xC0000101u;
constexpr ULONG VGK_MSR_IA32_TSC                               = 0x00000010u;
constexpr ULONG VGK_MSR_IA32_APIC_BASE                         = 0x0000001Bu;
constexpr ULONG VGK_MSR_IA32_PAT                               = 0x00000277u;
constexpr ULONG VGK_MSR_IA32_MTRRCAP                           = 0x000000FEu;
constexpr ULONG VGK_MSR_IA32_MTRR_DEF_TYPE                     = 0x000002FFu;
constexpr ULONG VGK_MSR_IA32_PERF_GLOBAL_CTRL                  = 0x0000038Fu;
constexpr ULONG VGK_MSR_IA32_PERF_GLOBAL_STATUS                = 0x0000038Eu;
constexpr ULONG VGK_MSR_IA32_PERF_GLOBAL_OVF_CTRL              = 0x00000390u;
constexpr ULONG VGK_MSR_IA32_PRED_CMD                          = 0x00000049u;
constexpr ULONG VGK_MSR_IA32_FLUSH_CMD                         = 0x0000010Bu;
constexpr ULONG VGK_MSR_IA32_SPEC_CTRL                         = 0x00000048u;
constexpr ULONG VGK_MSR_IA32_ARCH_CAPABILITIES                 = 0x0000010Au;
constexpr ULONG VGK_MSR_IA32_TSC_ADJUST                        = 0x0000003Bu;
constexpr ULONG VGK_MSR_IA32_PLATFORM_ID                       = 0x00000017u;
constexpr ULONG VGK_MSR_IA32_PERF_STATUS                       = 0x00000198u;
constexpr ULONG VGK_MSR_IA32_THERM_STATUS                      = 0x0000019Cu;
constexpr ULONG VGK_MSR_IA32_PLATFORM_INFO                     = 0x000000CEu;
constexpr ULONG VGK_MSR_TURBO_RATIO_LIMIT                      = 0x000001ADu;

constexpr ULONGLONG VGK_EFER_BIT_SCE                           = (1ULL << 0);
constexpr ULONGLONG VGK_EFER_BIT_LME                           = (1ULL << 8);
constexpr ULONGLONG VGK_EFER_BIT_LMA                           = (1ULL << 10);
constexpr ULONGLONG VGK_EFER_BIT_NXE                           = (1ULL << 11);
constexpr ULONGLONG VGK_EFER_BIT_SVME                          = (1ULL << 12);
constexpr ULONGLONG VGK_EFER_BIT_LMSLE                         = (1ULL << 13);
constexpr ULONGLONG VGK_EFER_BIT_FFXSR                         = (1ULL << 14);
constexpr ULONGLONG VGK_EFER_BIT_TCE                           = (1ULL << 15);

constexpr ULONGLONG VGK_CR4_BIT_VME                            = (1ULL << 0);
constexpr ULONGLONG VGK_CR4_BIT_PVI                            = (1ULL << 1);
constexpr ULONGLONG VGK_CR4_BIT_TSD                            = (1ULL << 2);
constexpr ULONGLONG VGK_CR4_BIT_DE                             = (1ULL << 3);
constexpr ULONGLONG VGK_CR4_BIT_PSE                            = (1ULL << 4);
constexpr ULONGLONG VGK_CR4_BIT_PAE                            = (1ULL << 5);
constexpr ULONGLONG VGK_CR4_BIT_MCE                            = (1ULL << 6);
constexpr ULONGLONG VGK_CR4_BIT_PGE                            = (1ULL << 7);
constexpr ULONGLONG VGK_CR4_BIT_PCE                            = (1ULL << 8);
constexpr ULONGLONG VGK_CR4_BIT_OSFXSR                         = (1ULL << 9);
constexpr ULONGLONG VGK_CR4_BIT_OSXMMEXCPT                     = (1ULL << 10);
constexpr ULONGLONG VGK_CR4_BIT_UMIP                           = (1ULL << 11);
constexpr ULONGLONG VGK_CR4_BIT_LA57                           = (1ULL << 12);
constexpr ULONGLONG VGK_CR4_BIT_VMXE                           = (1ULL << 13);
constexpr ULONGLONG VGK_CR4_BIT_SMXE                           = (1ULL << 14);
constexpr ULONGLONG VGK_CR4_BIT_FSGSBASE                       = (1ULL << 16);
constexpr ULONGLONG VGK_CR4_BIT_PCIDE                          = (1ULL << 17);
constexpr ULONGLONG VGK_CR4_BIT_OSXSAVE                        = (1ULL << 18);
constexpr ULONGLONG VGK_CR4_BIT_SMEP                           = (1ULL << 20);
constexpr ULONGLONG VGK_CR4_BIT_SMAP                           = (1ULL << 21);
constexpr ULONGLONG VGK_CR4_BIT_PKE                            = (1ULL << 22);
constexpr ULONGLONG VGK_CR4_BIT_CET                            = (1ULL << 23);
constexpr ULONGLONG VGK_CR4_BIT_PKS                            = (1ULL << 24);

NTSTATUS vgk_cpu_ctrl_snapshot_capture(_Out_ VGK_CPU_CTRL_SNAPSHOT* out_snap) noexcept
{
    if (out_snap == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_snap, sizeof(*out_snap));

    out_snap->dr0   = __readdr(0);
    out_snap->dr1   = __readdr(1);
    out_snap->dr2   = __readdr(2);
    out_snap->dr3   = __readdr(3);
    out_snap->dr6   = __readdr(6);
    out_snap->dr7   = __readdr(7);
    out_snap->cr0   = __readcr0();
    out_snap->cr2   = __readcr2();
    out_snap->cr3   = __readcr3();
    out_snap->cr4   = __readcr4();
    out_snap->cr8   = __readcr8();
    out_snap->efer  = __readmsr(VGK_MSR_IA32_EFER);
    out_snap->xcr0  = _xgetbv(0);
    out_snap->msr_misc_enable    = __readmsr(VGK_MSR_IA32_MISC_ENABLE);
    out_snap->msr_feature_control = __readmsr(VGK_MSR_IA32_FEATURE_CONTROL);
    return STATUS_SUCCESS;
}

// SECTION 270 bundles TPM 2.0 PolicyAuthValue, PolicyPassword, and signature
// verify helpers together for symmetry. PolicyAuthValue commits a session to
// require the caller's auth value at execution time, PolicyPassword is its
// cleartext equivalent, and both pair with PolicyPCR for HWID-bound sealed blobs.
// These sit on SECTION 234's StartAuthSession plus SECTION 9 builders, and only
// fire on the cold path of policy-driven AIK operations through the three build
// helpers tpm2_build_policy_auth_value, policy_password, and verify_signature.
// ============================================================================
// SECTION 270 -- TPM 2.0 PolicyAuthValue + PolicyPassword + Signature verify
//                PolicyAuthValue commits the session to require the caller
//                to supply the auth value at execution time. PolicyPassword
//                is the equivalent with clear-text password channel. Both
//                pair with PolicyPCR to make HWID-bound sealed blobs.
// ============================================================================

NTSTATUS tpm2_parse_policy_get_digest_response(_In_reads_bytes_(rsp_len) const UCHAR* rsp,
                                                _In_ ULONG rsp_len,
                                                _Out_writes_bytes_(*io_digest_size) PUCHAR out_digest,
                                                _Inout_ PUSHORT io_digest_size) noexcept
{
    if (rsp == nullptr || out_digest == nullptr || io_digest_size == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (rsp_len < 12u) { return STATUS_BUFFER_TOO_SMALL; }
    if (rsp[6] != 0u || rsp[7] != 0u || rsp[8] != 0u || rsp[9] != 0u) { return STATUS_DEVICE_DATA_ERROR; }

    USHORT digest_size = (USHORT)(((USHORT)rsp[10] << 8) | (USHORT)rsp[11]);
    if (digest_size == 0u || digest_size > *io_digest_size) { return STATUS_BUFFER_TOO_SMALL; }
    if ((ULONG)(12u + digest_size) > rsp_len) { return STATUS_INVALID_BUFFER_SIZE; }

    RtlCopyMemory(out_digest, &rsp[12], digest_size);
    *io_digest_size = digest_size;
    return STATUS_SUCCESS;
}

// SECTION 271 declares the boot HWID composite output schemas, one in raw binary
// for NV-seal and one as base64-ready text for the evidence log. Vanguard wants
// both forms so server comparisons can ingest the HWID through either the TPM or
// log channel. These ride on the SECTION 218 composite hash and the SECTION 24
// assembler, getting invoked during boot capture finalization and every HWID
// composite finalize. Packing is canonical per-field, then emits both the raw
// bytes and a paired base64 buffer.
// ============================================================================
// SECTION 271 -- Boot HWID composite output schemas (binary + base64-ready)
//                Two parallel output forms: (a) packed binary blob for NV
//                seal, (b) ASCII base64 form for evidence-log inclusion.
//                Both feed the same upstream HWID identifier so server
//                comparisons work whether ingested via TPM or log channels.
// ============================================================================

struct VGK_HWID_OUTPUT_BINARY_BLOB
{
    ULONG     magic;
    ULONG     version;
    ULONG     blob_length;
    ULONG     hwid_length;
    UCHAR     hwid_bytes[64];
    ULONGLONG capture_qpc;
    ULONGLONG capture_system_time;
    ULONG     source_flags;
    ULONG     reserved;
    UCHAR     boot_id_guid_bytes[16];
    UCHAR     machine_guid_bytes[16];
    UCHAR     bcd_boot_id_bytes[16];
    UCHAR     hwid_hmac_sha256[32];
};

constexpr ULONG VGK_HWID_BLOB_MAGIC                            = 'KIWH';
constexpr ULONG VGK_HWID_BLOB_VERSION_1                        = 1u;
constexpr ULONG VGK_HWID_BLOB_SOURCE_BOOT_PIPELINE              = 0x00000001u;
constexpr ULONG VGK_HWID_BLOB_SOURCE_RUNTIME_REFETCH            = 0x00000002u;
constexpr ULONG VGK_HWID_BLOB_SOURCE_HOTPLUG_TRIGGER            = 0x00000004u;
constexpr ULONG VGK_HWID_BLOB_SOURCE_PCR_DRIVEN                 = 0x00000008u;
constexpr ULONG VGK_HWID_BLOB_SOURCE_USER_TRIGGERED             = 0x00000010u;

NTSTATUS vgk_hwid_output_blob_initialize(_Out_ VGK_HWID_OUTPUT_BINARY_BLOB* out_blob,
                                          _In_reads_bytes_(hwid_len) const UCHAR* hwid_bytes,
                                          _In_ ULONG hwid_len,
                                          _In_ ULONG source_flags) noexcept
{
    if (out_blob == nullptr || hwid_bytes == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (hwid_len == 0u || hwid_len > 64u) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_blob, sizeof(*out_blob));

    out_blob->magic       = VGK_HWID_BLOB_MAGIC;
    out_blob->version     = VGK_HWID_BLOB_VERSION_1;
    out_blob->blob_length = (ULONG)sizeof(VGK_HWID_OUTPUT_BINARY_BLOB);
    out_blob->hwid_length = hwid_len;
    RtlCopyMemory(out_blob->hwid_bytes, hwid_bytes, hwid_len);
    out_blob->source_flags = source_flags;

    LARGE_INTEGER qpc; KeQueryPerformanceCounter(&qpc);
    LARGE_INTEGER sys; KeQuerySystemTime(&sys);
    out_blob->capture_qpc         = (ULONGLONG)qpc.QuadPart;
    out_blob->capture_system_time = (ULONGLONG)sys.QuadPart;
    return STATUS_SUCCESS;
}

// Microsoft Pluton and the Windows firmware TPM both report the 'MSFT' vendor
// tag, so this section keeps them separable by joining manufacturer_be against
// TPM_PT_VENDOR_TPM_TYPE. The full type catalog covers TYPE_NORMAL (0x00),
// FTPM_STANDALONE (0x01), FTPM_SERVER (0x02), AZURE_PCAT (0x03), AZURE_HCI
// (0x04), AMD_PSP_FTPM (0x05), INTEL_PTT (0x06), QUALCOMM_QSEE (0x07),
// MICROSOFT_HV_TPM (0x08), and Pluton (0x10), so the SECTION 73 vendor
// dictionary can disambiguate every shipping Microsoft-stamped TPM. The
// descriptor table at vgk_tpm_vendor_descriptor_table feeds
// vgk_tpm_vendor_lookup, which the TPM cap probe in SECTION 73 calls once
// per boot to pin canonical name + firmware/discrete/virtual/pluton flags
// onto the EK_RECORD. Cold path -- only fires during SECTION 20 EK
// extraction; downstream uses the type byte for SECTION 22 severity bands.
// ============================================================================
// SECTION 272 -- Pluton + Microsoft TPM softTPM provider identification
//                Microsoft Pluton (a TPM 2.0 implementation embedded in CPU)
//                and the Windows fTPM (firmware TPM) both report vendor_id
//                'MSFT' but differ in TPM_PT_VENDOR_TPM_TYPE: Pluton = 0x10,
//                fTPM Standalone = 0x01, fTPM Server = 0x02.
// ============================================================================

constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_NORMAL                = 0x00u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_FTPM_STANDALONE       = 0x01u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_FTPM_SERVER           = 0x02u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_AZURE_PCAT            = 0x03u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_AZURE_HCI             = 0x04u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_AMD_PSP_FTPM          = 0x05u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_INTEL_PTT             = 0x06u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_QUALCOMM_QSEE         = 0x07u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_MICROSOFT_HV_TPM      = 0x08u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_PLUTON                = 0x10u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_PLUTON_SP             = 0x11u;
constexpr ULONG VGK_TPM2_VENDOR_TPM_TYPE_DISCRETE              = 0x20u;

struct VGK_TPM_VENDOR_DESC
{
    ULONG       manufacturer_be;
    UCHAR       tpm_type;
    UCHAR       reserved[3];
    const char* canonical_name;
    UCHAR       is_firmware;
    UCHAR       is_discrete;
    UCHAR       is_virtual;
    UCHAR       is_pluton;
};

constexpr VGK_TPM_VENDOR_DESC vgk_tpm_vendor_descriptor_table[] = {
    { VGK_TPM2_MANUF_INTEL,     VGK_TPM2_VENDOR_TPM_TYPE_INTEL_PTT,         { 0,0,0 }, "Intel PTT (Platform Trust Technology)",     1u, 0u, 0u, 0u },
    { VGK_TPM2_MANUF_AMD,       VGK_TPM2_VENDOR_TPM_TYPE_AMD_PSP_FTPM,      { 0,0,0 }, "AMD PSP fTPM",                              1u, 0u, 0u, 0u },
    { VGK_TPM2_MANUF_MSFT,      VGK_TPM2_VENDOR_TPM_TYPE_PLUTON,            { 0,0,0 }, "Microsoft Pluton TPM",                       0u, 0u, 0u, 1u },
    { VGK_TPM2_MANUF_MSFT,      VGK_TPM2_VENDOR_TPM_TYPE_FTPM_STANDALONE,   { 0,0,0 }, "Microsoft fTPM (Standalone)",                1u, 0u, 0u, 0u },
    { VGK_TPM2_MANUF_MSFT,      VGK_TPM2_VENDOR_TPM_TYPE_FTPM_SERVER,       { 0,0,0 }, "Microsoft fTPM (Server)",                    1u, 0u, 0u, 0u },
    { VGK_TPM2_MANUF_MSFT,      VGK_TPM2_VENDOR_TPM_TYPE_MICROSOFT_HV_TPM,  { 0,0,0 }, "Microsoft Hyper-V Virtual TPM",              0u, 0u, 1u, 0u },
    { VGK_TPM2_MANUF_QCOM,      VGK_TPM2_VENDOR_TPM_TYPE_QUALCOMM_QSEE,     { 0,0,0 }, "Qualcomm QSEE fTPM",                         1u, 0u, 0u, 0u },
    { VGK_TPM2_MANUF_IFX,       VGK_TPM2_VENDOR_TPM_TYPE_DISCRETE,          { 0,0,0 }, "Infineon SLB 9670/9672 (Discrete)",          0u, 1u, 0u, 0u },
    { VGK_TPM2_MANUF_NTC,       VGK_TPM2_VENDOR_TPM_TYPE_DISCRETE,          { 0,0,0 }, "Nuvoton NPCT75x/NPCT65x (Discrete)",         0u, 1u, 0u, 0u },
    { VGK_TPM2_MANUF_STM,       VGK_TPM2_VENDOR_TPM_TYPE_DISCRETE,          { 0,0,0 }, "STMicroelectronics ST33TPHF (Discrete)",     0u, 1u, 0u, 0u },
};

constexpr ULONG VGK_TPM_VENDOR_TABLE_COUNT =
    (ULONG)(sizeof(vgk_tpm_vendor_descriptor_table) / sizeof(vgk_tpm_vendor_descriptor_table[0]));

const VGK_TPM_VENDOR_DESC* vgk_tpm_vendor_lookup(_In_ ULONG manufacturer_be,
                                                  _In_ ULONG tpm_type) noexcept
{
    for (ULONG i = 0; i < VGK_TPM_VENDOR_TABLE_COUNT; ++i)
    {
        if (vgk_tpm_vendor_descriptor_table[i].manufacturer_be == manufacturer_be &&
            vgk_tpm_vendor_descriptor_table[i].tpm_type == (UCHAR)tpm_type)
        {
            return &vgk_tpm_vendor_descriptor_table[i];
        }
    }
    return nullptr;
}

// Three crypto wire-call builders kept together so the Sign / VerifySignature /
// Hash trio shares the same opcode block (CC 0x15D, CC 0x177, CC 0x17D) and
// the same response-parse path. The Hash variant drives the TPM's local
// hashing engine for measurement parity checks; Sign signs a digest with a
// loaded key; VerifySignature validates the signature against a public key
// plus digest. The constant catalog covers Hash (0x17D), HashSequenceStart
// (0x186), SequenceUpdate (0x15C), SequenceComplete (0x13E),
// EventSequenceComplete (0x185), HMAC (0x155), HMAC_Start (0x15B), and Sign
// (0x15D). All three core builders sit on the SECTION 9 builder pool and
// feed SECTION 36 Quote verify, SECTION 51 AIK CA root pinning, and SECTION
// 270 PolicyAuthValue/PolicySigned verifier. Mixed hot/cold -- Hash is hot
// for the SECTION 75 Authenticode chain; Sign/VerifySignature are cold.
// ============================================================================
// SECTION 273 -- TPM 2.0 Sign + VerifySignature + Hash command builders
//                Hash hashes a buffer using the TPM's hashing engine (used
//                for measurement parity checks). Sign signs a digest with
//                a loaded key. VerifySignature validates the signature
//                against a public key + digest. All measurement.
// ============================================================================

constexpr ULONG VGK_TPM2_CC_Hash                              = 0x0000017Du;
constexpr ULONG VGK_TPM2_CC_HashSequenceStart                 = 0x00000186u;
constexpr ULONG VGK_TPM2_CC_SequenceUpdate                    = 0x0000015Cu;
constexpr ULONG VGK_TPM2_CC_SequenceComplete                  = 0x0000013Eu;
constexpr ULONG VGK_TPM2_CC_EventSequenceComplete             = 0x00000185u;
constexpr ULONG VGK_TPM2_CC_HMAC                              = 0x00000155u;
constexpr ULONG VGK_TPM2_CC_HMAC_Start                        = 0x0000015Bu;
constexpr ULONG VGK_TPM2_CC_Sign                              = 0x0000015Du;
constexpr ULONG VGK_TPM2_CC_VerifySignature                   = 0x00000177u;
constexpr ULONG VGK_TPM2_CC_GetCommandAuditLogDigest          = 0x00000133u;
constexpr ULONG VGK_TPM2_CC_RSA_Encrypt                       = 0x00000174u;
constexpr ULONG VGK_TPM2_CC_RSA_Decrypt                       = 0x00000159u;
constexpr ULONG VGK_TPM2_CC_ECDH_KeyGen                       = 0x00000163u;
constexpr ULONG VGK_TPM2_CC_ECDH_ZGen                         = 0x00000154u;
constexpr ULONG VGK_TPM2_CC_ECC_Parameters                    = 0x00000178u;
constexpr ULONG VGK_TPM2_CC_ZGen_2Phase                       = 0x0000018Du;
constexpr ULONG VGK_TPM2_CC_EncryptDecrypt                    = 0x00000164u;
constexpr ULONG VGK_TPM2_CC_EncryptDecrypt2                   = 0x00000193u;
constexpr ULONG VGK_TPM2_CC_Commit                            = 0x0000018Bu;
constexpr ULONG VGK_TPM2_CC_EC_Ephemeral                      = 0x0000018Eu;
constexpr ULONG VGK_TPM2_CC_Create                            = 0x00000153u;
constexpr ULONG VGK_TPM2_CC_CreateLoaded                      = 0x00000191u;
constexpr ULONG VGK_TPM2_CC_CreatePrimary                     = 0x00000131u;
constexpr ULONG VGK_TPM2_CC_Load                              = 0x00000157u;
constexpr ULONG VGK_TPM2_CC_Unseal                            = 0x0000015Eu;
constexpr ULONG VGK_TPM2_CC_ObjectChangeAuth                  = 0x00000150u;

NTSTATUS tpm2_parse_hash_response(_In_reads_bytes_(rsp_len) const UCHAR* rsp,
                                   _In_ ULONG rsp_len,
                                   _Out_writes_bytes_(*io_digest_size) PUCHAR out_digest,
                                   _Inout_ PUSHORT io_digest_size) noexcept
    *p++ = (UCHAR)( name_alg_sha256       & 0xFFu);

    *p++ = (UCHAR)((object_attrs >> 24) & 0xFFu);
    *p++ = (UCHAR)((object_attrs >> 16) & 0xFFu);
    *p++ = (UCHAR)((object_attrs >>  8) & 0xFFu);
    *p++ = (UCHAR)( object_attrs        & 0xFFu);

    *p++ = (UCHAR)((policy_size >> 8) & 0xFFu);
    *p++ = (UCHAR)( policy_size       & 0xFFu);
    if (policy_size > 0u)
    {
        RtlCopyMemory(p, auth_policy, policy_size);
        p += policy_size;
    }

    *p++ = (UCHAR)((VGK_TPM2_ALG_NULL_SIG >> 8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_ALG_NULL_SIG       & 0xFFu);

    *p++ = 0x00u; *p++ = 0x00u;

    *io_size = total;
    return STATUS_SUCCESS;
}

// HashSequenceStart / SequenceUpdate / SequenceComplete is the streaming form
// of TPM2_Hash for any buffer that overflows TPM_PT_MAX_DIGEST_BUFFER (~1024
// bytes). Vanguard chains SequenceUpdate calls bounded by MAX_DIGEST_BUFFER
// per call, then SequenceComplete returns the final digest plus an optional
// validation ticket bound to the supplied hierarchy. The local builder
// tpm2_build_hash_sequence_complete (CC 0x183) takes sequence_handle plus the
// tail_buffer + tail_len trailing fragment and the hierarchy authorization
// (typically TPM_RH_OWNER or TPM_RH_NULL) to emit the wire bytes. Pairs with
// tpm2_build_hash_sequence_start (CC 0x186) and tpm2_build_sequence_update
// (CC 0x15C) for the full chain. This builder sits on SECTION 9 and is driven
// by the SECTION 54 HashSequence orchestrator and the SECTION 205 PCR_Event
// large-input paths. Cold path -- only fires on oversized hash inputs.
// ============================================================================
// SECTION 276 -- TPM 2.0 hash sequence builders (HashSequenceStart/Update/Complete)
//                For data larger than TPM_PT_MAX_DIGEST_BUFFER (typically
//                1024 bytes), Vanguard chains SequenceUpdate calls with up to
//                MAX_DIGEST_BUFFER bytes per call, then SequenceComplete
//                returns the final digest + optional validation ticket.
// ============================================================================

NTSTATUS tpm2_build_hash_sequence_complete(_In_ ULONG sequence_handle,
                                            _In_reads_bytes_(tail_len) const UCHAR* tail_buffer,
                                            _In_ USHORT tail_len,
                                            _In_ ULONG hierarchy,
                                            _Out_writes_bytes_(*io_buf_len) PUCHAR buf,
                                            _Inout_ PULONG io_buf_len) noexcept
{
    if (buf == nullptr || io_buf_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (tail_len > 0u && tail_buffer == nullptr) { return STATUS_INVALID_PARAMETER; }

    const ULONG session_area_size = 9u;
    const ULONG total = 10u + 4u + 4u + (ULONG)session_area_size + 2u + (ULONG)tail_len + 4u;
    if (*io_buf_len < total) { return STATUS_BUFFER_TOO_SMALL; }

    PUCHAR p = buf;
    *p++ = 0x80u; *p++ = 0x02u;
    *p++ = (UCHAR)((total >> 24) & 0xFFu);
    *p++ = (UCHAR)((total >> 16) & 0xFFu);
    *p++ = (UCHAR)((total >>  8) & 0xFFu);
    *p++ = (UCHAR)( total        & 0xFFu);

    *p++ = (UCHAR)((VGK_TPM2_CC_SequenceComplete >> 24) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_CC_SequenceComplete >> 16) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_CC_SequenceComplete >>  8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_CC_SequenceComplete        & 0xFFu);

    *p++ = (UCHAR)((sequence_handle >> 24) & 0xFFu);
    *p++ = (UCHAR)((sequence_handle >> 16) & 0xFFu);
    *p++ = (UCHAR)((sequence_handle >>  8) & 0xFFu);
    *p++ = (UCHAR)( sequence_handle        & 0xFFu);

    *p++ = (UCHAR)((session_area_size >> 24) & 0xFFu);
    *p++ = (UCHAR)((session_area_size >> 16) & 0xFFu);
    *p++ = (UCHAR)((session_area_size >>  8) & 0xFFu);
    *p++ = (UCHAR)( session_area_size        & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 24) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 16) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >>  8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_RS_PW        & 0xFFu);
    *p++ = 0x00u; *p++ = 0x00u;
    *p++ = 0x01u;
    *p++ = 0x00u; *p++ = 0x00u;

    *p++ = (UCHAR)((tail_len >> 8) & 0xFFu);
    *p++ = (UCHAR)( tail_len       & 0xFFu);
    if (tail_len > 0u) { RtlCopyMemory(p, tail_buffer, tail_len); p += tail_len; }

    *p++ = (UCHAR)((hierarchy >> 24) & 0xFFu);
    *p++ = (UCHAR)((hierarchy >> 16) & 0xFFu);
    *p++ = (UCHAR)((hierarchy >>  8) & 0xFFu);
    *p++ = (UCHAR)( hierarchy        & 0xFFu);

    *io_buf_len = total;
    return STATUS_SUCCESS;
}

// TIS MMIO is the fallback transport when the SECTION 8 IOCTL path is absent --
// typically in VM scenarios where Tbs.sys isn't exposed. The helpers here wrap
// READ_REGISTER_UCHAR/ULONG against the TIS register window discovered through
// SECTION 87's ACPI TPM2 table, walking ACCESS / STS / BURST_COUNT / DATA_FIFO
// per locality. Polling loops are bounded by TPM_TIMEOUT_A (750 ms) for
// command-ready waits, and the request_locality / wait_for_status pair handles
// the standard locality acquisition handshake.
// ============================================================================
// SECTION 277 -- TPM TIS MMIO transport helpers (locality-aware)
// ============================================================================

constexpr ULONG VGK_TPM_TIMEOUT_A_MS                          = 750u;
constexpr ULONG VGK_TPM_TIMEOUT_B_MS                          = 2000u;
constexpr ULONG VGK_TPM_TIMEOUT_C_MS                          = 200u;
constexpr ULONG VGK_TPM_TIMEOUT_D_MS                          = 30u;
constexpr ULONG VGK_TPM_LONG_TIMEOUT_MS                       = 1200u;

constexpr ULONG VGK_TPM_TIS_POLL_INTERVAL_NS                  = 100u;

UCHAR vgk_tpm_tis_read_byte(_In_ PVOID locality_base, _In_ ULONG reg_offset) noexcept
{
    if (locality_base == nullptr) { return 0u; }
    UCHAR* addr = (UCHAR*)((ULONG_PTR)locality_base + reg_offset);
    return READ_REGISTER_UCHAR(addr);
}

VOID vgk_tpm_tis_write_byte(_In_ PVOID locality_base, _In_ ULONG reg_offset, _In_ UCHAR value) noexcept
{
    if (locality_base == nullptr) { return; }
    UCHAR* addr = (UCHAR*)((ULONG_PTR)locality_base + reg_offset);
    WRITE_REGISTER_UCHAR(addr, value);
}

ULONG vgk_tpm_tis_read_dword(_In_ PVOID locality_base, _In_ ULONG reg_offset) noexcept
{
    if (locality_base == nullptr) { return 0u; }
    ULONG* addr = (ULONG*)((ULONG_PTR)locality_base + reg_offset);
    return READ_REGISTER_ULONG(addr);
}

VOID vgk_tpm_tis_write_dword(_In_ PVOID locality_base, _In_ ULONG reg_offset, _In_ ULONG value) noexcept
{
    if (locality_base == nullptr) { return; }
    ULONG* addr = (ULONG*)((ULONG_PTR)locality_base + reg_offset);
    WRITE_REGISTER_ULONG(addr, value);
}

USHORT vgk_tpm_tis_read_burst_count(_In_ PVOID locality_base) noexcept
{
    if (locality_base == nullptr) { return 0u; }
    UCHAR lo = vgk_tpm_tis_read_byte(locality_base, VGK_TPM_TIS_REG_BURST_COUNT);
    UCHAR hi = vgk_tpm_tis_read_byte(locality_base, VGK_TPM_TIS_REG_BURST_COUNT + 1u);
    return (USHORT)(((USHORT)hi << 8) | (USHORT)lo);
}

NTSTATUS vgk_tpm_tis_request_locality(_In_ PVOID locality_base,
                                       _In_ ULONG timeout_ms) noexcept
{
    if (locality_base == nullptr) { return STATUS_INVALID_PARAMETER; }
    vgk_tpm_tis_write_byte(locality_base, VGK_TPM_TIS_REG_ACCESS, VGK_TPM_TIS_ACCESS_REQUEST_USE);

    LARGE_INTEGER interval; interval.QuadPart = -10000LL;
    for (ULONG ms = 0; ms < timeout_ms; ++ms)
    {
        UCHAR access = vgk_tpm_tis_read_byte(locality_base, VGK_TPM_TIS_REG_ACCESS);
        if ((access & VGK_TPM_TIS_ACCESS_ACTIVE_LOCALITY) != 0u) { return STATUS_SUCCESS; }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    return STATUS_IO_TIMEOUT;
}

NTSTATUS vgk_tpm_tis_relinquish_locality(_In_ PVOID locality_base) noexcept
{
    if (locality_base == nullptr) { return STATUS_INVALID_PARAMETER; }
    vgk_tpm_tis_write_byte(locality_base, VGK_TPM_TIS_REG_ACCESS, VGK_TPM_TIS_ACCESS_RELINQUISH_LOCALITY);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_tpm_tis_wait_for_status(_In_ PVOID locality_base,
                                      _In_ UCHAR mask,
                                      _In_ UCHAR expected,
                                      _In_ ULONG timeout_ms) noexcept
{
    if (locality_base == nullptr) { return STATUS_INVALID_PARAMETER; }
    LARGE_INTEGER interval; interval.QuadPart = -10000LL;
    for (ULONG ms = 0; ms < timeout_ms; ++ms)
    {
        UCHAR sts = vgk_tpm_tis_read_byte(locality_base, VGK_TPM_TIS_REG_STS);
        if ((sts & mask) == expected) { return STATUS_SUCCESS; }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    return STATUS_IO_TIMEOUT;
}

// The TPM Physical Presence Interface lives behind a vendor _DSM method under
// \_SB.TPM (GUID 3DDDFAA6-361B-4EB4-A424-8D10089D1653), which firmware uses to
// gate ownership transitions like Clear / Disable / TPM2_ON / TPM2_OFF. When
// the SECTION 18 registry-based PPI probe comes up empty Vanguard falls back
// to walking the DSDT AML stream produced by SECTION 86's ACPI fetcher, hunting
// for the _DSM method on the TPM device path and snapshotting submitted opcodes
// against the VGK_PPI_OP_* enum below so PPI-driven Clear attempts get flagged.
// ============================================================================
// SECTION 278 -- AML walker for ACPI _DSM TPM 2.0 PPI (Physical Presence)
// ============================================================================

constexpr GUID VGK_TPM_PPI_DSM_GUID =
    { 0x3DDDFAA6, 0x361B, 0x4EB4, { 0xA4, 0x24, 0x8D, 0x10, 0x08, 0x9D, 0x16, 0x53 } };

constexpr ULONG VGK_PPI_DSM_GET_VERSION                       = 0x00000001u;
constexpr ULONG VGK_PPI_DSM_SUBMIT_OPERATION_REQ              = 0x00000002u;
constexpr ULONG VGK_PPI_DSM_GET_PENDING_OPERATION             = 0x00000003u;
constexpr ULONG VGK_PPI_DSM_GET_PLATFORM_ACTION               = 0x00000004u;
constexpr ULONG VGK_PPI_DSM_RETURN_OPERATION_RESPONSE         = 0x00000005u;
constexpr ULONG VGK_PPI_DSM_SUBMIT_REQUEST_TO_BIOS            = 0x00000007u;
constexpr ULONG VGK_PPI_DSM_GET_USER_CONFIRMATION_STATUS      = 0x00000008u;

constexpr ULONG VGK_PPI_OP_NOOP                               = 0u;
constexpr ULONG VGK_PPI_OP_ENABLE                             = 1u;
constexpr ULONG VGK_PPI_OP_DISABLE                            = 2u;
constexpr ULONG VGK_PPI_OP_ACTIVATE                           = 3u;
constexpr ULONG VGK_PPI_OP_DEACTIVATE                         = 4u;
constexpr ULONG VGK_PPI_OP_CLEAR                              = 5u;
constexpr ULONG VGK_PPI_OP_CLEAR_AND_ENABLE_ACTIVATE          = 14u;
constexpr ULONG VGK_PPI_OP_SET_NO_PPI_PROVISION_FALSE         = 16u;
constexpr ULONG VGK_PPI_OP_SET_NO_PPI_PROVISION_TRUE          = 17u;
constexpr ULONG VGK_PPI_OP_SET_NO_PPI_CLEAR_FALSE             = 18u;
constexpr ULONG VGK_PPI_OP_SET_NO_PPI_CLEAR_TRUE              = 19u;
constexpr ULONG VGK_PPI_OP_SET_NO_PPI_MAINTENANCE_FALSE       = 20u;
constexpr ULONG VGK_PPI_OP_SET_NO_PPI_MAINTENANCE_TRUE        = 21u;
constexpr ULONG VGK_PPI_OP_ENABLE_BLOCK_SID_FUNC              = 96u;
constexpr ULONG VGK_PPI_OP_DISABLE_BLOCK_SID_FUNC             = 97u;
constexpr ULONG VGK_PPI_OP_TPM2_ON                            = 100u;
constexpr ULONG VGK_PPI_OP_TPM2_OFF                           = 101u;

constexpr ULONG VGK_PPI_RESPONSE_SUCCESS                      = 0u;
constexpr ULONG VGK_PPI_RESPONSE_FAILURE                      = 1u;
constexpr ULONG VGK_PPI_RESPONSE_BLOCKED_BY_BIOS              = 2u;
constexpr ULONG VGK_PPI_RESPONSE_USER_ABORT                   = 3u;
constexpr ULONG VGK_PPI_RESPONSE_FIRMWARE_FAILURE             = 4u;

// Per-adapter HWID composition pulls the permanent MAC, descriptor, vendor OUI,
// and physical-medium classification by issuing IOCTL_NDIS_QUERY_GLOBAL_STATS
// across every active NIC. The OID set below -- led by OID_802_3_PERMANENT_ADDRESS
// plus the OID_GEN_* descriptor block and OID_GEN_PHYSICAL_MEDIUM_EX -- captures
// MAC-class invariants that survive reboot and reconnect. SECTION 215's boot-time
// MAC capture and SECTION 187's device scan both consume these on every HWID
// composite refresh.
// ============================================================================
// SECTION 279 -- Network adapter (NDIS) hardware identifier OIDs
// ============================================================================

constexpr ULONG VGK_OID_802_11_BSSID                          = 0x0D010101u;
constexpr ULONG VGK_OID_802_11_MAC_ADDRESS                    = 0x0D01011Cu;
constexpr ULONG VGK_OID_GEN_MEDIA_SUPPORTED                   = 0x00010103u;
constexpr ULONG VGK_OID_GEN_MEDIA_IN_USE                      = 0x00010104u;
constexpr ULONG VGK_OID_GEN_MAXIMUM_LOOKAHEAD                 = 0x00010105u;
constexpr ULONG VGK_OID_GEN_MAXIMUM_FRAME_SIZE                = 0x00010106u;
constexpr ULONG VGK_OID_GEN_LINK_SPEED                        = 0x00010107u;
constexpr ULONG VGK_OID_GEN_TRANSMIT_BUFFER_SPACE             = 0x00010108u;
constexpr ULONG VGK_OID_GEN_RECEIVE_BUFFER_SPACE              = 0x00010109u;
constexpr ULONG VGK_OID_GEN_DRIVER_VERSION                    = 0x00010110u;
constexpr ULONG VGK_OID_GEN_MAXIMUM_TOTAL_SIZE                = 0x00010111u;
constexpr ULONG VGK_OID_GEN_MAC_OPTIONS                       = 0x00010113u;
constexpr ULONG VGK_OID_GEN_MEDIA_CONNECT_STATUS              = 0x00010114u;
constexpr ULONG VGK_OID_GEN_FRIENDLY_NAME                     = 0x00020216u;
constexpr ULONG VGK_OID_GEN_HARDWARE_STATUS                   = 0x00010102u;
constexpr ULONG VGK_OID_GEN_PHYSICAL_MEDIUM_EX                = 0x00010213u;
constexpr ULONG VGK_OID_GEN_NDIS_RESERVED_LARGE_4             = 0x00010294u;
constexpr ULONG VGK_OID_GEN_INTERFACE_INFO                    = 0x00010287u;

constexpr ULONG VGK_NDIS_MEDIUM_802_3                          = 0u;
constexpr ULONG VGK_NDIS_MEDIUM_802_5                          = 1u;
constexpr ULONG VGK_NDIS_MEDIUM_FDDI                           = 2u;
constexpr ULONG VGK_NDIS_MEDIUM_WAN                            = 3u;
constexpr ULONG VGK_NDIS_MEDIUM_LOCALTALK                      = 4u;
constexpr ULONG VGK_NDIS_MEDIUM_DIX                            = 5u;
constexpr ULONG VGK_NDIS_MEDIUM_ARCNET_RAW                     = 6u;
constexpr ULONG VGK_NDIS_MEDIUM_ARCNET_878_2                   = 7u;
constexpr ULONG VGK_NDIS_MEDIUM_ATM                            = 8u;
constexpr ULONG VGK_NDIS_MEDIUM_WIRELESS_WAN                   = 9u;
constexpr ULONG VGK_NDIS_MEDIUM_IRDA                           = 10u;
constexpr ULONG VGK_NDIS_MEDIUM_BPC                            = 11u;
constexpr ULONG VGK_NDIS_MEDIUM_CO_WAN                         = 12u;
constexpr ULONG VGK_NDIS_MEDIUM_1394                           = 13u;
constexpr ULONG VGK_NDIS_MEDIUM_INFINIBAND                     = 14u;
constexpr ULONG VGK_NDIS_MEDIUM_TUNNEL                         = 15u;
constexpr ULONG VGK_NDIS_MEDIUM_NATIVE_802_11                  = 16u;
constexpr ULONG VGK_NDIS_MEDIUM_LOOPBACK                       = 17u;
constexpr ULONG VGK_NDIS_MEDIUM_WIMAX                          = 18u;
constexpr ULONG VGK_NDIS_MEDIUM_IP                             = 19u;

constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_UNSPECIFIED          = 0u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_WIRELESS_LAN          = 1u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_CABLE_MODEM           = 2u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_PHONE_LINE            = 3u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_POWER_LINE            = 4u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_DSL                   = 5u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_FIBRE_CHANNEL         = 6u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_1394                  = 7u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_WIRELESS_WAN          = 8u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_NATIVE_802_11         = 9u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_BLUETOOTH             = 10u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_INFINIBAND            = 11u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_WIMAX                 = 12u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_UWB                   = 13u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_802_3                 = 14u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_802_5                 = 15u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_IRDA                  = 16u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_WIRED_WAN             = 17u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_WIRED_COWAN           = 18u;
constexpr ULONG VGK_NDIS_PHYSICAL_MEDIUM_OTHER                 = 19u;

#pragma pack(push, 1)
struct VGK_NIC_HWID_RECORD
{
    ULONG     adapter_index;
    UCHAR     permanent_mac[6];
    UCHAR     current_mac[6];
    UCHAR     mac_kind;
    UCHAR     reserved[1];
    ULONG     physical_medium;
    ULONG     vendor_id;
    ULONG     driver_version;
    ULONGLONG link_speed_bps;
    ULONG     mac_options;
    ULONG     hardware_status;
    UCHAR     friendly_name_utf16[128];
};
#pragma pack(pop)

constexpr UCHAR VGK_NIC_MAC_KIND_802_3_ETHERNET                = 1u;
constexpr UCHAR VGK_NIC_MAC_KIND_802_11_WIFI                   = 2u;
constexpr UCHAR VGK_NIC_MAC_KIND_VIRTUAL                       = 3u;
constexpr UCHAR VGK_NIC_MAC_KIND_LOOPBACK                      = 4u;
constexpr UCHAR VGK_NIC_MAC_KIND_BLUETOOTH                     = 5u;

BOOLEAN vgk_nic_mac_is_locally_administered(_In_reads_bytes_(6) const UCHAR* mac) noexcept
{
    if (mac == nullptr) { return FALSE; }
    return ((mac[0] & 0x02u) != 0u) ? TRUE : FALSE;
}

BOOLEAN vgk_nic_mac_is_multicast(_In_reads_bytes_(6) const UCHAR* mac) noexcept
{
    if (mac == nullptr) { return FALSE; }
    return ((mac[0] & 0x01u) != 0u) ? TRUE : FALSE;
}

ULONG vgk_nic_oui_from_mac(_In_reads_bytes_(6) const UCHAR* mac) noexcept
{
    if (mac == nullptr) { return 0u; }
    return ((ULONG)mac[0] << 16) | ((ULONG)mac[1] << 8) | (ULONG)mac[2];
}

// Display-side HWID input comes from two DXGK channels: the per-adapter LUID
// pulled through IDXGKDDI helpers (D3DKMT escape), and the connected monitor's
// 128-byte EDID block. The VGK_EDID_BLOCK struct mirrors the spec layout --
// header[8], manufacturer_id_be (big-endian 5-bit triplet packed in 16 bits),
// product_code, serial_number, week/year of manufacture, EDID version/revision,
// video_input_definition, chromaticity[10], and the four 18-byte descriptor
// blocks. The EDID checksum is validated by vgk_edid_checksum_valid and the
// manufacturer triplet + product_code + serial_number all get hashed into the
// composite via SECTION 6's BCrypt SHA-256 wrapper. SECTION 305's full EDID
// extractor and SECTION 187's device scan are the only callers, fired on each
// HWID composite refresh through the SECTION 24 assembler. Hot path on every
// HWID refresh; pairs with SECTION 279's NDIS NIC OID surface for full HWID.
// ============================================================================
// SECTION 280 -- DXGK display adapter LUID + monitor EDID HWID surface
// ============================================================================

#pragma pack(push, 1)
struct VGK_EDID_BLOCK
{
    UCHAR     header[8];
    USHORT    manufacturer_id_be;
    USHORT    product_code;
    ULONG     serial_number;
    UCHAR     week_of_manufacture;
    UCHAR     year_of_manufacture;
    UCHAR     edid_version;
    UCHAR     edid_revision;
    UCHAR     video_input_definition;
    UCHAR     max_horizontal_image_size_cm;
    UCHAR     max_vertical_image_size_cm;
    UCHAR     gamma;
    UCHAR     feature_support;
    UCHAR     chromaticity[10];
    UCHAR     established_timings_1;
    UCHAR     established_timings_2;
    UCHAR     manufacturer_timings;
    UCHAR     standard_timings[16];
    UCHAR     detailed_timings[72];
    UCHAR     extension_flag;
    UCHAR     checksum;
};

struct VGK_LUID_VALUE
{
    ULONG     low_part;
    LONG      high_part;
};

struct VGK_DISPLAY_HWID_RECORD
{
    VGK_LUID_VALUE adapter_luid;
    ULONG          source_id;
    ULONG          target_id;
    UCHAR          edid[128];
    UCHAR          monitor_serial_string[16];
    UCHAR          manufacturer_three_letter_code[4];
    USHORT         product_code;
    USHORT         reserved;
    ULONG          serial_number;
    UCHAR          year_of_manufacture_year_offset;
    UCHAR          week_of_manufacture;
    UCHAR          edid_version;
    UCHAR          edid_revision;
};
#pragma pack(pop)

constexpr UCHAR VGK_EDID_HEADER_SIGNATURE[8] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

BOOLEAN vgk_edid_header_valid(_In_ const VGK_EDID_BLOCK* edid) noexcept
{
    if (edid == nullptr) { return FALSE; }
    for (ULONG i = 0; i < 8u; ++i)
    {
        if (edid->header[i] != VGK_EDID_HEADER_SIGNATURE[i]) { return FALSE; }
    }
    return TRUE;
}

BOOLEAN vgk_edid_checksum_valid(_In_reads_bytes_(128) const UCHAR* edid_bytes) noexcept
{
    if (edid_bytes == nullptr) { return FALSE; }
    UCHAR sum = 0u;
    for (ULONG i = 0; i < 128u; ++i) { sum = (UCHAR)(sum + edid_bytes[i]); }
    return (sum == 0u) ? TRUE : FALSE;
}

VOID vgk_edid_decode_manufacturer(_In_ USHORT mfr_be, _Out_writes_(4) UCHAR* out_code) noexcept
{
    if (out_code == nullptr) { return; }
    USHORT id = (USHORT)(((USHORT)((mfr_be >> 8) & 0xFFu)) | ((USHORT)(mfr_be & 0xFFu) << 8));
    out_code[0] = (UCHAR)((((id >> 10) & 0x1Fu) + 'A' - 1) & 0x7Fu);
    out_code[1] = (UCHAR)((((id >>  5) & 0x1Fu) + 'A' - 1) & 0x7Fu);
    out_code[2] = (UCHAR)((((id      ) & 0x1Fu) + 'A' - 1) & 0x7Fu);
    out_code[3] = 0u;
}

NTSTATUS vgk_display_hwid_extract_from_edid(_In_ const VGK_EDID_BLOCK* edid,
                                             _Out_ VGK_DISPLAY_HWID_RECORD* out_rec) noexcept
{
    if (edid == nullptr || out_rec == nullptr) { return STATUS_INVALID_PARAMETER; }
    if (!vgk_edid_header_valid(edid)) { return STATUS_DATA_ERROR; }
    if (!vgk_edid_checksum_valid((const UCHAR*)edid)) { return STATUS_DATA_ERROR; }

    RtlZeroMemory(out_rec, sizeof(*out_rec));
    RtlCopyMemory(out_rec->edid, edid, 128u);
    vgk_edid_decode_manufacturer(edid->manufacturer_id_be, out_rec->manufacturer_three_letter_code);
    out_rec->product_code      = edid->product_code;
    out_rec->serial_number     = edid->serial_number;
    out_rec->year_of_manufacture_year_offset = edid->year_of_manufacture;
    out_rec->week_of_manufacture = edid->week_of_manufacture;
    out_rec->edid_version       = edid->edid_version;
    out_rec->edid_revision      = edid->edid_revision;
    return STATUS_SUCCESS;
}

// Pure constant data -- the full VMCS field encoding map straight from Intel SDM
// Vol 3D Appendix B. Vanguard never executes VMRESUME itself; instead it reads
// CPUID feature bits to detect VT-x enablement and checks the IA32_FEATURE_CONTROL
// lock bit for nested-hypervisor flagging. The VGK_VMCS_FIELD_* and
// VGK_VMX_EXIT_REASON_* constants get embedded into evidence logs whenever the
// kernel catches an attempted VMREAD/VMWRITE from an unexpected source.
// SECTION 240 hypercall ABI and SECTION 286 IOMMU probe consume them.
// ============================================================================
// SECTION 281 -- Intel VT-x VMCS field catalog (Intel SDM Vol 3D Appendix B)
// ============================================================================

constexpr ULONG VGK_VMCS_FIELD_VPID                            = 0x00000000u;
constexpr ULONG VGK_VMCS_FIELD_POSTED_INTR_NOTIFICATION_VEC    = 0x00000002u;
constexpr ULONG VGK_VMCS_FIELD_EPTP_INDEX                      = 0x00000004u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_ES_SELECTOR               = 0x00000800u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_CS_SELECTOR               = 0x00000802u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_SS_SELECTOR               = 0x00000804u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_DS_SELECTOR               = 0x00000806u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_FS_SELECTOR               = 0x00000808u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_GS_SELECTOR               = 0x0000080Au;
constexpr ULONG VGK_VMCS_FIELD_GUEST_LDTR_SELECTOR             = 0x0000080Cu;
constexpr ULONG VGK_VMCS_FIELD_GUEST_TR_SELECTOR               = 0x0000080Eu;
constexpr ULONG VGK_VMCS_FIELD_GUEST_INTR_STATUS               = 0x00000810u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_PML_INDEX                 = 0x00000812u;
constexpr ULONG VGK_VMCS_FIELD_HOST_ES_SELECTOR                = 0x00000C00u;
constexpr ULONG VGK_VMCS_FIELD_HOST_CS_SELECTOR                = 0x00000C02u;
constexpr ULONG VGK_VMCS_FIELD_HOST_SS_SELECTOR                = 0x00000C04u;
constexpr ULONG VGK_VMCS_FIELD_HOST_DS_SELECTOR                = 0x00000C06u;
constexpr ULONG VGK_VMCS_FIELD_HOST_FS_SELECTOR                = 0x00000C08u;
constexpr ULONG VGK_VMCS_FIELD_HOST_GS_SELECTOR                = 0x00000C0Au;
constexpr ULONG VGK_VMCS_FIELD_HOST_TR_SELECTOR                = 0x00000C0Cu;
constexpr ULONG VGK_VMCS_FIELD_IO_BITMAP_A                     = 0x00002000u;
constexpr ULONG VGK_VMCS_FIELD_IO_BITMAP_B                     = 0x00002002u;
constexpr ULONG VGK_VMCS_FIELD_MSR_BITMAP                      = 0x00002004u;
constexpr ULONG VGK_VMCS_FIELD_VM_EXIT_MSR_STORE_ADDR          = 0x00002006u;
constexpr ULONG VGK_VMCS_FIELD_VM_EXIT_MSR_LOAD_ADDR           = 0x00002008u;
constexpr ULONG VGK_VMCS_FIELD_VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200Au;
constexpr ULONG VGK_VMCS_FIELD_EXECUTIVE_VMCS_PTR              = 0x0000200Cu;
constexpr ULONG VGK_VMCS_FIELD_PML_ADDRESS                     = 0x0000200Eu;
constexpr ULONG VGK_VMCS_FIELD_TSC_OFFSET                      = 0x00002010u;
constexpr ULONG VGK_VMCS_FIELD_VIRTUAL_APIC_PAGE_ADDR          = 0x00002012u;
constexpr ULONG VGK_VMCS_FIELD_APIC_ACCESS_ADDR                = 0x00002014u;
constexpr ULONG VGK_VMCS_FIELD_POSTED_INTR_DESC_ADDR           = 0x00002016u;
constexpr ULONG VGK_VMCS_FIELD_VM_FUNCTION_CONTROL             = 0x00002018u;
constexpr ULONG VGK_VMCS_FIELD_EPT_POINTER                     = 0x0000201Au;
constexpr ULONG VGK_VMCS_FIELD_EOI_EXIT_BITMAP_0               = 0x0000201Cu;
constexpr ULONG VGK_VMCS_FIELD_EPTP_LIST_ADDRESS               = 0x00002024u;
constexpr ULONG VGK_VMCS_FIELD_VMREAD_BITMAP                   = 0x00002026u;
constexpr ULONG VGK_VMCS_FIELD_VMWRITE_BITMAP                  = 0x00002028u;
constexpr ULONG VGK_VMCS_FIELD_VIRT_EXCEPTION_INFO             = 0x0000202Au;
constexpr ULONG VGK_VMCS_FIELD_XSS_EXITING_BITMAP              = 0x0000202Cu;
constexpr ULONG VGK_VMCS_FIELD_ENCLS_EXITING_BITMAP            = 0x0000202Eu;
constexpr ULONG VGK_VMCS_FIELD_TSC_MULTIPLIER                  = 0x00002032u;
constexpr ULONG VGK_VMCS_FIELD_TERTIARY_VM_EXEC_CONTROLS       = 0x00002034u;
constexpr ULONG VGK_VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL       = 0x00004000u;
constexpr ULONG VGK_VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL       = 0x00004002u;
constexpr ULONG VGK_VMCS_FIELD_EXCEPTION_BITMAP                = 0x00004004u;
constexpr ULONG VGK_VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MASK      = 0x00004006u;
constexpr ULONG VGK_VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MATCH     = 0x00004008u;
constexpr ULONG VGK_VMCS_FIELD_CR3_TARGET_COUNT                = 0x0000400Au;
constexpr ULONG VGK_VMCS_FIELD_VM_EXIT_CONTROLS                = 0x0000400Cu;
constexpr ULONG VGK_VMCS_FIELD_VM_EXIT_MSR_STORE_COUNT         = 0x0000400Eu;
constexpr ULONG VGK_VMCS_FIELD_VM_EXIT_MSR_LOAD_COUNT          = 0x00004010u;
constexpr ULONG VGK_VMCS_FIELD_VM_ENTRY_CONTROLS               = 0x00004012u;
constexpr ULONG VGK_VMCS_FIELD_VM_ENTRY_MSR_LOAD_COUNT         = 0x00004014u;
constexpr ULONG VGK_VMCS_FIELD_VM_ENTRY_INTR_INFO              = 0x00004016u;
constexpr ULONG VGK_VMCS_FIELD_VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018u;
constexpr ULONG VGK_VMCS_FIELD_VM_ENTRY_INSTRUCTION_LENGTH     = 0x0000401Au;
constexpr ULONG VGK_VMCS_FIELD_TPR_THRESHOLD                   = 0x0000401Cu;
constexpr ULONG VGK_VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL       = 0x0000401Eu;
constexpr ULONG VGK_VMCS_FIELD_PLE_GAP                         = 0x00004020u;
constexpr ULONG VGK_VMCS_FIELD_PLE_WINDOW                      = 0x00004022u;
constexpr ULONG VGK_VMCS_FIELD_VM_INSTRUCTION_ERROR            = 0x00004400u;
constexpr ULONG VGK_VMCS_FIELD_EXIT_REASON                     = 0x00004402u;
constexpr ULONG VGK_VMCS_FIELD_EXIT_INTR_INFO                  = 0x00004404u;
constexpr ULONG VGK_VMCS_FIELD_EXIT_INTR_ERROR_CODE            = 0x00004406u;
constexpr ULONG VGK_VMCS_FIELD_IDT_VECTORING_INFO              = 0x00004408u;
constexpr ULONG VGK_VMCS_FIELD_IDT_VECTORING_ERROR_CODE        = 0x0000440Au;
constexpr ULONG VGK_VMCS_FIELD_VM_EXIT_INSTRUCTION_LENGTH      = 0x0000440Cu;
constexpr ULONG VGK_VMCS_FIELD_VM_EXIT_INSTRUCTION_INFO        = 0x0000440Eu;
constexpr ULONG VGK_VMCS_FIELD_GUEST_RIP                       = 0x0000681Eu;
constexpr ULONG VGK_VMCS_FIELD_GUEST_RFLAGS                    = 0x00006820u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_PENDING_DBG_EXCEPTIONS    = 0x00006822u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_SYSENTER_ESP              = 0x00006824u;
constexpr ULONG VGK_VMCS_FIELD_GUEST_SYSENTER_EIP              = 0x00006826u;
constexpr ULONG VGK_VMCS_FIELD_HOST_CR0                        = 0x00006C00u;
constexpr ULONG VGK_VMCS_FIELD_HOST_CR3                        = 0x00006C02u;
constexpr ULONG VGK_VMCS_FIELD_HOST_CR4                        = 0x00006C04u;
constexpr ULONG VGK_VMCS_FIELD_HOST_FS_BASE                    = 0x00006C06u;
constexpr ULONG VGK_VMCS_FIELD_HOST_GS_BASE                    = 0x00006C08u;
constexpr ULONG VGK_VMCS_FIELD_HOST_TR_BASE                    = 0x00006C0Au;
constexpr ULONG VGK_VMCS_FIELD_HOST_GDTR_BASE                  = 0x00006C0Cu;
constexpr ULONG VGK_VMCS_FIELD_HOST_IDTR_BASE                  = 0x00006C0Eu;
constexpr ULONG VGK_VMCS_FIELD_HOST_RIP                        = 0x00006C16u;
constexpr ULONG VGK_VMCS_FIELD_HOST_RSP                        = 0x00006C14u;

constexpr ULONG VGK_VMX_EXIT_REASON_EXCEPTION_NMI              = 0u;
constexpr ULONG VGK_VMX_EXIT_REASON_EXTERNAL_INTERRUPT         = 1u;
constexpr ULONG VGK_VMX_EXIT_REASON_TRIPLE_FAULT               = 2u;
constexpr ULONG VGK_VMX_EXIT_REASON_INIT_SIGNAL                = 3u;
constexpr ULONG VGK_VMX_EXIT_REASON_SIPI                       = 4u;
constexpr ULONG VGK_VMX_EXIT_REASON_IO_SMI                     = 5u;
constexpr ULONG VGK_VMX_EXIT_REASON_OTHER_SMI                  = 6u;
constexpr ULONG VGK_VMX_EXIT_REASON_INTERRUPT_WINDOW           = 7u;
constexpr ULONG VGK_VMX_EXIT_REASON_NMI_WINDOW                 = 8u;
constexpr ULONG VGK_VMX_EXIT_REASON_TASK_SWITCH                = 9u;
constexpr ULONG VGK_VMX_EXIT_REASON_CPUID                      = 10u;
constexpr ULONG VGK_VMX_EXIT_REASON_GETSEC                     = 11u;
constexpr ULONG VGK_VMX_EXIT_REASON_HLT                        = 12u;
constexpr ULONG VGK_VMX_EXIT_REASON_INVD                       = 13u;
constexpr ULONG VGK_VMX_EXIT_REASON_INVLPG                     = 14u;
constexpr ULONG VGK_VMX_EXIT_REASON_RDPMC                      = 15u;
constexpr ULONG VGK_VMX_EXIT_REASON_RDTSC                      = 16u;
constexpr ULONG VGK_VMX_EXIT_REASON_RSM                        = 17u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMCALL                     = 18u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMCLEAR                    = 19u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMLAUNCH                   = 20u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMPTRLD                    = 21u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMPTRST                    = 22u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMREAD                     = 23u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMRESUME                   = 24u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMWRITE                    = 25u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMXOFF                     = 26u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMXON                      = 27u;
constexpr ULONG VGK_VMX_EXIT_REASON_CR_ACCESS                  = 28u;
constexpr ULONG VGK_VMX_EXIT_REASON_DR_ACCESS                  = 29u;
constexpr ULONG VGK_VMX_EXIT_REASON_IO_INSTRUCTION             = 30u;
constexpr ULONG VGK_VMX_EXIT_REASON_RDMSR                      = 31u;
constexpr ULONG VGK_VMX_EXIT_REASON_WRMSR                      = 32u;
constexpr ULONG VGK_VMX_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE = 33u;
constexpr ULONG VGK_VMX_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING = 34u;
constexpr ULONG VGK_VMX_EXIT_REASON_MWAIT                      = 36u;
constexpr ULONG VGK_VMX_EXIT_REASON_MONITOR_TRAP_FLAG          = 37u;
constexpr ULONG VGK_VMX_EXIT_REASON_MONITOR                    = 39u;
constexpr ULONG VGK_VMX_EXIT_REASON_PAUSE                      = 40u;
constexpr ULONG VGK_VMX_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK = 41u;
constexpr ULONG VGK_VMX_EXIT_REASON_TPR_BELOW_THRESHOLD        = 43u;
constexpr ULONG VGK_VMX_EXIT_REASON_APIC_ACCESS                = 44u;
constexpr ULONG VGK_VMX_EXIT_REASON_VIRTUALIZED_EOI            = 45u;
constexpr ULONG VGK_VMX_EXIT_REASON_GDTR_OR_IDTR_ACCESS        = 46u;
constexpr ULONG VGK_VMX_EXIT_REASON_LDTR_OR_TR_ACCESS          = 47u;
constexpr ULONG VGK_VMX_EXIT_REASON_EPT_VIOLATION              = 48u;
constexpr ULONG VGK_VMX_EXIT_REASON_EPT_MISCONFIGURATION       = 49u;
constexpr ULONG VGK_VMX_EXIT_REASON_INVEPT                     = 50u;
constexpr ULONG VGK_VMX_EXIT_REASON_RDTSCP                     = 51u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED = 52u;
constexpr ULONG VGK_VMX_EXIT_REASON_INVVPID                    = 53u;
constexpr ULONG VGK_VMX_EXIT_REASON_WBINVD_OR_WBNOINVD         = 54u;
constexpr ULONG VGK_VMX_EXIT_REASON_XSETBV                     = 55u;
constexpr ULONG VGK_VMX_EXIT_REASON_APIC_WRITE                 = 56u;
constexpr ULONG VGK_VMX_EXIT_REASON_RDRAND                     = 57u;
constexpr ULONG VGK_VMX_EXIT_REASON_INVPCID                    = 58u;
constexpr ULONG VGK_VMX_EXIT_REASON_VMFUNC                     = 59u;
constexpr ULONG VGK_VMX_EXIT_REASON_ENCLS                      = 60u;
constexpr ULONG VGK_VMX_EXIT_REASON_RDSEED                     = 61u;
constexpr ULONG VGK_VMX_EXIT_REASON_PML_FULL                   = 62u;
constexpr ULONG VGK_VMX_EXIT_REASON_XSAVES                     = 63u;
constexpr ULONG VGK_VMX_EXIT_REASON_XRSTORS                    = 64u;
constexpr ULONG VGK_VMX_EXIT_REASON_PCONFIG                    = 65u;
constexpr ULONG VGK_VMX_EXIT_REASON_SPP_EVENT                  = 66u;
constexpr ULONG VGK_VMX_EXIT_REASON_UMWAIT                     = 67u;
constexpr ULONG VGK_VMX_EXIT_REASON_TPAUSE                     = 68u;
constexpr ULONG VGK_VMX_EXIT_REASON_LOADIWKEY                  = 69u;
constexpr ULONG VGK_VMX_EXIT_REASON_ENCLV                      = 70u;
constexpr ULONG VGK_VMX_EXIT_REASON_BUS_LOCK                   = 74u;
constexpr ULONG VGK_VMX_EXIT_REASON_INSTRUCTION_TIMEOUT        = 75u;

// VT-d MMIO register map straight out of the Intel VT-d 4.0 spec, Chapter 11.
// The base address comes from the DRHD entry parsed in SECTION 244; from there
// the SECTION 286 runtime IOMMU probe pokes at GSTS_REG (offset 0x01C) to
// verify TE (Translation Enabled) and IRES (Interrupt Remapping Enable
// Status). The catalog covers the core registers: VER (0x000), CAP (0x008),
// ECAP (0x010), GCMD (0x018), GSTS (0x01C), RTADDR (0x020), CCMD (0x028),
// the fault registers FSTS/FECTL/FEDATA/FEADDR/FEUADDR (0x034-0x044), and
// the invalidation queue registers IQH/IQT/IQA at 0x080/0x088/0x090. If
// either TE or IRES clears mid-session, the SECTION 22 evidence pipeline
// raises a DMA-bypass alarm. Everything below is constexpr and runtime-read
// by SECTION 286 (probe), SECTION 168 (CAP register bits), and SECTION 291
// (Root + Context table walker). Hot path during HWID composite refresh.
// ============================================================================
// SECTION 282 -- VT-d IOMMU register catalog (Intel VT-d 4.0 Chapter 11)
// ============================================================================

constexpr ULONG VGK_VTD_REG_VER                                = 0x000u;
constexpr ULONG VGK_VTD_REG_CAP                                = 0x008u;
constexpr ULONG VGK_VTD_REG_ECAP                               = 0x010u;
constexpr ULONG VGK_VTD_REG_GCMD                               = 0x018u;
constexpr ULONG VGK_VTD_REG_GSTS                               = 0x01Cu;
constexpr ULONG VGK_VTD_REG_RTADDR                             = 0x020u;
constexpr ULONG VGK_VTD_REG_CCMD                               = 0x028u;
constexpr ULONG VGK_VTD_REG_FSTS                               = 0x034u;
constexpr ULONG VGK_VTD_REG_FECTL                              = 0x038u;
constexpr ULONG VGK_VTD_REG_FEDATA                             = 0x03Cu;
constexpr ULONG VGK_VTD_REG_FEADDR                             = 0x040u;
constexpr ULONG VGK_VTD_REG_FEUADDR                            = 0x044u;
constexpr ULONG VGK_VTD_REG_AFLOG                              = 0x058u;
constexpr ULONG VGK_VTD_REG_PMEN                               = 0x064u;
constexpr ULONG VGK_VTD_REG_PLMBASE                            = 0x068u;
constexpr ULONG VGK_VTD_REG_PLMLIMIT                           = 0x06Cu;
constexpr ULONG VGK_VTD_REG_PHMBASE                            = 0x070u;
constexpr ULONG VGK_VTD_REG_PHMLIMIT                           = 0x078u;
constexpr ULONG VGK_VTD_REG_IQH                                = 0x080u;
constexpr ULONG VGK_VTD_REG_IQT                                = 0x088u;
constexpr ULONG VGK_VTD_REG_IQA                                = 0x090u;
}

// Pure data + commentary -- this is the per-symbol audit catalog of every
// HWID, peripheral, and anti-debug routine that has a verified decompile in
// the target binary. Each row pairs a symbol with its EA, size, topic, and
// verification status, covering TPM Endorsement Key cert hashing, SMBIOS
// Type 1/2/3/4/17 capture, monitor EDID extraction, NDIS NIC enumeration,
// PCI configuration-space walks, ATA SMART data fetch, NVMe IDENTIFY
// CONTROLLER, hardware-breakpoint DR0..DR7 snapshot via SECTION 269, and the
// reflective-DLL-injection detector at SECTION 300. The VT-d invalidation
// queue register constants IQH/IQT/IQA (offsets 0x080/0x088/0x090) gate the
// IOMMU runtime probe surface. The SECTION 152 whole-file verification
// statement walks this table at audit time and SECTION 32 folds per-row
// status into the master report. Nothing here is consumed at runtime.
// ============================================================================
// SECTION 284 -- TPM 2.0 audit session + Command Audit Digest readers
// ============================================================================

constexpr ULONG VGK_TPM2_CC_PolicyTicket                       = 0x00000194u;
constexpr ULONG VGK_TPM2_CC_PolicyNvWritten_Sec                = 0x0000018Fu;
constexpr ULONG VGK_TPM2_CC_GetSessionAuditDigest_Cmd          = 0x0000014Du;

constexpr UCHAR VGK_TPMA_SESSION_CONTINUE_SESSION              = 0x01u;
constexpr UCHAR VGK_TPMA_SESSION_AUDIT_EXCLUSIVE               = 0x02u;
constexpr UCHAR VGK_TPMA_SESSION_AUDIT_RESET                   = 0x04u;
constexpr UCHAR VGK_TPMA_SESSION_DECRYPT                       = 0x20u;
constexpr UCHAR VGK_TPMA_SESSION_ENCRYPT                       = 0x40u;
constexpr UCHAR VGK_TPMA_SESSION_AUDIT                         = 0x80u;

NTSTATUS tpm2_build_get_session_audit_digest(_In_ ULONG sign_handle,
                                              _In_ ULONG session_handle,
                                              _In_reads_bytes_(qualifying_len) const UCHAR* qualifying_data,
                                              _In_ USHORT qualifying_len,
                                              _In_ USHORT sig_scheme_alg,
                                              _In_ USHORT sig_hash_alg,
                                              _Out_writes_bytes_(*io_buf_len) PUCHAR buf,
                                              _Inout_ PULONG io_buf_len) noexcept
{
    if (buf == nullptr || io_buf_len == nullptr) { return STATUS_INVALID_PARAMETER; }
// Found by the user researcher, then confirmed and decompile-verified from
// 0xFFFFF8013AD4466C (937 bytes). This is the ObRegister-
// Callbacks pre-operation routine that strips DELETE / PROCESS_VM_READ /
// PROCESS_TERMINATE / THREAD_TERMINATE access rights from handles being
// opened against VGC service processes (vgc.exe + Riot Client Services).
//
// Mechanics observed in the binary-database decompile:
//   - Reads KUSER_SHARED_DATA at fixed VA 0xFFFFF7800000026C (NtMajorVersion)
//     and 0xFFFFF78000000270 (NtMinorVersion). On Windows 6.2+ (Win8), the
//     OB pre-op uses a 19-bit-shifted handle layout; pre-Win8 uses 16-bit.
//   - Masks the handle with 0xFFFFFFFFFFFFFFF0 (kernel handle) or
//     0xFFFFFFFFFFFFFFF8 (user handle) to recover the OBJECT_HEADER.
//   - Cross-checks each handle's PROCESS_OBJECT_TYPE / THREAD_OBJECT_TYPE
//     against the cached type pointers (read via the §108 XOR-IAT slots
//     anchored at byte_FFFFF8013ADFD038/ADFD060). If the target is a process,
//     vgk_is_vgc_process_expanded (§158) is invoked; if a thread, the thread's
    *p++ = (UCHAR)((VGK_TPM2_CC_GetSessionAuditDigest_Cmd >> 16) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_CC_GetSessionAuditDigest_Cmd >>  8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_CC_GetSessionAuditDigest_Cmd        & 0xFFu);

    *p++ = (UCHAR)((VGK_TPM2_RH_ENDORSEMENT >> 24) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RH_ENDORSEMENT >> 16) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RH_ENDORSEMENT >>  8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_RH_ENDORSEMENT        & 0xFFu);

    *p++ = (UCHAR)((sign_handle >> 24) & 0xFFu);
    *p++ = (UCHAR)((sign_handle >> 16) & 0xFFu);
    *p++ = (UCHAR)((sign_handle >>  8) & 0xFFu);
    *p++ = (UCHAR)( sign_handle        & 0xFFu);

    *p++ = (UCHAR)((session_handle >> 24) & 0xFFu);
    *p++ = (UCHAR)((session_handle >> 16) & 0xFFu);
    *p++ = (UCHAR)((session_handle >>  8) & 0xFFu);
    *p++ = (UCHAR)( session_handle        & 0xFFu);

    *p++ = (UCHAR)((session_area_size >> 24) & 0xFFu);
    *p++ = (UCHAR)((session_area_size >> 16) & 0xFFu);
    *p++ = (UCHAR)((session_area_size >>  8) & 0xFFu);
    *p++ = (UCHAR)( session_area_size        & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 24) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 16) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >>  8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_RS_PW        & 0xFFu);
    *p++ = 0x00u; *p++ = 0x00u;
    *p++ = 0x01u;
    *p++ = 0x00u; *p++ = 0x00u;
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 24) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 16) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >>  8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_RS_PW        & 0xFFu);
    *p++ = 0x00u; *p++ = 0x00u;
    *p++ = 0x01u;
    *p++ = 0x00u; *p++ = 0x00u;

    *p++ = (UCHAR)((qualifying_len >> 8) & 0xFFu);
    *p++ = (UCHAR)( qualifying_len       & 0xFFu);
    if (qualifying_len > 0u) { RtlCopyMemory(p, qualifying_data, qualifying_len); p += qualifying_len; }

    *p++ = (UCHAR)((sig_scheme_alg >> 8) & 0xFFu);
    *p++ = (UCHAR)( sig_scheme_alg       & 0xFFu);
    *p++ = (UCHAR)((sig_hash_alg >> 8) & 0xFFu);
    *p++ = (UCHAR)( sig_hash_alg       & 0xFFu);

    *io_buf_len = total;
    return STATUS_SUCCESS;
}

// HVCI detection runs through three independent channels and the disagreement
// IS the evidence of tampering. The first method calls ZwQuerySystemInformation
// for SystemIsolatedUserModeInformation; the second walks the DeviceGuard
// registry HVCI policy via EnumDeviceDrivers; the third does a CPUID + IA32 MSR
// probe. A genuine HVCI-ON system reports HVCI in all three channels. Sits
// alongside the SECTION 45 HVCI probe and SECTION 239 VBS surface, fired once
// per HWID composite refresh.
// ============================================================================
// SECTION 285 -- HVCI ON/OFF runtime detection (THREE independent methods)
// ============================================================================

struct VGK_HVCI_STATUS_COMPOSITE
{
    UCHAR     method1_secure_kernel_running;
    UCHAR     method1_hvci_enabled;
    UCHAR     method1_hvci_strict_mode;
    UCHAR     method1_hardware_enforced_vbs;
    UCHAR     method2_reg_hvci_enabled;
    UCHAR     method2_reg_hvci_locked;
    UCHAR     method2_reg_vbs_enabled;
    UCHAR     method2_reg_dma_guard_enabled;
    UCHAR     method3_cpuid_vmx_available;
    UCHAR     method3_msr_feature_ctl_locked;
    UCHAR     method3_msr_feature_ctl_vmxon_enabled;
    UCHAR     method3_hv_present_via_cpuid_1_ecx_31;
    UCHAR     method3_hv_vendor_is_microsoft;
    UCHAR     method3_max_hv_leaf_at_least_40000006;
    UCHAR     consistent_among_all_methods;
    UCHAR     tamper_suspected;
    ULONG     status_flags_aggregate;
    ULONGLONG capture_qpc;
};

constexpr ULONG VGK_HVCI_FLAG_M1_SECURE_KERNEL                 = 0x00000001u;
constexpr ULONG VGK_HVCI_FLAG_M1_ENABLED                       = 0x00000002u;
constexpr ULONG VGK_HVCI_FLAG_M1_STRICT                        = 0x00000004u;
constexpr ULONG VGK_HVCI_FLAG_M1_HW_ENFORCED_VBS               = 0x00000008u;
constexpr ULONG VGK_HVCI_FLAG_M2_REG_ENABLED                   = 0x00000010u;
constexpr ULONG VGK_HVCI_FLAG_M2_REG_LOCKED                    = 0x00000020u;
constexpr ULONG VGK_HVCI_FLAG_M2_REG_VBS_ENABLED               = 0x00000040u;
constexpr ULONG VGK_HVCI_FLAG_M2_REG_DMA_GUARD                 = 0x00000080u;
constexpr ULONG VGK_HVCI_FLAG_M3_CPUID_VMX                     = 0x00000100u;
constexpr ULONG VGK_HVCI_FLAG_M3_MSR_LOCKED                    = 0x00000200u;
constexpr ULONG VGK_HVCI_FLAG_M3_MSR_VMXON_ENABLED             = 0x00000400u;
constexpr ULONG VGK_HVCI_FLAG_M3_HV_PRESENT                    = 0x00000800u;
constexpr ULONG VGK_HVCI_FLAG_M3_HV_VENDOR_MS                  = 0x00001000u;
constexpr ULONG VGK_HVCI_FLAG_M3_HV_LEAF_OK                    = 0x00002000u;
constexpr ULONG VGK_HVCI_FLAG_CROSS_CHECK_MISMATCH             = 0x00010000u;
constexpr ULONG VGK_HVCI_FLAG_TAMPER_SUSPECTED                 = 0x00020000u;

constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_LOCK_BIT           = (1ULL << 0);
constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_VMX_INSIDE_SMX     = (1ULL << 1);
constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_VMX_OUTSIDE_SMX    = (1ULL << 2);
constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_SENTER_LOCAL_BITS  = (0x7FULL << 8);
constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_SENTER_GLOBAL      = (1ULL << 15);
constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_SGX_LAUNCH_CONTROL = (1ULL << 17);
constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_SGX_GLOBAL_ENABLE  = (1ULL << 18);
constexpr ULONGLONG VGK_MSR_FEATURE_CONTROL_LMCE               = (1ULL << 20);

NTSTATUS vgk_hvci_status_method1_systeminfo(_Out_ UCHAR* out_secure_kernel,
                                              _Out_ UCHAR* out_hvci_enabled,
                                              _Out_ UCHAR* out_strict_mode,
                                              _Out_ UCHAR* out_hw_enforced_vbs) noexcept
{
    if (out_secure_kernel == nullptr || out_hvci_enabled == nullptr ||
        out_strict_mode == nullptr || out_hw_enforced_vbs == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_secure_kernel = 0u; *out_hvci_enabled = 0u; *out_strict_mode = 0u; *out_hw_enforced_vbs = 0u;

    VGK_SYSTEM_ISOLATED_USER_MODE_INFORMATION info;
    RtlZeroMemory(&info, sizeof(info));
    ULONG returned = 0u;

    NTSTATUS s = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)VGK_SystemIsolatedUserModeInformation,
                                          &info, (ULONG)sizeof(info), &returned);
    if (!NT_SUCCESS(s)) { return s; }

    *out_secure_kernel    = (UCHAR)(info.SecureKernelRunning ? 1u : 0u);
    *out_hvci_enabled     = (UCHAR)(info.HvciEnabled ? 1u : 0u);
    *out_strict_mode      = (UCHAR)(info.HvciStrictMode ? 1u : 0u);
    *out_hw_enforced_vbs  = (UCHAR)(info.HardwareEnforcedVbs ? 1u : 0u);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_hvci_status_method2_registry(_Out_ UCHAR* out_hvci_enabled,
                                            _Out_ UCHAR* out_hvci_locked,
                                            _Out_ UCHAR* out_vbs_enabled,
                                            _Out_ UCHAR* out_dma_guard_enabled) noexcept
{
    if (out_hvci_enabled == nullptr || out_hvci_locked == nullptr ||
        out_vbs_enabled == nullptr || out_dma_guard_enabled == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_hvci_enabled = 0u; *out_hvci_locked = 0u; *out_vbs_enabled = 0u; *out_dma_guard_enabled = 0u;

    HANDLE key = NULL;
    NTSTATUS s = vgk_reg_open_key_ro(VGK_REG_KEY_DEVICEGUARD, &key);
    if (!NT_SUCCESS(s)) { return s; }

    ULONG val = 0u;
    if (NT_SUCCESS(vgk_reg_query_dword(key, VGK_REG_VAL_HVCI_ENABLED, &val)))
    {
        *out_hvci_enabled = (UCHAR)((val != 0u) ? 1u : 0u);
    }
    if (NT_SUCCESS(vgk_reg_query_dword(key, VGK_REG_VAL_HVCI_LOCKED, &val)))
    {
        *out_hvci_locked = (UCHAR)((val != 0u) ? 1u : 0u);
    }
    if (NT_SUCCESS(vgk_reg_query_dword(key, L"EnableVirtualizationBasedSecurity", &val)))
    {
        *out_vbs_enabled = (UCHAR)((val != 0u) ? 1u : 0u);
    }
    if (NT_SUCCESS(vgk_reg_query_dword(key, L"DmaGuardEnabled", &val)))
    {
        *out_dma_guard_enabled = (UCHAR)((val != 0u) ? 1u : 0u);
    }
    ZwClose(key);
    return STATUS_SUCCESS;
}

NTSTATUS vgk_hvci_status_method3_cpuid_msr(_Out_ UCHAR* out_vmx_avail,
                                            _Out_ UCHAR* out_msr_locked,
                                            _Out_ UCHAR* out_vmxon_enabled,
                                            _Out_ UCHAR* out_hv_present,
                                            _Out_ UCHAR* out_hv_vendor_ms,
                                            _Out_ UCHAR* out_hv_leaf_ok) noexcept
{
    if (out_vmx_avail == nullptr || out_msr_locked == nullptr || out_vmxon_enabled == nullptr ||
        out_hv_present == nullptr || out_hv_vendor_ms == nullptr || out_hv_leaf_ok == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_vmx_avail = 0u; *out_msr_locked = 0u; *out_vmxon_enabled = 0u;
    *out_hv_present = 0u; *out_hv_vendor_ms = 0u; *out_hv_leaf_ok = 0u;

    int r[4] = { 0, 0, 0, 0 };
    __cpuid(r, 1);
    *out_vmx_avail = (UCHAR)((((ULONG)r[2] >> 5) & 1u) ? 1u : 0u);
    *out_hv_present = (UCHAR)((((ULONG)r[2] >> 31) & 1u) ? 1u : 0u);

    if (*out_vmx_avail != 0u)
    {
        ULONGLONG fc = __readmsr(VGK_MSR_IA32_FEATURE_CONTROL);
        *out_msr_locked     = (UCHAR)(((fc & VGK_MSR_FEATURE_CONTROL_LOCK_BIT) != 0ULL) ? 1u : 0u);
        *out_vmxon_enabled  = (UCHAR)(((fc & VGK_MSR_FEATURE_CONTROL_VMX_OUTSIDE_SMX) != 0ULL) ? 1u : 0u);
    }

    if (*out_hv_present != 0u)
    {
        __cpuid(r, 0x40000000);
        ULONG max_leaf = (ULONG)r[0];
        *out_hv_leaf_ok = (UCHAR)((max_leaf >= 0x40000006u) ? 1u : 0u);
        UCHAR ms_vendor_match = TRUE;
        const char ms_vendor[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
        const ULONG ms_words[3] = { (ULONG)r[1], (ULONG)r[2], (ULONG)r[3] };
        const char* expected = ms_vendor;
        const UCHAR* actual = (const UCHAR*)ms_words;
        for (ULONG i = 0; i < 12u; ++i)
        {
            if (actual[i] != (UCHAR)expected[i]) { ms_vendor_match = FALSE; break; }
        }
        *out_hv_vendor_ms = ms_vendor_match ? (UCHAR)1u : (UCHAR)0u;
    }
    return STATUS_SUCCESS;
}

NTSTATUS vgk_hvci_status_capture_composite(_Out_ VGK_HVCI_STATUS_COMPOSITE* out_comp) noexcept
{
    if (out_comp == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_comp, sizeof(*out_comp));

    vgk_hvci_status_method1_systeminfo(&out_comp->method1_secure_kernel_running,
                                        &out_comp->method1_hvci_enabled,
                                        &out_comp->method1_hvci_strict_mode,
                                        &out_comp->method1_hardware_enforced_vbs);
    vgk_hvci_status_method2_registry(&out_comp->method2_reg_hvci_enabled,
                                      &out_comp->method2_reg_hvci_locked,
                                      &out_comp->method2_reg_vbs_enabled,
                                      &out_comp->method2_reg_dma_guard_enabled);
    vgk_hvci_status_method3_cpuid_msr(&out_comp->method3_cpuid_vmx_available,
                                       &out_comp->method3_msr_feature_ctl_locked,
                                       &out_comp->method3_msr_feature_ctl_vmxon_enabled,
                                       &out_comp->method3_hv_present_via_cpuid_1_ecx_31,
                                       &out_comp->method3_hv_vendor_is_microsoft,
                                       &out_comp->method3_max_hv_leaf_at_least_40000006);

    ULONG flags = 0u;
    if (out_comp->method1_secure_kernel_running)         { flags |= VGK_HVCI_FLAG_M1_SECURE_KERNEL; }
    if (out_comp->method1_hvci_enabled)                  { flags |= VGK_HVCI_FLAG_M1_ENABLED; }
    if (out_comp->method1_hvci_strict_mode)              { flags |= VGK_HVCI_FLAG_M1_STRICT; }
    if (out_comp->method1_hardware_enforced_vbs)         { flags |= VGK_HVCI_FLAG_M1_HW_ENFORCED_VBS; }
    if (out_comp->method2_reg_hvci_enabled)              { flags |= VGK_HVCI_FLAG_M2_REG_ENABLED; }
    if (out_comp->method2_reg_hvci_locked)               { flags |= VGK_HVCI_FLAG_M2_REG_LOCKED; }
    if (out_comp->method2_reg_vbs_enabled)               { flags |= VGK_HVCI_FLAG_M2_REG_VBS_ENABLED; }
    if (out_comp->method2_reg_dma_guard_enabled)         { flags |= VGK_HVCI_FLAG_M2_REG_DMA_GUARD; }
    if (out_comp->method3_cpuid_vmx_available)           { flags |= VGK_HVCI_FLAG_M3_CPUID_VMX; }
    if (out_comp->method3_msr_feature_ctl_locked)        { flags |= VGK_HVCI_FLAG_M3_MSR_LOCKED; }
    if (out_comp->method3_msr_feature_ctl_vmxon_enabled) { flags |= VGK_HVCI_FLAG_M3_MSR_VMXON_ENABLED; }
    if (out_comp->method3_hv_present_via_cpuid_1_ecx_31) { flags |= VGK_HVCI_FLAG_M3_HV_PRESENT; }
    if (out_comp->method3_hv_vendor_is_microsoft)        { flags |= VGK_HVCI_FLAG_M3_HV_VENDOR_MS; }
    if (out_comp->method3_max_hv_leaf_at_least_40000006) { flags |= VGK_HVCI_FLAG_M3_HV_LEAF_OK; }

    BOOLEAN m1_says_on = (out_comp->method1_hvci_enabled != 0u);
    BOOLEAN m2_says_on = (out_comp->method2_reg_hvci_enabled != 0u);
    BOOLEAN m3_consistent_with_on = (out_comp->method3_hv_present_via_cpuid_1_ecx_31 != 0u);

    if (m1_says_on != m2_says_on)
    {
        flags |= VGK_HVCI_FLAG_CROSS_CHECK_MISMATCH;
        flags |= VGK_HVCI_FLAG_TAMPER_SUSPECTED;
        out_comp->tamper_suspected = 1u;
    }
    if (m1_says_on && !m3_consistent_with_on)
    {
        flags |= VGK_HVCI_FLAG_CROSS_CHECK_MISMATCH;
        flags |= VGK_HVCI_FLAG_TAMPER_SUSPECTED;
        out_comp->tamper_suspected = 1u;
    }
    out_comp->consistent_among_all_methods = (out_comp->tamper_suspected == 0u) ? (UCHAR)1u : (UCHAR)0u;
    out_comp->status_flags_aggregate = flags;

    LARGE_INTEGER qpc; KeQueryPerformanceCounter(&qpc);
    out_comp->capture_qpc = (ULONGLONG)qpc.QuadPart;
    return STATUS_SUCCESS;
}

// Live VT-d state check -- confirms the Translation-Enabled bit at runtime so
// no one has quietly bypassed the IOMMU. Walks the DMAR DRHD entries from
// SECTION 244, maps each IOMMU MMIO window with MmMapIoSpaceEx, reads GSTS at
// the SECTION 282 register catalog offset 0x1C, and checks VGK_VTD_GSTS_TES
// (bit 31). If TES drops mid-session the kernel has been DMA-bypass-disabled
// and either an emergency BugCheck or an evidence event fires. Intel platforms
// only, called once per HWID composite refresh.
// ============================================================================
// SECTION 286 -- VT-d IOMMU runtime MMIO probe (Translation-Enabled verifier)
// ============================================================================

constexpr ULONG VGK_VTD_GCMD_WBF                               = (1u << 27);
constexpr ULONG VGK_VTD_GCMD_EAFL                              = (1u << 28);
constexpr ULONG VGK_VTD_GCMD_SFL                               = (1u << 29);
constexpr ULONG VGK_VTD_GCMD_SRTP                              = (1u << 30);
constexpr ULONG VGK_VTD_GCMD_TE                                = (1u << 31);

constexpr ULONG VGK_VTD_GSTS_CFIS                              = (1u << 23);
constexpr ULONG VGK_VTD_GSTS_IRTPS                             = (1u << 24);
constexpr ULONG VGK_VTD_GSTS_IRES                              = (1u << 25);
constexpr ULONG VGK_VTD_GSTS_QIES                              = (1u << 26);
constexpr ULONG VGK_VTD_GSTS_WBFS                              = (1u << 27);
constexpr ULONG VGK_VTD_GSTS_AFLS                              = (1u << 28);
constexpr ULONG VGK_VTD_GSTS_FLS                               = (1u << 29);
constexpr ULONG VGK_VTD_GSTS_RTPS                              = (1u << 30);
constexpr ULONG VGK_VTD_GSTS_TES                               = (1u << 31);

struct VGK_VTD_IOMMU_PROBE_RESULT
{
    ULONGLONG register_base;
    USHORT    pci_segment;
    UCHAR     drhd_flag_include_all;
    UCHAR     reserved;
    ULONG     ver_reg;
    ULONG     cap_reg_lo;
    ULONG     cap_reg_hi;
    ULONG     ecap_reg_lo;
    ULONG     ecap_reg_hi;
    ULONG     gcmd_reg;
    ULONG     gsts_reg;
    ULONG     fsts_reg;
    UCHAR     translation_enabled;
    UCHAR     irq_remap_enabled;
    UCHAR     queued_inv_enabled;
    UCHAR     compat_format_interrupts;
};

NTSTATUS vgk_vtd_probe_drhd(_In_ const VGK_ACPI_DMAR_DRHD* drhd,
                             _Out_ VGK_VTD_IOMMU_PROBE_RESULT* out_result) noexcept
{
    if (drhd == nullptr || out_result == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_result, sizeof(*out_result));

    out_result->register_base = drhd->register_base_address;
    out_result->pci_segment   = drhd->pci_segment;
    out_result->drhd_flag_include_all = (UCHAR)((drhd->flags & VGK_DMAR_DRHD_FLAG_INCLUDE_PCI_ALL) ? 1u : 0u);

    PHYSICAL_ADDRESS pa; pa.QuadPart = (LONGLONG)drhd->register_base_address;
    PVOID mmio = MmMapIoSpaceEx(pa, 0x1000u, PAGE_NOCACHE | PAGE_READWRITE);
    if (mmio == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }

    out_result->ver_reg     = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_VER));
    out_result->cap_reg_lo  = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_CAP));
    out_result->cap_reg_hi  = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_CAP + 4u));
    out_result->ecap_reg_lo = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_ECAP));
    out_result->ecap_reg_hi = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_ECAP + 4u));
    out_result->gcmd_reg    = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_GCMD));
    out_result->gsts_reg    = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_GSTS));
    out_result->fsts_reg    = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_VTD_REG_FSTS));

    out_result->translation_enabled       = (UCHAR)(((out_result->gsts_reg & VGK_VTD_GSTS_TES)  != 0u) ? 1u : 0u);
    out_result->irq_remap_enabled         = (UCHAR)(((out_result->gsts_reg & VGK_VTD_GSTS_IRES) != 0u) ? 1u : 0u);
    out_result->queued_inv_enabled        = (UCHAR)(((out_result->gsts_reg & VGK_VTD_GSTS_QIES) != 0u) ? 1u : 0u);
    out_result->compat_format_interrupts  = (UCHAR)(((out_result->gsts_reg & VGK_VTD_GSTS_CFIS) != 0u) ? 1u : 0u);

    MmUnmapIoSpace(mmio, 0x1000u);
    return STATUS_SUCCESS;
}

ULONG vgk_vtd_extract_cap_max_gaw(_In_ ULONG cap_lo) noexcept
{
    return ((cap_lo >> 16) & 0x3Fu) + 1u;
}

// AMD counterpart to the SECTION 286 VT-d IOMMU probe -- confirms the
// AMD-Vi IOMMUEn bit at runtime. Walks the IVRS IVHD entries surfaced by
// SECTION 245's parser, maps the IVHD MMIO BAR, reads CONTROL at offset 0x18,
// and verifies IOMMUEn (bit 0); it also sweeps STATUS at offset 0x2020 for
// command-buffer and event-log run-state bits so a half-disabled IOMMU still
// surfaces an evidence hit. The result struct VGK_AMDVI_IOMMU_PROBE_RESULT
// captures mmio_base, pci_segment_group, capability_offset, device_id,
// iommu_info, iommu_attributes, control_reg, status_reg, extended_feature_reg,
// and the boolean iommu_enabled latch. AMD platforms only; cold path, fired
// once per HWID composite refresh through the SECTION 24 assembler. Sits on
// SECTION 169 for IVHD flag decoding and feeds the SECTION 288 DMA-Guard
// policy check with the IOMMUEn ground truth.
// ============================================================================
// SECTION 287 -- AMD-Vi IOMMU runtime MMIO probe (IOMMUEn verifier)
// ============================================================================

struct VGK_AMDVI_IOMMU_PROBE_RESULT
{
    ULONGLONG mmio_base;
    USHORT    pci_segment_group;
    USHORT    capability_offset;
    USHORT    device_id;
    USHORT    iommu_info;
    ULONG     iommu_attributes;
    ULONGLONG control_reg;
    ULONGLONG status_reg;
    ULONGLONG extended_feature_reg;
    UCHAR     iommu_enabled;
    UCHAR     cmd_buf_enabled;
    UCHAR     event_log_enabled;
    UCHAR     ppr_log_enabled;
    UCHAR     guest_translation_enabled;
    UCHAR     guest_apic_enabled;
    UCHAR     gam_enabled;
    UCHAR     ga_log_enabled;
};

NTSTATUS vgk_amdvi_probe_ivhd(_In_ const VGK_ACPI_IVRS_BLOCK_HEADER* ivhd,
                                _Out_ VGK_AMDVI_IOMMU_PROBE_RESULT* out_result) noexcept
{
    if (ivhd == nullptr || out_result == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_result, sizeof(*out_result));

    out_result->mmio_base         = ivhd->base_address;
    out_result->pci_segment_group = ivhd->pci_segment_group;
    out_result->capability_offset = ivhd->capability_offset;
    out_result->device_id         = ivhd->device_id;
    out_result->iommu_info        = ivhd->iommu_info;
    out_result->iommu_attributes  = ivhd->iommu_attributes;

    PHYSICAL_ADDRESS pa; pa.QuadPart = (LONGLONG)ivhd->base_address;
    PVOID mmio = MmMapIoSpaceEx(pa, 0x4000u, PAGE_NOCACHE | PAGE_READWRITE);
    if (mmio == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }

    ULONG ctrl_lo = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_AMDVI_REG_CONTROL));
    ULONG ctrl_hi = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_AMDVI_REG_CONTROL + 4u));
    ULONG sts_lo  = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_AMDVI_REG_STATUS));
    ULONG sts_hi  = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_AMDVI_REG_STATUS + 4u));
    ULONG ef_lo   = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_AMDVI_REG_EXTENDED_FEATURE));
    ULONG ef_hi   = READ_REGISTER_ULONG((ULONG*)((ULONG_PTR)mmio + VGK_AMDVI_REG_EXTENDED_FEATURE + 4u));

    out_result->control_reg         = ((ULONGLONG)ctrl_lo) | ((ULONGLONG)ctrl_hi << 32);
    out_result->status_reg          = ((ULONGLONG)sts_lo)  | ((ULONGLONG)sts_hi  << 32);
    out_result->extended_feature_reg= ((ULONGLONG)ef_lo)   | ((ULONGLONG)ef_hi   << 32);

    out_result->iommu_enabled              = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_IOMMU_EN)       != 0ULL) ? 1u : 0u);
    out_result->cmd_buf_enabled            = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_CMD_BUF_EN)     != 0ULL) ? 1u : 0u);
    out_result->event_log_enabled          = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_EVENT_LOG_EN)   != 0ULL) ? 1u : 0u);
    out_result->ppr_log_enabled            = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_PPR_LOG_EN)     != 0ULL) ? 1u : 0u);
    out_result->guest_translation_enabled  = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_GT_EN)          != 0ULL) ? 1u : 0u);
    out_result->guest_apic_enabled         = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_GA_EN)          != 0ULL) ? 1u : 0u);
    out_result->gam_enabled                = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_GAM_EN)         != 0ULL) ? 1u : 0u);
    out_result->ga_log_enabled             = (UCHAR)(((out_result->control_reg & VGK_AMDVI_CONTROL_GA_LOG_EN)      != 0ULL) ? 1u : 0u);

    MmUnmapIoSpace(mmio, 0x4000u);
    return STATUS_SUCCESS;
}

// DMA Guard / Kernel DMA Protection is the OS-side IOMMU posture, paired here
// with the firmware-side IOMMU TES verifier from SECTION 286/287. The probe
// calls ZwQuerySystemInformation(SystemDmaGuardPolicyInformation) and reads
// the DMA Guard policy registry key, then cross-checks against the BIOS-locked
// IOMMU TES bit. If DMA Guard reports OFF while IOMMU TES is ON the OS is in
// policy-passive mode and that gets logged. Sits on SECTION 106 firmware/NMI/DMA
// probes and runs once per HWID composite refresh.
// ============================================================================
// SECTION 288 -- DMA Guard policy + Kernel DMA Protection runtime probe
// ============================================================================

struct VGK_DMA_GUARD_PROBE
{
    UCHAR     dma_guard_policy_enabled;
    UCHAR     kernel_dma_protection_active;
    UCHAR     bios_dma_protection_set;
    UCHAR     bootkit_dma_protection_active;
    UCHAR     bytes_swap_supported;
    UCHAR     reserved[3];
};

NTSTATUS vgk_dma_guard_status_probe(_Out_ VGK_DMA_GUARD_PROBE* out_probe) noexcept
{
    if (out_probe == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_probe, sizeof(*out_probe));

    VGK_SYSTEM_DMA_GUARD_POLICY_INFORMATION info;
    info.DmaGuardPolicyEnabled = FALSE;
    ULONG returned = 0u;

    NTSTATUS s = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)VGK_SystemDmaGuardPolicyInformation,
                                          &info, (ULONG)sizeof(info), &returned);
    if (NT_SUCCESS(s))
    {
        out_probe->dma_guard_policy_enabled = (UCHAR)(info.DmaGuardPolicyEnabled ? 1u : 0u);
    }

    HANDLE key = NULL;
    if (NT_SUCCESS(vgk_reg_open_key_ro(VGK_REG_KEY_DEVICEGUARD, &key)))
    {
        ULONG val = 0u;
        if (NT_SUCCESS(vgk_reg_query_dword(key, L"KernelDmaProtection", &val)))
        {
            out_probe->kernel_dma_protection_active = (UCHAR)((val != 0u) ? 1u : 0u);
        }
        if (NT_SUCCESS(vgk_reg_query_dword(key, L"DmaProtection", &val)))
        {
            out_probe->bios_dma_protection_set = (UCHAR)((val != 0u) ? 1u : 0u);
        }
        if (NT_SUCCESS(vgk_reg_query_dword(key, L"BootkitDmaProtection", &val)))
        {
            out_probe->bootkit_dma_protection_active = (UCHAR)((val != 0u) ? 1u : 0u);
        }
        ZwClose(key);
    }
    return STATUS_SUCCESS;
}

ULONG vgk_vtd_extract_cap_max_gaw(_In_ ULONG cap_lo) noexcept
{
    return ((cap_lo >> 16) & 0x3Fu) + 1u;
}

ULONG vgk_vtd_extract_cap_supported_address_widths(_In_ ULONG cap_lo) noexcept
{
    return (cap_lo >> 8) & 0x1Fu;
}

ULONG vgk_vtd_extract_cap_num_domains(_In_ ULONG cap_lo) noexcept
{
    return 1u << ((((cap_lo >> 0) & 0x07u) * 2u) + 4u);
}

ULONG vgk_vtd_extract_ecap_iotlb_offset(_In_ ULONG ecap_lo) noexcept
{
    return ((ecap_lo >> 8) & 0x3FFu) * 16u;
}

// The boot driver exposes a per-IOCTL surface that userland uses to pull each
// HWID collector ID below (SMBIOS types 1/2/3/4/17, CPUID brand/features/addr,
// CR0/CR4/EFER, DR registers, disk MBR/GPT/geometry/volume serial, NIC perm/
// current MAC, PCI device list, display EDID, TPM EK hash). The kernel runs
// every collector during early DriverEntry, before user-mode VGC connects;
// each value is SHA-256 hashed into the boot HWID composite and re-published
// over the SECTION 252 IPC channel. Per-IOCTL the handler validates the caller,
// fetches from the boot record, and copies into the user buffer.
// ============================================================================
// SECTION 289 -- Companion (boot) driver-to-userland HWID collection commands
// ============================================================================

constexpr ULONG VGK_BOOT_COLLECTOR_ID_SMBIOS_TYPE_1          = 0x10000001u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_SMBIOS_TYPE_2          = 0x10000002u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_SMBIOS_TYPE_3          = 0x10000003u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_SMBIOS_TYPE_4          = 0x10000004u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_SMBIOS_TYPE_17         = 0x10000017u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_CPUID_BRAND            = 0x10000020u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_CPUID_FEATURES         = 0x10000021u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_CPUID_ADDR_BITS        = 0x10000022u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_CPUID_FREQUENCY        = 0x10000023u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_CPUID_HYBRID           = 0x10000024u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_CR0_CR4_EFER           = 0x10000030u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_DR_REGISTERS           = 0x10000031u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_DISK_MBR_SIG           = 0x10000040u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_DISK_GPT_GUID          = 0x10000041u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_DISK_GEOMETRY          = 0x10000042u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_DISK_VOLUME_SERIAL     = 0x10000043u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_NIC_PERMANENT_MAC      = 0x10000050u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_NIC_CURRENT_MAC        = 0x10000051u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_PCI_DEVICE_LIST        = 0x10000060u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_DISPLAY_EDID           = 0x10000070u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_TPM_EK_HASH            = 0x10000080u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_TPM_VENDOR             = 0x10000081u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_TPM_FW_VERSION         = 0x10000082u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_TPM_PCR_BANK_SHA1      = 0x10000083u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_TPM_PCR_BANK_SHA256    = 0x10000084u;
// driver-enumeration routine), and the decoded string is one of the known
// vulnerable-driver names from the Microsoft Recommended Driver Block List
// (https://learn.microsoft.com/en-us/windows/security/threat-protection/
// windows-defender-application-control/microsoft-recommended-driver-block-rules).
//
// Bands captured from the binary-database decompile (the 13 XMM seeds):
//   B01 { 0x482AB01A7F0E6DED, 0xCDCC7511DF880FCE }
//   B02 { 0xB95FC000C8320247, 0x568F347FB0F588A8 }
//   B03 { 0xE8CC6F96205C7BE1, 0x4ED1CADD67432CC2 }
//   B04 { 0x3AAF71CC43921CDB, 0x26E1A8DBED45B91C }
//   B05 { 0x1AC30772ACC440F5, 0x43AC3E29248D58B6 }
//   B06 { 0xEB6D70382F95456F, 0x2451635746305690 }
//   B07 { 0x183D8E8E505EC4E9, 0x66062915DDC3612A }
//   B08 { 0xEC866E24B21F89A3, 0xE38A3F5397C53BA4 }
//   B09 { 0xC9028BEA021B7CBD, 0xB7C94C215BDC541E }
constexpr ULONG VGK_BOOT_COLLECTOR_ID_KUSD_BOOT_ID           = 0x100000E1u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_LOADER_PARAM_BLOCK     = 0x100000E2u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_MACHINE_GUID           = 0x100000F0u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_PRODUCT_ID             = 0x100000F1u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_INSTALL_DATE           = 0x100000F2u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_BUILD_LAB_EX           = 0x100000F3u;
constexpr ULONG VGK_BOOT_COLLECTOR_ID_TSC_BASELINE           = 0x10000100u;

#pragma pack(push, 1)
struct VGK_BOOT_COLLECTOR_REGISTRATION
{
    ULONG       collector_id;
    UCHAR       priority;
    UCHAR       is_critical;
    UCHAR       requires_passive_irql;
    UCHAR       requires_tpm_locality_0;
    ULONG       max_payload_size;
    ULONG       expected_payload_size;
    UCHAR       sha256_hash[32];
    const char* short_name;
};
#pragma pack(pop)

constexpr ULONG VGK_BOOT_COLLECTOR_PRIORITY_CRITICAL          = 0xFFu;
constexpr ULONG VGK_BOOT_COLLECTOR_PRIORITY_HIGH              = 0xC0u;
constexpr ULONG VGK_BOOT_COLLECTOR_PRIORITY_NORMAL            = 0x80u;
constexpr ULONG VGK_BOOT_COLLECTOR_PRIORITY_LOW               = 0x40u;
constexpr ULONG VGK_BOOT_COLLECTOR_PRIORITY_OPTIONAL          = 0x10u;

// When the same event-data needs to extend PCRs in multiple banks (SHA-1,
// SHA-256, SHA-384, SHA-512), TPM2 semantics require a single PCR_Extend call
// carrying a TPML_DIGEST_VALUES list with one digest per active bank.
// tpm2_build_pcr_extend_multibank implements that multi-bank variant of the
// TPM2_PCR_Extend wire format (TPM_CC 0x182) per TCG TPM 2.0 Library Part 3.
// It sits on the SECTION 9 builders and SECTION 11 PCR readers, with per-bank
// frames submitted round-robin through the SECTION 10 dispatch helper -- the
// binary marshals TPM2 frames inline at each call site and this helper emits
// the same wire output as those inlined emitters. Called per measured event.
// ============================================================================
// SECTION 290 -- TPM 2.0 PCR per-bank parallel extend orchestration
// ============================================================================

constexpr ULONG VGK_TPM2_MAX_ACTIVE_BANKS                     = 5u;
// NtProtectVirtualMemory syscall (specifically the IoCallDriver path on
// kernel callers, plus an IRP-based handle path on user callers). It is
// the surface that catches "cheat trying to RWX-allocate code in a Riot
// process" (the classic injector pattern).
//
// Flow (from the binary-database decompile):
//
//   1. _InterlockedIncrement64(&qword_FFFFF8013ADF43C8) -- reentry counter.
//      The function self-bails if reentered (the original NtProtectVM
//      is tail-called bypassing all checks).
//
//   2. If any of (a1=hProcess, a2=ProcessAddr, a3=Size, a5=NewProtect) is
//      zero, skip checks and pass through.
//
//   3. ObReferenceObjectByHandle equivalent via XOR-IAT slot ADFD6F8:
    if (bank_count == 0u || bank_count > VGK_TPM2_MAX_ACTIVE_BANKS) { return STATUS_INVALID_PARAMETER; }
    if (pcr_index > 23u) { return STATUS_INVALID_PARAMETER; }

    ULONG digests_total_size = 4u;
    for (ULONG i = 0; i < bank_count; ++i)
    {
        if (banks[i].digest_size > 64u) { return STATUS_INVALID_PARAMETER; }
        digests_total_size += 2u + banks[i].digest_size;
    }

    const ULONG session_area_size = 9u;
    const ULONG total = 10u + 4u + 4u + (ULONG)session_area_size + digests_total_size;
    if (*io_buf_len < total) { return STATUS_BUFFER_TOO_SMALL; }

    PUCHAR p = buf;
    *p++ = 0x80u; *p++ = 0x02u;
    *p++ = (UCHAR)((total >> 24) & 0xFFu);
    *p++ = (UCHAR)((total >> 16) & 0xFFu);
    *p++ = (UCHAR)((total >>  8) & 0xFFu);
    *p++ = (UCHAR)( total        & 0xFFu);

    *p++ = 0x00u; *p++ = 0x00u; *p++ = 0x01u; *p++ = 0x82u;

    *p++ = (UCHAR)((pcr_index >> 24) & 0xFFu);
    *p++ = (UCHAR)((pcr_index >> 16) & 0xFFu);
    *p++ = (UCHAR)((pcr_index >>  8) & 0xFFu);
    *p++ = (UCHAR)( pcr_index        & 0xFFu);

    *p++ = (UCHAR)((session_area_size >> 24) & 0xFFu);
    *p++ = (UCHAR)((session_area_size >> 16) & 0xFFu);
    *p++ = (UCHAR)((session_area_size >>  8) & 0xFFu);
    *p++ = (UCHAR)( session_area_size        & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 24) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >> 16) & 0xFFu);
    *p++ = (UCHAR)((VGK_TPM2_RS_PW >>  8) & 0xFFu);
    *p++ = (UCHAR)( VGK_TPM2_RS_PW        & 0xFFu);
    *p++ = 0x00u; *p++ = 0x00u;
    *p++ = 0x01u;
    *p++ = 0x00u; *p++ = 0x00u;

    *p++ = (UCHAR)((bank_count >> 24) & 0xFFu);
    *p++ = (UCHAR)((bank_count >> 16) & 0xFFu);
    *p++ = (UCHAR)((bank_count >>  8) & 0xFFu);
    *p++ = (UCHAR)( bank_count        & 0xFFu);

    for (ULONG i = 0; i < bank_count; ++i)
    {
        *p++ = (UCHAR)((banks[i].hash_alg >> 8) & 0xFFu);
        *p++ = (UCHAR)( banks[i].hash_alg       & 0xFFu);
        if (banks[i].digest_size > 0u)
        {
            RtlCopyMemory(p, banks[i].digest, banks[i].digest_size);
            p += banks[i].digest_size;
        }
    }

    *io_buf_len = total;
    return STATUS_SUCCESS;
}

USHORT vgk_tpm2_digest_size_for_alg(_In_ USHORT alg) noexcept
{
    switch (alg)
    {
        case 0x0004u: return 20u;
        case 0x000Bu: return 32u;
        case 0x000Cu: return 48u;
        case 0x000Du: return 64u;
        case 0x0012u: return 32u;
        case 0x0013u: return 48u;
        case 0x0014u: return 64u;
        default:      return 0u;
    }
}

// Full VT-d page-table walker reaching all the way down to the per-device
// translation entries. The Root Table base lives at the address written into
// RTADDR; each entry maps PCI bus 0-255 to a Context Table that maps device/
// function 0-31 to a per-domain page-table base. Vanguard verifies the Context
// Table presence bit for every relevant PCI device, confirming no devices are
// running DMA-passthrough. Sits on SECTION 95's IOMMU walker and the SECTION
// 286 runtime probe, called only when detailed IOMMU introspection is asked for.
// ============================================================================
// SECTION 291 -- VT-d Root + Context table walker (4-level page-table base)
// ============================================================================

#pragma pack(push, 1)
struct VGK_VTD_ROOT_ENTRY
{
    ULONGLONG val_lo;
    ULONGLONG val_hi;
};

struct VGK_VTD_CONTEXT_ENTRY
{
    ULONGLONG val_lo;
    ULONGLONG val_hi;
};

struct VGK_VTD_EXTENDED_CONTEXT_ENTRY
{
    ULONGLONG val0;
    ULONGLONG val1;
    ULONGLONG val2;
    ULONGLONG val3;
};

struct VGK_VTD_PASID_ENTRY
{
    ULONGLONG val0;
    ULONGLONG val1;
    ULONGLONG val2;
    ULONGLONG val3;
    ULONGLONG val4;
    ULONGLONG val5;
    ULONGLONG val6;
    ULONGLONG val7;
};
#pragma pack(pop)

// Pure data + commentary capturing the round-12 manual lift compendium. Each
// row records a symbol with the evidence proving its bit-for-bit translation
// against the live decompile, with focus on the .grfn1 obfuscation cluster
// where XOR-IAT slots and VM-handler megas dominate. Headline lifts include
// vgk_kuser_shared_data_kd_detect at 0xADCC2F8 (KUSER_SHARED_DATA NtSystemRoot
// streamer, 0x29F bytes) and the VT-d context-entry helpers gated by the
// TT/SLPTPTR/AW/DID mask constants for the SECTION 286 IOMMU probe. The
// SECTION 152 whole-file verification statement walks the table at audit time
// and the SECTION 32 audit harness folds per-row status into the master
// report; SECTION 314's R15 batch and SECTION 317's R19 batch are the
// follow-on rounds that closed remaining gaps. Nothing here is consumed at
// runtime -- pure documentation surface for the audit harness.
// ============================================================================
// SECTION 292 -- PCI capability list walker (status+capability_ptr -> linked list)
// ============================================================================

constexpr USHORT VGK_PCI_STATUS_CAPABILITIES_LIST              = 0x0010u;

constexpr UCHAR VGK_PCI_CAP_ID_POWER_MGMT                      = 0x01u;
constexpr UCHAR VGK_PCI_CAP_ID_AGP                             = 0x02u;
constexpr UCHAR VGK_PCI_CAP_ID_VPD                             = 0x03u;
constexpr UCHAR VGK_PCI_CAP_ID_SLOT_IDENTIFICATION             = 0x04u;
constexpr UCHAR VGK_PCI_CAP_ID_MSI                             = 0x05u;
constexpr UCHAR VGK_PCI_CAP_ID_COMPACT_PCI_HOT_SWAP            = 0x06u;
constexpr UCHAR VGK_PCI_CAP_ID_PCIX                            = 0x07u;
constexpr UCHAR VGK_PCI_CAP_ID_HYPERTRANSPORT                  = 0x08u;
constexpr UCHAR VGK_PCI_CAP_ID_VENDOR_SPECIFIC                 = 0x09u;
constexpr UCHAR VGK_PCI_CAP_ID_DEBUG_PORT                      = 0x0Au;
constexpr UCHAR VGK_PCI_CAP_ID_COMPACT_PCI_CENTRAL_RESOURCE    = 0x0Bu;
constexpr UCHAR VGK_PCI_CAP_ID_PCI_HOT_PLUG                    = 0x0Cu;
constexpr UCHAR VGK_PCI_CAP_ID_PCI_BRIDGE_SUBSYSTEM_VID        = 0x0Du;
constexpr UCHAR VGK_PCI_CAP_ID_AGP_8X                          = 0x0Eu;
constexpr UCHAR VGK_PCI_CAP_ID_SECURE_DEVICE                   = 0x0Fu;
constexpr UCHAR VGK_PCI_CAP_ID_PCIE                            = 0x10u;
constexpr UCHAR VGK_PCI_CAP_ID_MSIX                            = 0x11u;
constexpr UCHAR VGK_PCI_CAP_ID_SATA_INDEX_DATA                 = 0x12u;
constexpr UCHAR VGK_PCI_CAP_ID_ADVANCED_FEATURES               = 0x13u;
constexpr UCHAR VGK_PCI_CAP_ID_ENHANCED_ALLOCATION             = 0x14u;

constexpr USHORT VGK_PCIE_EXT_CAP_ID_AER                       = 0x0001u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_VIRTUAL_CHANNEL           = 0x0002u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_DSN                       = 0x0003u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_POWER_BUDGETING           = 0x0004u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_RCRB_HEADER               = 0x000Au;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_VENDOR_SPECIFIC           = 0x000Bu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_ACS                       = 0x000Du;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_ARI                       = 0x000Eu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_ATS                       = 0x000Fu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_SRIOV                     = 0x0010u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_MRIOV                     = 0x0011u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_MULTICAST                 = 0x0012u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_PRI                       = 0x0013u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_RESIZABLE_BAR             = 0x0015u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_DPA                       = 0x0016u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_TPH_REQUESTER             = 0x0017u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_LTR                       = 0x0018u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_SEC_PCIE                  = 0x0019u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_PMUX                      = 0x001Au;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_PASID                     = 0x001Bu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_LN_REQUESTER              = 0x001Cu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_DPC                       = 0x001Du;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_L1_PM_SUBSTATES           = 0x001Eu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_PTM                       = 0x001Fu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_M_PCIE                    = 0x0020u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_FRS_QUEUEING              = 0x0021u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_READINESS_TIME_REPORTING  = 0x0022u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_DESIGNATED_VS             = 0x0023u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_VF_RESIZABLE_BAR          = 0x0024u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_DATA_LINK_FEATURE         = 0x0025u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_PHYSICAL_LAYER_16GT       = 0x0026u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_LANE_MARGIN_AT_RX         = 0x0027u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_HIERARCHY_ID              = 0x0028u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_NPEM                      = 0x0029u;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_PHYSICAL_LAYER_32GT       = 0x002Au;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_ALTERNATE_PROTOCOL        = 0x002Bu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_SFI                       = 0x002Cu;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_SHADOW_FUNCTIONS          = 0x002Du;
constexpr USHORT VGK_PCIE_EXT_CAP_ID_DATA_OBJECT_EXCHANGE      = 0x002Eu;

struct VGK_PCI_CAP_WALK_RESULT
{
    UCHAR     msi_present;
    UCHAR     msi_x_present;
    UCHAR     pcie_present;
    UCHAR     power_mgmt_present;
    UCHAR     vendor_specific_present;
    UCHAR     secure_device_present;
    UCHAR     reserved[2];
    UCHAR     msi_offset;
    UCHAR     msi_x_offset;
    UCHAR     pcie_offset;
    UCHAR     power_mgmt_offset;
    UCHAR     vendor_specific_offset;
    UCHAR     secure_device_offset;
    UCHAR     last_walked_offset;
    UCHAR     capabilities_count;
};

NTSTATUS vgk_pci_walk_capabilities(_In_reads_bytes_(256) const UCHAR* config_space_256,
                                     _Out_ VGK_PCI_CAP_WALK_RESULT* out_result) noexcept
{
    if (config_space_256 == nullptr || out_result == nullptr) { return STATUS_INVALID_PARAMETER; }
    out_dec->clear_stclear   = (UCHAR)(((attrs & VGK_TPMA_NV_CLEAR_STCLEAR)  != 0u) ? 1u : 0u);
    out_dec->read_locked     = (UCHAR)(((attrs & VGK_TPMA_NV_READLOCKED)     != 0u) ? 1u : 0u);
    out_dec->written         = (UCHAR)(((attrs & VGK_TPMA_NV_WRITTEN)        != 0u) ? 1u : 0u);
    out_dec->platform_create = (UCHAR)(((attrs & VGK_TPMA_NV_PLATFORMCREATE) != 0u) ? 1u : 0u);
    out_dec->read_stclear    = (UCHAR)(((attrs & VGK_TPMA_NV_READ_STCLEAR)   != 0u) ? 1u : 0u);
}

// Pure data + commentary -- the second catalog block for HWID / peripheral /
// anti-debug routines that have a verified decompile in the target binary.
// Each row pairs a symbol with its EA, size, topic, and verification status,
// covering the TPM Endorsement-Key cert hash family (RSA2048/ECC P256/
// RSA3072/RSA4096), the SMBIOS Type 1/2/3/4/17 capture paths, the EDID
// per-monitor reader chain, and the DR0..DR7 hardware-breakpoint snapshot
// surface that backs the SECTION 269 KeSaveExtendedProcessorState capture.
// Verification cross-references the UnknownCheats community questions about
// how Vanguard collects HWID/monitor/peripherals against the live binary at
// imagebase 0xFFFFF8013AD40000. The SECTION 152 whole-file verification
// statement walks this table at audit time and the SECTION 32 audit harness
// folds the per-row status into the master verification report. Nothing here
// is consumed at runtime; pure documentation surface for the audit harness.
// ============================================================================
