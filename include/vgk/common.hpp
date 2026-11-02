#pragma once
// Shared forward declarations and orientation types for the split reference.
// The original monorepo relied on a private precompiled.hpp (WDK / kernel
// headers). That header is intentionally not redistributed here.

// Minimal stand-ins so static readers understand the surface. Replace with
// real WDK types when building a private analysis harness.

#ifndef VGK_COMMON_HPP
#define VGK_COMMON_HPP

#ifdef _MSC_VER
#  include <ntddk.h>
#else
// Host-side documentation build: opaque substitutes.
typedef unsigned long       ULONG;
typedef unsigned long long  ULONG_PTR;
typedef unsigned long long  ULONGLONG;
typedef long                NTSTATUS;
typedef void*               PVOID;
typedef const void*         PCVOID;
typedef unsigned char       UCHAR;
typedef unsigned short      USHORT;
typedef unsigned char       BOOLEAN;
typedef long long           LONGLONG;
typedef size_t              SIZE_T;
typedef char*               PSTR;
typedef const char*         PCSTR;
typedef wchar_t*            PWSTR;
typedef const wchar_t*      PCWSTR;
typedef void*               HANDLE;
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _GUID { unsigned long Data1; unsigned short Data2; unsigned short Data3; unsigned char Data4[8]; } GUID, *LPGUID;
#  ifndef NTAPI
#    define NTAPI
#  endif
#  ifndef _Out_opt_
#    define _Out_opt_
#  endif
#  ifndef _In_
#    define _In_
#  endif
#  ifndef _Out_
#    define _Out_
#  endif
#endif

#include <bcrypt.h>

#ifndef BCRYPT_SHA256_ALGORITHM
#  define BCRYPT_SHA256_ALGORITHM   L"SHA256"
#endif
#ifndef BCRYPT_SHA1_ALGORITHM
#  define BCRYPT_SHA1_ALGORITHM     L"SHA1"
#endif

// External kernel imports referenced by the reconstruction.
extern "C" {
    NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
    NTSTATUS NTAPI ExGetFirmwareEnvironmentVariable(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG);
}

// Suspicion / evidence sinks provided by the wider research harness.
namespace vgk { namespace susp {
    void accumulate(ULONG detection_bit, ULONG magnitude) noexcept;
}}
namespace vgk { namespace evidence {
    NTSTATUS push_packet(ULONG tag, const void* payload, ULONG length) noexcept;
}}

// Audit harness types (SECTION 0).
extern "C" {

typedef enum _VGK_TPM_TRIPLE_STATUS {
    VGK_TPM_STATUS_PASS    = 0,
    VGK_TPM_STATUS_PARTIAL = 1,
    VGK_TPM_STATUS_FAIL    = 2,
    VGK_TPM_STATUS_UNKNOWN = 3,
} VGK_TPM_TRIPLE_STATUS;

typedef struct _VGK_TPM_AUDIT_ROW {
    PCSTR                  topic;
    ULONG_PTR              ea;
    PCSTR                  symbol;
    SIZE_T                 size_bytes;
    PCSTR                  segment;
    VGK_TPM_TRIPLE_STATUS  v1_decompile;
    VGK_TPM_TRIPLE_STATUS  v2_disasm;
    VGK_TPM_TRIPLE_STATUS  v3_xref;
    VGK_TPM_TRIPLE_STATUS  overall;
    PCSTR                  evidence;
    PCSTR                  notes;
} VGK_TPM_AUDIT_ROW;

extern const VGK_TPM_AUDIT_ROW g_vgk_tpm_audit_rows[];
extern const ULONG             g_vgk_tpm_audit_row_count;
NTSTATUS vgk_tpm_audit_all(_Out_opt_ ULONG* out_pass_count,
                           _Out_opt_ ULONG* out_partial_count,
                           _Out_opt_ ULONG* out_unknown_count);

} // extern "C"

#endif // VGK_COMMON_HPP