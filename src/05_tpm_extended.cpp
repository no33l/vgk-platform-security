// ============================================================================
// Overlay of module: 05_tpm_extended.cpp
// Certify/Sign/Hash/HMAC sequences, GetRandom, clock, SelfTest, Create/Load, Import, RSA, Startup
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
// SECTION 50 -- TPM2_Certify (CC 0x148) + TPM2_CertifyCreation (CC 0x14A)
//
// Certify generates a TPMS_ATTEST.type=TPM_ST_ATTEST_CERTIFY signed by an AK
// that binds the AK's view of an object's Name and qualifiedName. Vanguard's
// AK-binding chain verifier uses this to prove the AK lives inside the same
// TPM as the EK without trusting platform reports.
// ============================================================================

constexpr USHORT TPM_ST_ATTEST_NV_DIGEST= 0x801Cu;

struct TPM_CERTIFY_RESULT
{
    UCHAR  attest_blob[256];
    ULONG  attest_len;
    UCHAR  qualified_name[68];
    USHORT qualified_name_len;
    UCHAR  name[68];
    USHORT name_len;
    UCHAR  extra_data[64];
    USHORT extra_data_len;
    USHORT signature_alg;
    USHORT signature_hash_alg;
    UCHAR  signature_blob[512];
    ULONG  signature_len;
};

NTSTATUS tpm2_parse_certify_response(const UCHAR* rsp_buf, ULONG rsp_used,
                                     TPM_CERTIFY_RESULT* out) noexcept
{
    if (out == nullptr || rsp_used < 14u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp_buf + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    RtlZeroMemory(out, sizeof(*out));
    const UCHAR* p = rsp_buf + 10u;
    p += 4u;
    const USHORT attest_size = peek_be16(p); p += 2;
    if (attest_size == 0u || attest_size > sizeof(out->attest_blob)) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(out->attest_blob, p, attest_size);
    out->attest_len = attest_size;

    const UCHAR* a = p;
    const UCHAR* aend = p + attest_size;
    p += attest_size;

    const ULONG magic = peek_be32(a); a += 4;
    if (magic != TPM_GENERATED_VALUE) { return STATUS_DATA_ERROR; }
    const USHORT type = peek_be16(a); a += 2;
    if (type != TPM_ST_ATTEST_CERTIFY) { return STATUS_DATA_ERROR; }
    const USHORT qname_len = peek_be16(a); a += 2;
    if (qname_len > sizeof(out->qualified_name) || a + qname_len > aend) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(out->qualified_name, a, qname_len);
    out->qualified_name_len = qname_len;
    a += qname_len;
    const USHORT ed_len = peek_be16(a); a += 2;
    if (ed_len > sizeof(out->extra_data) || a + ed_len > aend) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(out->extra_data, a, ed_len);
    out->extra_data_len = ed_len;
    a += ed_len;
    a += 17u;
    if (a + 8 > aend) { return STATUS_INVALID_BUFFER_SIZE; }
    a += 8;
    if (a + 2 > aend) { return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT name_len = peek_be16(a); a += 2;
    if (name_len > sizeof(out->name) || a + name_len > aend) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(out->name, a, name_len);
    out->name_len = name_len;

    if (p + 4 > rsp_buf + rsp_used) { return STATUS_INVALID_BUFFER_SIZE; }
    out->signature_alg      = peek_be16(p); p += 2;
    out->signature_hash_alg = peek_be16(p); p += 2;
    switch (out->signature_alg)
    {
        case TPM_ALG_RSASSA:
        case TPM_ALG_RSAPSS:
        {
            const USHORT slen = peek_be16(p); p += 2;
            if (slen > sizeof(out->signature_blob) || p + slen > rsp_buf + rsp_used) { return STATUS_INVALID_BUFFER_SIZE; }
            RtlCopyMemory(out->signature_blob, p, slen);
            out->signature_len = slen;
            break;
        }
        case TPM_ALG_ECDSA:
        {
            const USHORT r_len = peek_be16(p); p += 2;
            if (p + r_len + 2 > rsp_buf + rsp_used) { return STATUS_INVALID_BUFFER_SIZE; }
            UCHAR* w = out->signature_blob;
            put_be16(w, r_len);
            RtlCopyMemory(w, p, r_len); w += r_len; p += r_len;
    {
        if (cmd_len != nullptr) { *cmd_len = 18u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 18u);
    put_be32(p, TPM_CC_PolicyCommandCode);
    put_be32(p, policy_session);
    put_be32(p, cc);
    *cmd_len = 18u;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_policy_get_digest(ULONG policy_session,
                                      UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 14u)
    {
        if (cmd_len != nullptr) { *cmd_len = 14u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 14u);
    put_be32(p, TPM_CC_PolicyGetDigest);
    put_be32(p, policy_session);
    *cmd_len = 14u;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_policy_auth_value(ULONG policy_session,
                                      UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 14u)
    {
        if (cmd_len != nullptr) { *cmd_len = 14u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 14u);
    put_be32(p, TPM_CC_PolicyAuthValue);
    put_be32(p, policy_session);
    *cmd_len = 14u;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_policy_locality(ULONG policy_session, UCHAR locality_mask,
                                    UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 15u)
    {
        if (cmd_len != nullptr) { *cmd_len = 15u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 15u);
    put_be32(p, policy_session);
    *p++ = locality_mask;
    *cmd_len = 15u;
    return STATUS_SUCCESS;
}

// SecureBoot deep readers for PK, KEK, db, dbx, dbt, dbr UEFI variables
// plus SecureBootMode, CustomMode, DeployedMode, MokList, and SbatLevel.
// Vanguard's SecureBoot evidence needs every signature DB walked for
// fingerprint extraction -- the goal is a stable identity vector that
// changes only when an admin reprovisions the Secure Boot databases.
// Reads via ExGetFirmwareEnvironmentVariable against global EFI GUIDs,
// walks each EFI_SIGNATURE_LIST blob; feeds the SECTION 24 HWID report.
// ============================================================================
// SECTION 51 -- Microsoft AIK CA root pinning + cert chain validation
//
// Microsoft issues per-device AIKs via its certificate authorities. Vanguard
// pins the well-known MSFT TPM root and intermediate CA subjects to confirm
// that any presented AK certificate chains back to a Microsoft-signed root.
// SHA-1 fingerprints (40 hex chars) for the chain anchors:
//   "Microsoft TPM Root Certificate Authority 2014"
//       SHA-1 thumbprint: 26B6C0D03D0D14B85B53A78C03BFD0BFBFA8F7D9
//   "Microsoft Root Certificate Authority 2011"
//       SHA-1 thumbprint: 8F43288AD272F3103B6FB1428485EA3014C0BCFE
//   "Microsoft Root Certificate Authority 2010"
//       SHA-1 thumbprint: 3B1EFD3A66EA28B16697394703A72CA340A05BD5
// ============================================================================

struct VGK_PINNED_ROOT
{
    UCHAR       sha1_thumb[20];
    const char* friendly_name;
};

static const VGK_PINNED_ROOT g_vgk_pinned_microsoft_roots[] = {
    { { 0x26, 0xB6, 0xC0, 0xD0, 0x3D, 0x0D, 0x14, 0xB8, 0x5B, 0x53,
        0xA7, 0x8C, 0x03, 0xBF, 0xD0, 0xBF, 0xBF, 0xA8, 0xF7, 0xD9 },
      "Microsoft TPM Root Certificate Authority 2014" },
    { { 0x8F, 0x43, 0x28, 0x8A, 0xD2, 0x72, 0xF3, 0x10, 0x3B, 0x6F,
        0xB1, 0x42, 0x84, 0x85, 0xEA, 0x30, 0x14, 0xC0, 0xBC, 0xFE },
      "Microsoft Root Certificate Authority 2011" },
    { { 0x3B, 0x1E, 0xFD, 0x3A, 0x66, 0xEA, 0x28, 0xB1, 0x66, 0x97,
        0x39, 0x47, 0x03, 0xA7, 0x2C, 0xA3, 0x40, 0xA0, 0x5B, 0xD5 },
      "Microsoft Root Certificate Authority 2010" },
};

NTSTATUS vgk_bcrypt_sha1(const UCHAR* data, ULONG data_len, UCHAR out[20]) noexcept
{
    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) { return s; }
    s = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (NT_SUCCESS(s))
    {
        s = BCryptHashData(hash, (PUCHAR)data, data_len, 0);
        if (NT_SUCCESS(s)) { s = BCryptFinishHash(hash, out, 20, 0); }
        BCryptDestroyHash(hash);
    }
    vgk_bcrypt_close_alg_safe(alg);
    return s;
}

BOOLEAN vgk_root_is_pinned_microsoft(const UCHAR* root_der, ULONG root_len) noexcept
{
    if (root_der == nullptr || root_len == 0u) { return FALSE; }
    UCHAR thumb[20];
    if (!NT_SUCCESS(vgk_bcrypt_sha1(root_der, root_len, thumb))) { return FALSE; }
    for (ULONG i = 0; i < sizeof(g_vgk_pinned_microsoft_roots) / sizeof(g_vgk_pinned_microsoft_roots[0]); ++i)
    {
        if (RtlEqualMemory(thumb, g_vgk_pinned_microsoft_roots[i].sha1_thumb, 20)) { return TRUE; }
    }
    return FALSE;
}

// TPM2_Sign (CC 0x15D) and TPM2_VerifySignature (CC 0x177) helpers. Need
// round-trip sign/verify inside the TPM and host-side for parity so AIK
// sign-test paths can confirm the device produced the signature rather
// than a hostile substitute. Sits on SECTION 9 builders + SECTION 36
// verifier; called on demand by AIK sign-test paths, not in the hot loop.
// tpm2_build_sign or tpm2_build_verify_signature, then parse the returned
// TPMT_SIGNATURE bytes for the algorithm in use.
// ============================================================================
// SECTION 52 -- TPM2_Sign (CC 0x15D) + TPM2_VerifySignature (CC 0x177)
// ============================================================================

NTSTATUS tpm2_build_sign(ULONG key_handle, const UCHAR* digest, USHORT digest_len,
                         USHORT scheme_alg, USHORT scheme_hash,
                         UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || digest == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 4u + 9u + 2u + digest_len + 2u + 2u + 2u + 4u + 2u;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_Sign);
    put_be32(p, key_handle);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, digest_len);
    RtlCopyMemory(p, digest, digest_len); p += digest_len;
    put_be16(p, scheme_alg);
    put_be16(p, scheme_hash);
    put_be16(p, 0x8024u);
    put_be32(p, 0x40000007u);
    put_be16(p, 0u);
    *cmd_len = total;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_verify_signature(ULONG key_handle,
                                     const UCHAR* digest, USHORT digest_len,
                                     USHORT sig_alg, USHORT sig_hash,
                                     const UCHAR* sig, USHORT sig_len,
                                     UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 2u + digest_len + 2u + 2u + 2u + sig_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_VerifySignature);
    put_be32(p, key_handle);
    put_be16(p, digest_len);
    RtlCopyMemory(p, digest, digest_len); p += digest_len;
    put_be16(p, sig_alg);
    put_be16(p, sig_hash);
    put_be16(p, sig_len);
    if (sig_len > 0u && sig != nullptr) { RtlCopyMemory(p, sig, sig_len); p += sig_len; }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// TPM2_Hash (CC 0x17D) and TPM2_HMAC (CC 0x155) helpers. Some test paths
// want the TPM to do the hash so a sanity check can compare against the
// host BCrypt result -- this catches firmware-TPM stacks that silently
// drop bits or swap byte order. The tpm2_build_hash builder takes the
// data buffer + data_len (USHORT), hash_alg (TPM_ALG_*), and hierarchy
// (TPM_RH_OWNER / TPM_RH_PLATFORM / TPM_RH_NULL), emitting total =
// 10 (header) + 2 (data_len) + data_len + 2 (hash_alg) + 4 (hierarchy)
// bytes onto the wire. HMAC is similar but takes a key_handle and yields
// an HMAC tag bound to that key. Sits on SECTION 9 builders, symmetric
// to SECTION 6 BCrypt wrappers; called only by the SECTION 30 self-test
// path. Pairs with SECTION 54 HashSequence for streaming-input cases
// where the input exceeds TPM_PT_MAX_DIGEST_BUFFER (~1024 bytes).
// ============================================================================
// SECTION 53 -- TPM2_Hash (CC 0x17D) + TPM2_HMAC (CC 0x155)
// ============================================================================

constexpr ULONG TPM_CC_HMAC = 0x00000155u;

NTSTATUS tpm2_build_hash(const UCHAR* data, USHORT data_len,
                         USHORT hash_alg, ULONG hierarchy,
                         UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 2u + data_len + 2u + 4u;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_Hash);
    put_be16(p, data_len);
    if (data_len > 0u && data != nullptr) { RtlCopyMemory(p, data, data_len); p += data_len; }
    put_be16(p, hash_alg);
    put_be32(p, hierarchy);
    *cmd_len = total;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_hmac(ULONG key_handle,
                         const UCHAR* buffer, USHORT buffer_len, USHORT hash_alg,
                         UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 4u + 9u + 2u + buffer_len + 2u;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_HMAC);
    put_be32(p, key_handle);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, buffer_len);
    if (buffer_len > 0u && buffer != nullptr) { RtlCopyMemory(p, buffer, buffer_len); p += buffer_len; }
    put_be16(p, hash_alg);
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// HashSequence and EventSequence -- the crypto-agile PCR_Event helpers.
// Multi-bank PCR extends need a sequence so every bank agrees on the input
// stream; without it a bank-specific length quirk could leave the SHA-1
// bank and the SHA-256 bank with divergent measurements. Sits on the
// SECTION 9 builders and the SECTION 290 per-bank parallel-extend path.
// Called per measured event the orchestrator wants to log to PCRs. The
// flow is TPM2_HashSequenceStart (CC 0x186), repeated SequenceUpdate
// (0x15C), then EventSequenceComplete (0x185) to extend across all banks.
// ============================================================================
// SECTION 54 -- HashSequence + EventSequence (crypto-agile PCR_Event)
//
// TPM2_HashSequenceStart  (CC 0x186) -> handle
// TPM2_SequenceUpdate     (CC 0x15C) -> append data, repeat
// TPM2_SequenceComplete   (CC 0x13E) -> final digest
// TPM2_EventSequenceComplete(CC 0x185)-> extend into PCR across all banks
// ============================================================================

constexpr ULONG TPM_CC_HashSequenceStart      = 0x00000186u;
constexpr ULONG TPM_CC_SequenceUpdate         = 0x0000015Cu;
constexpr ULONG TPM_CC_SequenceComplete       = 0x0000013Eu;
constexpr ULONG TPM_CC_EventSequenceComplete  = 0x00000185u;

NTSTATUS tpm2_build_hash_sequence_start(USHORT hash_alg,
                                        const UCHAR* auth, USHORT auth_len,
                                        UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 2u + auth_len + 2u;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_HashSequenceStart);
    put_be16(p, auth_len);
    if (auth_len > 0u && auth != nullptr) { RtlCopyMemory(p, auth, auth_len); p += auth_len; }
    put_be16(p, hash_alg);
    *cmd_len = total;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_sequence_update(ULONG seq_handle,
                                     const UCHAR* data, USHORT data_len,
                                     UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 4u + 9u + 2u + data_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_SequenceUpdate);
    put_be32(p, seq_handle);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, data_len);
    if (data_len > 0u && data != nullptr) { RtlCopyMemory(p, data, data_len); p += data_len; }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_event_sequence_complete(ULONG pcr_handle, ULONG seq_handle,
                                            const UCHAR* buffer, USHORT buffer_len,
                                            UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 4u + 4u + 18u + 2u + buffer_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_EventSequenceComplete);
    put_be32(p, pcr_handle);
    put_be32(p, seq_handle);
    put_be32(p, 18u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, buffer_len);
    if (buffer_len > 0u && buffer != nullptr) { RtlCopyMemory(p, buffer, buffer_len); p += buffer_len; }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// TPM2_GetRandom (CC 0x17B) and TPM2_StirRandom (CC 0x146) helpers. The
// preference for TPM RNG over host RNG for attestation nonces sidesteps
// host entropy questions: if host RNG is suspect (e.g. the SECTION 102
// vendor classifier detected a virtualized CPU with suspicious RDRAND
// behavior), the TPM hardware RNG is one of the few sources still
// trustworthy. The tpm2_build_get_random builder takes a bytes_requested
// USHORT count and emits the 12-byte wire frame (TPM_ST_NO_SESSIONS +
// size 12 + CC 0x17B + bytes_requested). StirRandom feeds external
// entropy back into the TPM's RNG pool. Sits on SECTION 9 builders, feeds
// nonce input for SECTION 36 Quote challenges and SECTION 39 master
// attestation orchestrator. Called per nonce generation and stir reseed.
// Mixed hot/cold -- GetRandom hot for attest, StirRandom cold.
// ============================================================================
// SECTION 55 -- TPM2_GetRandom (CC 0x17B) + TPM2_StirRandom (CC 0x146)
// ============================================================================

NTSTATUS tpm2_build_get_random(USHORT bytes_requested, UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 12u)
    {
        if (cmd_len != nullptr) { *cmd_len = 12u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 12u);
    put_be32(p, TPM_CC_GetRandom);
    put_be16(p, bytes_requested);
    *cmd_len = 12u;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_stir_random(const UCHAR* in_data, USHORT in_len,
                                UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 9u + 2u + in_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_StirRandom);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, in_len);
    if (in_len > 0u && in_data != nullptr) { RtlCopyMemory(p, in_data, in_len); p += in_len; }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// TPM2_ReadClock (CC 0x181), TPM2_ClockSet (CC 0x128), and
// TPM2_ClockRateAdjust (CC 0x130). TPM clock readback gives a monotonic
// timestamp that survives host reboots -- the only counter on the platform
// that can, since the TPM clock keeps running through power cycles and
// even most clear-events. The TPMS_TIME_INFO response struct carries a
// 64-bit time value plus the TPMS_CLOCK_INFO block (clock + resetCount +
// restartCount + safe flag) that anchors temporal evidence. The
// tpm2_build_read_clock builder takes no parameters and emits a 10-byte
// header-only frame. Sits on SECTION 9 builders and feeds the SECTION
// 259 TSC drift-watcher; called on every heartbeat by SECTION 189
// periodic orchestrator and whenever the TSC watcher needs an anchor for
// emulator-detection timing. Hot path on heartbeat ticks.
// ============================================================================
// SECTION 56 -- TPM2_ReadClock (CC 0x181) + TPM2_ClockSet + ClockRateAdjust
// ============================================================================

constexpr ULONG TPM_CC_ReadClock        = 0x00000181u;
constexpr ULONG TPM_CC_ClockSet         = 0x00000128u;
constexpr ULONG TPM_CC_ClockRateAdjust  = 0x00000130u;

struct TPMS_TIME_INFO
{
    ULONGLONG       time;
    TPMS_CLOCK_INFO clock_info;
};

NTSTATUS tpm2_build_read_clock(UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 10u)
    {
        if (cmd_len != nullptr) { *cmd_len = 10u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 10u);
    put_be32(p, TPM_CC_ReadClock);
    *cmd_len = 10u;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_parse_read_clock(const UCHAR* rsp_buf, ULONG rsp_used,
                               TPMS_TIME_INFO* out) noexcept
{
    if (out == nullptr || rsp_used < 10u + 8u + 8u + 4u + 4u + 1u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp_buf + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* p = rsp_buf + 10u;
    ULONGLONG hi = peek_be32(p); p += 4;
    ULONGLONG lo = peek_be32(p); p += 4;
    out->time = (hi << 32) | lo;
    hi = peek_be32(p); p += 4;
    lo = peek_be32(p); p += 4;
    out->clock_info.clock         = (hi << 32) | lo;
    out->clock_info.resetCount    = peek_be32(p); p += 4;
    out->clock_info.restartCount  = peek_be32(p); p += 4;
    out->clock_info.safe          = *p;
    return STATUS_SUCCESS;
}

// TPM2_SelfTest (CC 0x143), TPM2_IncrementalSelfTest (0x142), and
// TPM2_GetTestResult (0x17C) helpers. On startup I want the TPM to self-
// test before I trust its crypto operations; an untested TPM could be in
// a degraded mode where some algorithms misbehave silently. Sits on the
// SECTION 9 builders and gets called from the SECTION 39 orchestrator
// init path. Runs once at module load plus on every diagnostic refresh.
// Mechanically: tpm2_build_self_test, submit, then poll GetTestResult
// until the device reports completion.
// ============================================================================
// SECTION 57 -- TPM2_SelfTest (CC 0x143) + IncrementalSelfTest + GetTestResult
// ============================================================================

constexpr ULONG TPM_CC_IncrementalSelfTest  = 0x00000142u;
constexpr ULONG TPM_CC_GetTestResult        = 0x0000017Cu;

NTSTATUS tpm2_build_get_test_result(UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 10u)
    {
        if (cmd_len != nullptr) { *cmd_len = 10u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 10u);
    put_be32(p, TPM_CC_GetTestResult);
    *cmd_len = 10u;
    return STATUS_SUCCESS;
}

// TPM2_Create (CC 0x153), CreatePrimary, CreateLoaded (CC 0x191), Load
// (CC 0x157), LoadExternal (CC 0x167), and ObjectChangeAuth (CC 0x150)
// helpers. Key-creation primitives needed so the driver can provision new
// AIKs host-side -- Create makes a transient child key, CreatePrimary
// makes one under a hierarchy seed, CreateLoaded combines both in a single
// command for atomic provisioning, Load instantiates an off-TPM blob into
// the transient table, and LoadExternal pulls a public-only key in for
// signature verification. The tpm2_build_create_primary builder takes
// hierarchy + in_sensitive blob + in_public template + outside_info +
// creation_pcrs selection. Sits on SECTION 9 builders; cold path -- only
// AIK provisioning and re-provisioning calls these through SECTION 83's
// RSA-2048-SHA-256 AIK template. Pairs with SECTION 59 ContextSave.
// ============================================================================
// SECTION 58 -- TPM2_Create + CreatePrimary + CreateLoaded + Load + LoadExternal
// ============================================================================

constexpr ULONG TPM_CC_Create        = 0x00000153u;
constexpr ULONG TPM_CC_CreateLoaded  = 0x00000191u;
constexpr ULONG TPM_CC_Load          = 0x00000157u;
constexpr ULONG TPM_CC_LoadExternal  = 0x00000167u;
constexpr ULONG TPM_CC_ObjectChangeAuth = 0x00000150u;

NTSTATUS tpm2_build_create_primary(ULONG hierarchy,
                                   const UCHAR* in_sensitive, ULONG in_sensitive_len,
                                   const UCHAR* in_public,    ULONG in_public_len,
                                   const UCHAR* outside_info, USHORT outside_info_len,
                                   const UCHAR* creation_pcrs, ULONG creation_pcrs_len,
                                   UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || in_sensitive == nullptr || in_public == nullptr)
    { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 4u + 9u + 2u + in_sensitive_len + 2u + in_public_len
                      + 2u + outside_info_len + creation_pcrs_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_CreatePrimary);
    put_be32(p, hierarchy);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, (USHORT)in_sensitive_len);
    RtlCopyMemory(p, in_sensitive, in_sensitive_len); p += in_sensitive_len;
    put_be16(p, (USHORT)in_public_len);
    RtlCopyMemory(p, in_public, in_public_len); p += in_public_len;
    put_be16(p, outside_info_len);
    if (outside_info_len > 0u && outside_info != nullptr)
    { RtlCopyMemory(p, outside_info, outside_info_len); p += outside_info_len; }
    if (creation_pcrs_len > 0u && creation_pcrs != nullptr)
    { RtlCopyMemory(p, creation_pcrs, creation_pcrs_len); p += creation_pcrs_len; }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_load(ULONG parent_handle,
                          const UCHAR* in_private, USHORT in_private_len,
                          const UCHAR* in_public,  USHORT in_public_len,
                          UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 4u + 9u + 2u + in_private_len + 2u + in_public_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_Load);
    put_be32(p, parent_handle);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, in_private_len);
    if (in_private_len > 0u && in_private != nullptr) { RtlCopyMemory(p, in_private, in_private_len); p += in_private_len; }
    put_be16(p, in_public_len);
    if (in_public_len > 0u && in_public != nullptr) { RtlCopyMemory(p, in_public, in_public_len); p += in_public_len; }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// TPM2_ContextSave (CC 0x162), ContextLoad (CC 0x161), and EvictControl
// (CC 0x120). Flush and reload TPM contexts to keep the transient handle
// count low -- TPMs have a small transient object table (typically 3-7
// slots) and long-running paths exhaust it quickly without explicit
// rotation. ContextSave serializes a transient handle into an off-TPM
// blob, ContextLoad re-instantiates it back into a slot, and EvictControl
// promotes a handle to persistent state (or demotes one). The
// tpm2_build_context_save helper takes a handle and emits the 14-byte
// wire frame (TPM_ST_NO_SESSIONS + 14 size + CC 0x162 + 4-byte handle).
// Sits on SECTION 9 builders, called by SECTION 39 attestation orchestrator
// when the transient table approaches its cap during multi-key flows.
// Pairs with SECTION 58 Create/CreatePrimary/Load for the key lifecycle.
// ============================================================================
// SECTION 59 -- TPM2_ContextSave + ContextLoad + EvictControl
// ============================================================================

constexpr ULONG TPM_CC_ContextSave  = 0x00000162u;
constexpr ULONG TPM_CC_ContextLoad  = 0x00000161u;
constexpr ULONG TPM_CC_EvictControl = 0x00000120u;

NTSTATUS tpm2_build_context_save(ULONG handle, UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 14u)
    {
        if (cmd_len != nullptr) { *cmd_len = 14u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 14u);
    put_be32(p, TPM_CC_ContextSave);
    put_be32(p, handle);
    *cmd_len = 14u;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_evict_control(ULONG auth, ULONG object_handle,
                                  ULONG persistent_handle,
                                  UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 35u)
    {
        if (cmd_len != nullptr) { *cmd_len = 35u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, 35u);
    put_be32(p, TPM_CC_EvictControl);
    put_be32(p, auth);
    put_be32(p, object_handle);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be32(p, persistent_handle);
    *cmd_len = 35u;
    return STATUS_SUCCESS;
}

// SECTION 60 was the original home of the NV_Read and NV_ReadPublic helper
// pair, but the duplicate code paths were merged upward into the SECTION 8
// transport and SECTION 10 wire-call helpers so callers only need one
// canonical implementation. Originally housed tpm2_build_nv_read (CC 0x14E)
// and tpm2_build_nv_read_public (CC 0x169) frame builders that the EK
// extraction in SECTION 16 needs; the consolidated versions in SECTION 9
// builders + SECTION 10 high-level wire helpers carry the canonical
// implementations. Banner stays as a vestigial marker at the historical
// section number; no code lives here. The SECTION 87 TPM2 ACPI parser and
// SECTION 251 NV index type catalog reference these helpers downstream.
// Cold path -- no runtime cost since no code; pure documentation marker.
// ============================================================================
// SECTION 60 -- (consolidated into earlier §8 / §10 NV_Read + NV_ReadPublic
//               wire builders; aliases retained below for callers)
// ============================================================================

// SECTION 61 holds the TPM2_Startup and TPM2_Shutdown wire-frame builders
// (CC 0x144 and CC 0x145). Startup primes the TPM at boot with one of two
// shutdown types: SU_CLEAR (0x0000) for an initial startup that resets
// PCRs to defaults, or SU_STATE (0x0001) to restore prior state from a
// suspend. The TPM driver normally drives these, but Vanguard keeps the
// builders ready for the case where the firmware TPM presents a custom
// IOCTL channel that needs a Startup frame after a sleep cycle. The
// tpm2_build_startup helper takes a 16-bit startup_type, validates a
// minimum 12-byte buffer, then emits TPM_ST_NO_SESSIONS + 12-byte size +
// CC + startup_type into cmd. Sits on SECTION 9 builders; cold path,
// fires only during platform Startup or recovery flows. Pairs with
// SECTION 57's SelfTest commands for post-Startup verification.
// ============================================================================
// SECTION 61 -- TPM2_Startup (CC 0x144) + TPM2_Shutdown (CC 0x145)
//
// SU_CLEAR  = 0x0000 -> initial startup, PCRs reset to defaults
// SU_STATE  = 0x0001 -> restore prior state from suspend
// ============================================================================

constexpr USHORT TPM_SU_CLEAR    = 0x0000u;
constexpr USHORT TPM_SU_STATE    = 0x0001u;

NTSTATUS tpm2_build_startup(USHORT startup_type, UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 12u)
    {
        if (cmd_len != nullptr) { *cmd_len = 12u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 12u);
    put_be32(p, TPM_CC_Startup);
    put_be16(p, startup_type);
    *cmd_len = 12u;
    return STATUS_SUCCESS;
}

NTSTATUS tpm2_build_shutdown(USHORT shutdown_type, UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr || *cmd_len < 12u)
    {
        if (cmd_len != nullptr) { *cmd_len = 12u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 12u);
    put_be32(p, TPM_CC_Shutdown);
    put_be16(p, shutdown_type);
    *cmd_len = 12u;
    return STATUS_SUCCESS;
}

// TPM2_Import (CC 0x156), TPM2_Duplicate (CC 0x14B), and TPM2_Rewrap
// (CC 0x152) helpers. Key-migration primitives -- Import lets an external
// key blob enter a TPM parent, Duplicate exports an existing object under
// a new wrapping parent, and Rewrap moves a duplicated blob from one
// outer-parent encryption to another. Only Import is wired up in
// practice for the AIK loading path, but the trio is kept together for
// symmetry with the spec section. The tpm2_build_duplicate builder takes
// object_handle, new_parent, enc_key + enc_key_len, plus sym_alg /
// sym_keybits / sym_mode for the symmetric inner wrapper. Total wire size
// is 10 (header) + 4 (object) + 4 (new_parent) + 4 (enc_key handle) + 9
// (sym definition) + 2 + enc_key_len + 6. Sits on SECTION 9 builders;
// cold path -- never called per heartbeat, only migration / duplicate.
// ============================================================================
// SECTION 62 -- TPM2_Import (CC 0x156) + TPM2_Duplicate + TPM2_Rewrap
// ============================================================================

constexpr ULONG TPM_CC_Import    = 0x00000156u;
constexpr ULONG TPM_CC_Duplicate = 0x0000014Bu;
constexpr ULONG TPM_CC_Rewrap    = 0x00000152u;

NTSTATUS tpm2_build_duplicate(ULONG object_handle, ULONG new_parent,
                              const UCHAR* enc_key, USHORT enc_key_len,
                              USHORT sym_alg, USHORT sym_keybits, USHORT sym_mode,
                              UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 4u + 4u + 9u + 2u + enc_key_len + 6u;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_Duplicate);
    put_be32(p, object_handle);
    put_be32(p, new_parent);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, enc_key_len);
    if (enc_key_len > 0u && enc_key != nullptr) { RtlCopyMemory(p, enc_key, enc_key_len); p += enc_key_len; }
    put_be16(p, sym_alg);
    put_be16(p, sym_keybits);
    put_be16(p, sym_mode);
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// TPM2_RSA_Encrypt (CC 0x174) and TPM2_RSA_Decrypt (CC 0x159). Host-side
// RSA operations driven through the TPM. Some attestation paths want the
// TPM to do the RSA work so the private key never leaves the device --
// a fundamentally different trust model than the BCrypt-host equivalent
// where the key gets exposed in driver memory. The tpm2_build_rsa_encrypt
// builder takes key_handle, message + msg_len, scheme_alg, scheme_hash,
// and an optional OAEP label + label_len. Total wire size is 10 (header)
// + 4 (key) + 2 (msg_len) + msg_len + 2 (scheme) + 2 (hash) + 2
// (label_len) + label_len. Pairs with SECTION 62 Import/Duplicate/Rewrap
// for the full key-management trio. Sits on SECTION 9 builders; rarely
// used. Cold path -- never fires outside specific attestation flows that
// keep RSA inside the TPM boundary.
// ============================================================================
// SECTION 63 -- TPM2_RSA_Encrypt + TPM2_RSA_Decrypt
// ============================================================================

constexpr ULONG TPM_CC_RSA_Encrypt = 0x00000174u;
constexpr ULONG TPM_CC_RSA_Decrypt = 0x00000159u;

NTSTATUS tpm2_build_rsa_encrypt(ULONG key_handle,
                                const UCHAR* message, USHORT msg_len,
                                USHORT scheme_alg, USHORT scheme_hash,
                                const UCHAR* label, USHORT label_len,
                                UCHAR* cmd, ULONG* cmd_len) noexcept
{
    if (cmd == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = 10u + 4u + 2u + msg_len + 2u + 2u + 2u + label_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_RSA_Encrypt);
    put_be32(p, key_handle);
    put_be16(p, msg_len);
    if (msg_len > 0u && message != nullptr) { RtlCopyMemory(p, message, msg_len); p += msg_len; }
    put_be16(p, scheme_alg);
    put_be16(p, scheme_hash);
    put_be16(p, label_len);
    put_be32(p, 14u);
    put_be32(p, TPM_CC_ECDH_KeyGen);
    put_be32(p, key_handle);
    *cmd_len = 14u;
    return STATUS_SUCCESS;
}

// EFI_SIGNATURE_LIST and EFI_SIGNATURE_DATA parser for db/dbx UEFI
// signature databases. SecureBoot db and dbx are nested signature lists --
// each entry has to be walked and fingerprinted individually so the HWID
// identity vector stays stable. Per UEFI Specification 2.10 sec. 32.4.1
// / 32.5.3, a signature database is a concatenated list of
// EFI_SIGNATURE_LIST headers, each followed by N EFI_SIGNATURE_DATA
// entries. The common SignatureType GUIDs are EFI_CERT_SHA256_GUID
// (C1C41626-504C-4092-ACA9-41F936934328), EFI_CERT_RSA2048_GUID
// (3C5766E8-269C-4E34-AA14-ED776E85B3B6), EFI_CERT_X509_GUID
// (A5C059A1-94E4-4AA7-87B5-AB155C2BF072), and EFI_CERT_SHA1_GUID
// (826CA512-CF10-4AC9-B187-BE01496631BD). Used by SECTION 44 SecureBoot
// deep readers; runs per HWID composite refresh and on SecureBoot change.
// ============================================================================
