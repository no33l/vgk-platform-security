// ============================================================================
// Overlay of module: 02_tpm_core.cpp
// TPM 2.0 builders/parsers, PCR readers, TPM 1.2 fallback, capabilities, ASN.1/EK, emulator, PPI, severity
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
// SECTION 9 -- TPM 2.0 command builders
//              Found by the user researcher, then confirmed and verified bit-for-bit against the binary database at 0xFFFFF8013AE701BC
//              (SHA-1 monolith host). These helpers (tpm2_build_read_public,
//              tpm2_build_get_capability, tpm2_build_nv_read_public) emit
//              TPM 2.0 Library Part 3 command frames (TPM_ST_NO_SESSIONS /
//              size / commandCode) via put_be16/put_be32, matching the wire
//              output of the inlined emitters at that VA.
// ============================================================================

// Builds a TPM2_ReadPublic command (14 bytes) for the given EK persistent
// handle.
NTSTATUS tpm2_build_read_public(ULONG ek_handle, UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || *cmd_len < 14u)
    {
        if (cmd_len != nullptr) { *cmd_len = 14u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 14u);
    put_be32(p, TPM_CC_ReadPublic);
    put_be32(p, ek_handle);
    *cmd_len = 14u;
    return STATUS_SUCCESS;
}

// Builds a TPM2_GetCapability command (22 bytes).
NTSTATUS tpm2_build_get_capability(ULONG cap, ULONG prop, ULONG count,
                                   UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || *cmd_len < 22u)
    {
        if (cmd_len != nullptr) { *cmd_len = 22u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 22u);
    put_be32(p, TPM_CC_GetCapability);
    put_be32(p, cap);
    put_be32(p, prop);
    put_be32(p, count);
    *cmd_len = 22u;
    return STATUS_SUCCESS;
}

// Found by the user researcher, then confirmed and verified bit-for-bit against the binary database at 0xFFFFF8013AE701BC. The
// TPM_CC_NV_ReadPublic (0x169) emission is the inlined emitter inside the
// SHA-1 monolith at that VA (5 of 7 immediate hits live in that host).
// Frame: tag(2) + size(4) + cc(4) + nvIndex(4) = 14 bytes,
// TPM_ST_NO_SESSIONS, TPM_CC_NV_ReadPublic = 0x169.
NTSTATUS tpm2_build_nv_read_public(ULONG nv_index, UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || *cmd_len < 14u)
    if (cmd_out == nullptr || cmd_len == nullptr || *cmd_len < 14u)
    {
        if (cmd_len != nullptr) { *cmd_len = 14u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 14u);
    put_be32(p, TPM_CC_NV_ReadPublic);
    put_be32(p, nv_index);
    *cmd_len = 14u;
    return STATUS_SUCCESS;
}

// Builds a TPM2_NV_Read command using TPM_RH_ENDORSEMENT as the auth handle
// and a null-auth password session (TPM_RS_PW + zero nonce + zero attrs +
// zero hmac). Size and offset are bounds within the NV index.
NTSTATUS tpm2_build_nv_read(ULONG nv_index, USHORT size, USHORT offset,
                            UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG required = 35u;
    if (*cmd_len < required) { *cmd_len = required; return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, required);
    put_be32(p, TPM_CC_NV_Read);
    put_be32(p, TPM_RH_ENDORSEMENT);
    put_be32(p, nv_index);
    put_be32(p, 9u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u);
    *p++ = 0u;
    put_be16(p, 0u);
    put_be16(p, size);
    put_be16(p, offset);
    *cmd_len = required;
    return STATUS_SUCCESS;
}

// Builds a TPM2_SelfTest command (11 bytes). full_test = 1 means full self
// test; 0 = incremental.
NTSTATUS tpm2_build_self_test(UCHAR full_test, UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || *cmd_len < 11u)
    {
        if (cmd_len != nullptr) { *cmd_len = 11u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 11u);
    put_be32(p, TPM_CC_SelfTest);
    *p++ = full_test ? 1u : 0u;
    *cmd_len = 11u;
    return STATUS_SUCCESS;
}

// Builds a TPM2_Quote command. signHandle is the AK; nonce + sig scheme +
// PCR selection are caller-supplied. Auth area is a TPM_RS_PW password
// session with empty HMAC.
NTSTATUS tpm2_build_quote(ULONG sign_handle,
                          const UCHAR* nonce, USHORT nonce_len,
                          USHORT scheme, USHORT hash_alg,
                          USHORT bank,  UCHAR bm_lo, UCHAR bm_mid, UCHAR bm_hi,
                          UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || nonce == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONG auth_area = 9u;
    const ULONG total = sizeof(TPM2_HEADER) + 4u + 4u + auth_area
                      + 2u + nonce_len + 4u + 4u + sizeof(TPMS_PCR_SELECTION);
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }

    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_Quote);
    put_be32(p, sign_handle);
    put_be32(p, auth_area);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u);
    *p++ = 0u;
    put_be16(p, 0u);
    put_be16(p, nonce_len);
    RtlCopyMemory(p, nonce, nonce_len); p += nonce_len;
    put_be16(p, scheme);
    put_be16(p, hash_alg);
    put_be32(p, 1u);
    put_be16(p, bank);
    *p++ = 3u;
    *p++ = bm_lo;
    *p++ = bm_mid;
    *p++ = bm_hi;
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// Builds a TPM2_StartAuthSession command. tpmKey/bind are typically
// TPM_RH_NULL for unbound/unsalted sessions. nonceCaller must be >= 16
// bytes. encryptedSalt is empty when tpmKey == TPM_RH_NULL.
NTSTATUS tpm2_build_start_auth_session(ULONG tpm_key, ULONG bind,
                                       const UCHAR* nonce_caller, USHORT nonce_len,
                                       const UCHAR* enc_salt,     USHORT enc_salt_len,
                                       UCHAR session_type, USHORT sym_alg,
                                       USHORT sym_key_bits, USHORT sym_mode,
                                       USHORT auth_hash,
                                       UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || nonce_caller == nullptr || nonce_len < 16u)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONG sym_def_bytes = (sym_alg == TPM_ALG_NULL) ? 2u : 6u;
    const ULONG total = sizeof(TPM2_HEADER) + 4u + 4u + 2u + nonce_len
                      + 2u + enc_salt_len + 1u + sym_def_bytes + 2u;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }

    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_StartAuthSession);
    put_be32(p, tpm_key);
    put_be32(p, bind);
    put_be16(p, nonce_len);
    RtlCopyMemory(p, nonce_caller, nonce_len); p += nonce_len;
    put_be16(p, enc_salt_len);
    if (enc_salt_len > 0u && enc_salt != nullptr)
    {
        RtlCopyMemory(p, enc_salt, enc_salt_len); p += enc_salt_len;
    }
    *p++ = session_type;
    put_be16(p, sym_alg);
    if (sym_alg != TPM_ALG_NULL)
    {
        put_be16(p, sym_key_bits);
        put_be16(p, sym_mode);
    }
    put_be16(p, auth_hash);
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// Builds a TPM2_PolicyPCR command. When pcr_digest_len is 0 the TPM computes
// the digest itself from current PCRs; non-zero asserts a fixed value the
// TPM must match.
NTSTATUS tpm2_build_policy_pcr(ULONG policy_session,
                               const UCHAR* pcr_digest, USHORT pcr_digest_len,
                               USHORT bank, UCHAR bm_lo, UCHAR bm_mid, UCHAR bm_hi,
                               UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = sizeof(TPM2_HEADER) + 4u + 2u + pcr_digest_len + 4u
                      + sizeof(TPMS_PCR_SELECTION);
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }

    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_PolicyPCR);
    put_be32(p, policy_session);
    put_be16(p, pcr_digest_len);
    if (pcr_digest_len > 0u && pcr_digest != nullptr)
    {
        RtlCopyMemory(p, pcr_digest, pcr_digest_len); p += pcr_digest_len;
    }
    put_be32(p, 1u);
    put_be16(p, bank);
    *p++ = 3u;
    *p++ = bm_lo;
    *p++ = bm_mid;
    *p++ = bm_hi;
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// Builds a TPM2_Certify command. objectHandle is the object being
// certified; signHandle is the AK doing the signing. The auth area is two
// TPM_RS_PW password sessions with empty HMACs.
NTSTATUS tpm2_build_certify(ULONG object_handle, ULONG sign_handle,
                            const UCHAR* nonce, USHORT nonce_len,
                            USHORT scheme, USHORT hash_alg,
                            UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || nonce == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONG auth_area = 9u + 9u;
    const ULONG total = sizeof(TPM2_HEADER) + 4u + 4u + 4u + auth_area
                      + 2u + nonce_len + 2u + 2u;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }

    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_Certify);
    put_be32(p, object_handle);
    put_be32(p, sign_handle);
    put_be32(p, auth_area);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be16(p, nonce_len);
    RtlCopyMemory(p, nonce, nonce_len); p += nonce_len;
    put_be16(p, scheme);
    put_be16(p, hash_alg);
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// Builds a TPM2_ActivateCredential command. activateHandle = AK; keyHandle
// = EK. The credentialBlob is the TPM2B_ID_OBJECT produced by
// MakeCredential; secret is the TPM2B_ENCRYPTED_SECRET (OAEP-wrapped seed).
// The second auth session is a Policy session that satisfies the EK
// PolicySecret(TPM_RH_ENDORSEMENT) policy.
NTSTATUS tpm2_build_activate_credential(ULONG activate_handle, ULONG key_handle,
                                        ULONG policy_session_handle,
                                        const UCHAR* cred_blob, USHORT cred_blob_len,
                                        const UCHAR* secret,    USHORT secret_len,
                                        UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG auth_pw      = 9u;
    const ULONG auth_policy  = 9u;
    const ULONG auth_area    = auth_pw + auth_policy;
    const ULONG total = sizeof(TPM2_HEADER) + 4u + 4u + 4u + auth_area
                      + 2u + cred_blob_len + 2u + secret_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }

    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_ActivateCredential);
    put_be32(p, activate_handle);
    put_be32(p, key_handle);
    put_be32(p, auth_area);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be32(p, policy_session_handle);
    put_be16(p, 0u); *p++ = 1u; put_be16(p, 0u);
    put_be16(p, cred_blob_len);
    if (cred_blob_len > 0u && cred_blob != nullptr)
    {
        RtlCopyMemory(p, cred_blob, cred_blob_len); p += cred_blob_len;
    }
    put_be16(p, secret_len);
    if (secret_len > 0u && secret != nullptr)
    {
        RtlCopyMemory(p, secret, secret_len); p += secret_len;
    }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// Builds a TPM2_MakeCredential command. handle is the loaded EK; credential
// is the digest-sized blob to wrap; objectName is the Name of the AK.
NTSTATUS tpm2_build_make_credential(ULONG ek_handle,
                                    const UCHAR* credential, USHORT credential_len,
                                    const UCHAR* object_name, USHORT object_name_len,
                                    UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG total = sizeof(TPM2_HEADER) + 4u
                      + 2u + credential_len + 2u + object_name_len;
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }

    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_MakeCredential);
    put_be32(p, ek_handle);
    put_be16(p, credential_len);
    if (credential_len > 0u && credential != nullptr)
    {
        RtlCopyMemory(p, credential, credential_len); p += credential_len;
    }
    put_be16(p, object_name_len);
    if (object_name_len > 0u && object_name != nullptr)
    {
        RtlCopyMemory(p, object_name, object_name_len); p += object_name_len;
    }
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// Builds a TPM2_PCR_Allocate command requesting the supplied bank layout.
// Requires platform authorization (TPM_RH_PLATFORM); change takes effect
// only after the next TPM2_Startup(CLEAR).
NTSTATUS tpm2_build_pcr_allocate(USHORT bank, UCHAR bm_lo, UCHAR bm_mid, UCHAR bm_hi,
                                 UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG auth_area = 9u;
    const ULONG total = sizeof(TPM2_HEADER) + 4u + 4u + auth_area
                      + 4u + sizeof(TPMS_PCR_SELECTION);
    if (*cmd_len < total) { *cmd_len = total; return STATUS_BUFFER_TOO_SMALL; }

    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_SESSIONS);
    put_be32(p, total);
    put_be32(p, TPM_CC_PCR_Allocate);
    put_be32(p, TPM_RH_PLATFORM);
    put_be32(p, auth_area);
    put_be32(p, TPM_RS_PW);
    put_be16(p, 0u); *p++ = 0u; put_be16(p, 0u);
    put_be32(p, 1u);
    put_be16(p, bank);
    *p++ = 3u;
    *p++ = bm_lo;
    *p++ = bm_mid;
    *p++ = bm_hi;
    *cmd_len = total;
    return STATUS_SUCCESS;
}

// Builds a TPM2_FlushContext command (14 bytes) for releasing a session or
// transient object handle.
NTSTATUS tpm2_build_flush_context(ULONG flush_handle, UCHAR* cmd_out, ULONG* cmd_len) noexcept
{
    if (cmd_out == nullptr || cmd_len == nullptr || *cmd_len < 14u)
    {
        if (cmd_len != nullptr) { *cmd_len = 14u; }
        return STATUS_BUFFER_TOO_SMALL;
    }
    UCHAR* p = cmd_out;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, 14u);
    put_be32(p, TPM_CC_FlushContext);
    put_be32(p, flush_handle);
    *cmd_len = 14u;
    return STATUS_SUCCESS;
}

// End-to-end TPM call helpers -- one function per logical TPM operation that
// composes build + submit + header-validate + response-parse so the higher
// layers can issue a single call. Sits on top of SECTION 8 transport and
// SECTION 9 builders, and feeds the PCR readers in SECTION 11, the EK
// extractor in SECTION 20, and the capability probes in SECTION 13. Invoked
// once per logical TPM op. The mechanic is uniform: open the handle, build
// the frame, IOCTL-submit it, parse the response header (tag + size + rc),
// then feed the result into canary_feed before returning.
// ============================================================================
// SECTION 10 -- high-level TPM 2.0 wire-call helpers + wire parsers
// ============================================================================

// Issues TPM2_GetCapability, validates the response header, feeds the wire
// digest. The caller-supplied response buffer must be large enough for the
// expected property value.
NTSTATUS tpm2_get_capability(HANDLE device, EK_RECORD* rec,
                             ULONG capability, ULONG property, ULONG property_count,
                             UCHAR* rsp_buf, ULONG rsp_cap, ULONG* rsp_used) noexcept
{
    if (device == NULL || rsp_buf == nullptr || rsp_used == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    UCHAR cmd[32];
    ULONG cmd_len = sizeof(cmd);
    NTSTATUS s = tpm2_build_get_capability(capability, property, property_count, cmd, &cmd_len);
    if (!NT_SUCCESS(s)) { return s; }
    s = tpm2_submit_command(device, cmd, cmd_len, rsp_buf, rsp_cap, rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (*rsp_used < sizeof(TPM2_HEADER)) { return STATUS_INVALID_BUFFER_SIZE; }
    const ULONG rc = peek_be32(rsp_buf + 6);
    if (rec != nullptr) { rec->last_tpm_rc = rc; }
    if (rc != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    if (rec != nullptr) { update_wire_digest(rec, rsp_buf, *rsp_used); }
    return STATUS_SUCCESS;
}

// Sends TPM2_ReadPublic to the supplied EK handle and stores the response in
// the caller's buffer.
NTSTATUS tpm2_read_ek_public(HANDLE device, ULONG ek_handle,
                             UCHAR* rsp_buf, ULONG rsp_cap, ULONG* rsp_used) noexcept
{
    UCHAR cmd[16];
    ULONG cmd_len = sizeof(cmd);
    NTSTATUS s = tpm2_build_read_public(ek_handle, cmd, &cmd_len);
    if (!NT_SUCCESS(s)) { return s; }
    return tpm2_submit_command(device, cmd, cmd_len, rsp_buf, rsp_cap, rsp_used);
}

// Parses a TPM2_ReadPublic response into the lightweight EK_PUBLIC_AREA
// view used by the secureboot pillar.
NTSTATUS tpm2_parse_ek_public(const UCHAR* rsp_buf, ULONG rsp_used,
                              EK_PUBLIC_AREA* out) noexcept
{
    if (rsp_buf == nullptr || out == nullptr || rsp_used < sizeof(TPM2_HEADER) + 4u)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const UCHAR* p   = rsp_buf + sizeof(TPM2_HEADER);
    ULONG remaining  = rsp_used - sizeof(TPM2_HEADER);
    if (remaining < 2u) { return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT pub_size = get_be16(p);
    remaining -= 2u;
    if (pub_size > remaining) { return STATUS_INVALID_BUFFER_SIZE; }

    const UCHAR* pub_begin = p;
    out->raw_public = pub_begin;
    out->raw_public_len = pub_size;
    out->type     = get_be16(p);
    out->name_alg = get_be16(p);
    out->object_attributes = get_be32(p);
    const USHORT auth_policy_size = get_be16(p);
    p += auth_policy_size;
    const USHORT sym_alg = get_be16(p);
    if (sym_alg != TPM_ALG_NULL) { return STATUS_NOT_SUPPORTED; }
    const USHORT scheme  = get_be16(p);
    if (scheme  != TPM_ALG_NULL) { return STATUS_NOT_SUPPORTED; }
    if (out->type != TPM_ALG_RSA) { return STATUS_NOT_SUPPORTED; }
    out->key_bits  = get_be16(p);
    out->exponent  = get_be32(p);
    if (out->exponent == 0u) { out->exponent = 0x10001u; }
    out->modulus_len = get_be16(p);
    out->modulus     = p;
        if (rec->rsa.exponent == 0u) { rec->rsa.exponent = 0x10001u; }
        rec->rsa.modulus_len = get_be16(p);
        if (rec->rsa.modulus_len > sizeof(rec->rsa.modulus)) { return STATUS_BUFFER_TOO_SMALL; }
        RtlCopyMemory(rec->rsa.modulus, p, rec->rsa.modulus_len);
        return STATUS_SUCCESS;
    }
    if (rec->ek_alg_type == TPM_ALG_ECC)
    {
        rec->ecc.curve_id    = get_be16(p);
        rec->ecc.point_x_len = get_be16(p);
        if (rec->ecc.point_x_len > sizeof(rec->ecc.point_x)) { return STATUS_BUFFER_TOO_SMALL; }
        RtlCopyMemory(rec->ecc.point_x, p, rec->ecc.point_x_len);
        p += rec->ecc.point_x_len;
        rec->ecc.point_y_len = get_be16(p);
        if (rec->ecc.point_y_len > sizeof(rec->ecc.point_y)) { return STATUS_BUFFER_TOO_SMALL; }
        RtlCopyMemory(rec->ecc.point_y, p, rec->ecc.point_y_len);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS ek_modulus_sha256(const EK_PUBLIC_AREA& ek, UCHAR digest_out[32]) noexcept
{
    if (ek.modulus == nullptr) { return STATUS_INVALID_PARAMETER; }
    return bcrypt_sha256_block(ek.modulus, ek.modulus_len, digest_out);
}

NTSTATUS ek_name_sha256(const EK_PUBLIC_AREA& ek, UCHAR name_out[34]) noexcept
{
    if (ek.raw_public == nullptr) { return STATUS_INVALID_PARAMETER; }
    name_out[0] = (UCHAR)(TPM_ALG_SHA256 >> 8);
    name_out[1] = (UCHAR)(TPM_ALG_SHA256 & 0xFFu);
    return bcrypt_sha256_block(ek.raw_public, ek.raw_public_len, name_out + 2);
}

// Earlier draft defined vgk_pcr7_whitelist_install and
// vgk_pcr7_whitelist_check here. The PCR7 seed table in SECTION 38 and the
// storage block above were removed because the binary database carries no
// matching anchors.

NTSTATUS hash_ek_material(EK_RECORD* rec, const UCHAR* public_area_bytes,
                          ULONG public_area_len) noexcept;
void     project_composite_field(EK_RECORD* rec) noexcept;

// PLACEHOLDER STUBS: the binary database at 0xFFFFF8013AD40000 carries no
// PCR7 whitelist seed table, no install / check bodies, and no storage. The
// three live call sites in extract_ek / build_hwid_tpm_secureboot /
// vgk_tpm_full_attest still need these symbols to compile, so we provide safe
// no-policy defaults: check() returns TRUE (always-match, never trips
// Pcr7WhitelistMiss) and the count global stays at 0 (so the gated branches
// in the callers short-circuit before reading pcr7_whitelist_match).
static const ULONG g_vgk_pcr7_whitelist_count = 0u;

NTSTATUS hash_ek_material(EK_RECORD* rec, const UCHAR* public_area_bytes,
                          ULONG public_area_len) noexcept
{
    NTSTATUS s = STATUS_SUCCESS;
    if (rec->kind == EkKind::RSA)
    {
        s = bcrypt_sha256_block(rec->rsa.modulus, rec->rsa.modulus_len, rec->modulus_sha256);
    }
    else if (rec->kind == EkKind::ECC)
    {
        UCHAR concat[256];
        if ((ULONG)rec->ecc.point_x_len + (ULONG)rec->ecc.point_y_len > sizeof(concat))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(concat,                          rec->ecc.point_x, rec->ecc.point_x_len);
        RtlCopyMemory(concat + rec->ecc.point_x_len,   rec->ecc.point_y, rec->ecc.point_y_len);
        s = bcrypt_sha256_block(concat, rec->ecc.point_x_len + rec->ecc.point_y_len, rec->modulus_sha256);
    }
    else
    {
        return STATUS_NOT_SUPPORTED;
    }
    if (!NT_SUCCESS(s)) { return s; }
    s = bcrypt_sha256_block(public_area_bytes, public_area_len, rec->name_sha256);
    if (!NT_SUCCESS(s)) { return s; }
    project_composite_field(rec);
    return STATUS_SUCCESS;
}

// Parses a TPM2_Quote response. Extracts the marshaled TPMS_ATTEST blob,
// the signature, the pcrSelect echoed back, and the pcrDigest. Verification
// (signature + pcrDigest reconstruction) is delegated to a higher layer.
NTSTATUS tpm2_parse_quote_response(const UCHAR* rsp_buf, ULONG rsp_used,
                                   TPM_QUOTE_RESULT* out) noexcept
{
    if (rsp_buf == nullptr || out == nullptr || rsp_used < sizeof(TPM2_HEADER) + 6u)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (peek_be32(rsp_buf + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* p   = rsp_buf + sizeof(TPM2_HEADER);
    ULONG remaining  = rsp_used - sizeof(TPM2_HEADER);
    const ULONG param_size = get_be32(p);
    remaining -= 4u;
    if (param_size > remaining) { return STATUS_INVALID_BUFFER_SIZE; }

    const USHORT attest_len = get_be16(p);
    if (attest_len > sizeof(out->attest_blob)) { return STATUS_BUFFER_TOO_SMALL; }
    const UCHAR* attest_begin = p;
    RtlCopyMemory(out->attest_blob, p, attest_len);
    out->attest_len = attest_len;

    const UCHAR* a   = attest_begin;
    const UCHAR* aend = attest_begin + attest_len;
    if ((ULONG)(aend - a) < 6u) { return STATUS_INVALID_BUFFER_SIZE; }
    const ULONG  magic_v   = get_be32(a);
    const USHORT type_v    = get_be16(a);
    if (magic_v != TPM_GENERATED_VALUE) { return STATUS_DATA_ERROR; }
    if (type_v != TPM_ST_ATTEST_QUOTE)  { return STATUS_DATA_ERROR; }

    if ((ULONG)(aend - a) < 2u) { return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT qs_size = get_be16(a);
    if ((ULONG)(aend - a) < qs_size + 2u) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(out->qualified_signer_name,
                  a, (qs_size < sizeof(out->qualified_signer_name)) ? qs_size : sizeof(out->qualified_signer_name));
    out->qualified_signer_name_len = qs_size;
    a += qs_size;

    const USHORT ex_size = get_be16(a);
    if ((ULONG)(aend - a) < ex_size + 17u + 8u) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(out->extra_data,
                  a, (ex_size < sizeof(out->extra_data)) ? ex_size : sizeof(out->extra_data));
    out->extra_data_len = ex_size;
    a += ex_size;

    out->clock_info.clock        = get_be64(a);
    out->clock_info.resetCount   = get_be32(a);
    out->clock_info.restartCount = get_be32(a);
    out->clock_info.safe         = *a++;

    out->firmware_version = get_be64(a);

    if ((ULONG)(aend - a) < 4u) { return STATUS_INVALID_BUFFER_SIZE; }
    const ULONG sel_count = get_be32(a);
    if (sel_count == 0u) { return STATUS_DATA_ERROR; }
    for (ULONG i = 0; i < sel_count; ++i)
    {
        if ((ULONG)(aend - a) < 3u) { return STATUS_INVALID_BUFFER_SIZE; }
        a += 2;
        const UCHAR sel_size = *a++;
        if ((ULONG)(aend - a) < sel_size) { return STATUS_INVALID_BUFFER_SIZE; }
        a += sel_size;
    }
    if ((ULONG)(aend - a) < 2u) { return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT digest_size = get_be16(a);
    if (digest_size > sizeof(out->pcr_digest) || (ULONG)(aend - a) < digest_size)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(out->pcr_digest, a, digest_size);
    out->pcr_digest_len = digest_size;
    a += digest_size;

    const UCHAR* sig_p   = attest_begin + attest_len;
    const UCHAR* sig_end = rsp_buf + rsp_used;
    if ((ULONG)(sig_end - sig_p) >= 4u)
    {
        out->signature_alg      = get_be16(sig_p);
        out->signature_hash_alg = get_be16(sig_p);
        switch (out->signature_alg)
        {
            case TPM_ALG_RSASSA:
            case TPM_ALG_RSAPSS:
            {
                if ((ULONG)(sig_end - sig_p) < 2u) { return STATUS_INVALID_BUFFER_SIZE; }
                const USHORT sig_len = get_be16(sig_p);
                if (sig_len > sizeof(out->signature_blob) || (ULONG)(sig_end - sig_p) < sig_len)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                RtlCopyMemory(out->signature_blob, sig_p, sig_len);
                out->signature_len = sig_len;
                break;
            }
            case TPM_ALG_ECDSA:
            {
                if ((ULONG)(sig_end - sig_p) < 2u) { return STATUS_INVALID_BUFFER_SIZE; }
                const USHORT r_len = get_be16(sig_p);
                if ((ULONG)(sig_end - sig_p) < (ULONG)(r_len + 2u)) { return STATUS_INVALID_BUFFER_SIZE; }
                UCHAR* w = out->signature_blob;
                const ULONG r_block_bytes = 2u + (ULONG)r_len;
                if (r_block_bytes > sizeof(out->signature_blob)) { return STATUS_BUFFER_TOO_SMALL; }
                put_be16(w, r_len);
                RtlCopyMemory(w, sig_p, r_len); w += r_len; sig_p += r_len;
                const USHORT s_len = get_be16(sig_p);
                if ((ULONG)(sig_end - sig_p) < s_len) { return STATUS_INVALID_BUFFER_SIZE; }
                const ULONG total_blob_bytes = r_block_bytes + 2u + (ULONG)s_len;
                if (total_blob_bytes > sizeof(out->signature_blob)) { return STATUS_BUFFER_TOO_SMALL; }
                put_be16(w, s_len);
                RtlCopyMemory(w, sig_p, s_len);
                out->signature_len = (ULONG)(r_len + s_len + 4u);
                break;
            }
            default:
                out->signature_len = 0u;
                return STATUS_NOT_SUPPORTED;
        }
    }
    return STATUS_SUCCESS;
}

// Parses a TPM2_StartAuthSession response. Returns the new session handle
// and copies the TPM-supplied nonce. The session class is encoded in the
// upper byte of the handle (0x02 = HMAC, 0x03 = Policy/Trial).
NTSTATUS tpm2_parse_start_auth_session_response(const UCHAR* rsp_buf, ULONG rsp_used,
                                                ULONG* out_session_handle,
                                                UCHAR* out_nonce_tpm,
                                                ULONG  nonce_capacity,
                                                ULONG* out_nonce_tpm_len) noexcept
{
    if (rsp_buf == nullptr || out_session_handle == nullptr || rsp_used < sizeof(TPM2_HEADER) + 4u + 2u)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (peek_be32(rsp_buf + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* p = rsp_buf + sizeof(TPM2_HEADER);
    *out_session_handle = get_be32(p);
    const USHORT nl = get_be16(p);
    if (nl > nonce_capacity || nl > (rsp_used - sizeof(TPM2_HEADER) - 6u))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (out_nonce_tpm != nullptr) { RtlCopyMemory(out_nonce_tpm, p, nl); }
    if (out_nonce_tpm_len != nullptr) { *out_nonce_tpm_len = nl; }
    return STATUS_SUCCESS;
}

// Parses a TPM2_ActivateCredential response and copies the recovered
// credential bytes into the caller's buffer.
NTSTATUS tpm2_parse_activate_credential_response(const UCHAR* rsp_buf, ULONG rsp_used,

// Focused PCR readers -- PCR0 firmware-code measurement, PCR7 SecureBoot
// policy, PCR14 boot-authority pubkey digest, plus a full 24-bank enumeration
// and the boot-chain digest composition. Vanguard wants individual bank
// values to anchor the SecureBoot and measured-boot evidence path, not just a
// rolled-up digest. These ride on the SECTION 10 wire helpers and their
// output feeds the SECTION 19 composite projection and the SECTION 24
// HWID_TPM_SB_REPORT assembler. Called on every periodic HWID poll and on
// demand by the attestation orchestrator; mechanically they call
// tpm2_build_pcr_read, submit, and parse the response into the caller's
// digest buffer.
// ============================================================================
// SECTION 11 -- PCR readers (PCR0, PCR7 isolated, PCR14, banks, boot chain)
// ============================================================================

// Reads PCR0 in SHA-256 bank. Output is the 32-byte digest.
NTSTATUS tpm2_read_pcr0_sha256(HANDLE device, UCHAR digest_out[32]) noexcept
{
    if (device == NULL || digest_out == nullptr) { return STATUS_INVALID_PARAMETER; }
    UCHAR cmd[32], rsp[256];
    ULONG rsp_used = 0;
    const ULONG cmd_len = (ULONG)(sizeof(TPM2_HEADER) + sizeof(ULONG) + sizeof(TPMS_PCR_SELECTION));
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, cmd_len);
    put_be32(p, TPM_CC_PCR_Read);
    put_be32(p, 1u);
    put_be16(p, TPM_ALG_SHA256);
    *p++ = 3u; *p++ = 0x01u; *p++ = 0x00u; *p++ = 0x00u;
    NTSTATUS s = tpm2_submit_command(device, cmd, cmd_len, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (rsp_used < sizeof(TPM2_HEADER) + 4u + 4u + 6u + 4u + 2u + 32u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* q = rsp + sizeof(TPM2_HEADER) + 4u + 4u + 6u;
    const ULONG digest_count = peek_be32(q); q += 4;
    if (digest_count < 1u) { return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT dsize = peek_be16(q); q += 2;
    if (dsize != 32u) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(digest_out, q, 32);
    return STATUS_SUCCESS;
}

// Reads PCR7 (SecureBoot policy) in SHA-256 bank in isolation. Bitmap byte
// 0 bit 7 = PCR7 (0x80).
NTSTATUS tpm2_read_pcr7_sha256(HANDLE device, UCHAR digest_out[32]) noexcept
{
    if (device == NULL || digest_out == nullptr) { return STATUS_INVALID_PARAMETER; }
    UCHAR cmd[32], rsp[256];
    ULONG rsp_used = 0;
    const ULONG cmd_len = (ULONG)(sizeof(TPM2_HEADER) + sizeof(ULONG) + sizeof(TPMS_PCR_SELECTION));
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, cmd_len);
    put_be32(p, TPM_CC_PCR_Read);
    put_be32(p, 1u);
    put_be16(p, TPM_ALG_SHA256);
    *p++ = 3u; *p++ = 0x80u; *p++ = 0x00u; *p++ = 0x00u;
    NTSTATUS s = tpm2_submit_command(device, cmd, cmd_len, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (rsp_used < sizeof(TPM2_HEADER) + 4u + 4u + 6u + 4u + 2u + 32u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* q = rsp + sizeof(TPM2_HEADER) + 4u + 4u + 6u;
    const ULONG digest_count = peek_be32(q); q += 4;
    if (digest_count < 1u) { return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT dsize = peek_be16(q); q += 2;
    if (dsize != 32u) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(digest_out, q, 32);
    return STATUS_SUCCESS;
}

// Reads PCR14 (boot authority public keys / CustomKernelSigners) in SHA-256
// bank. Bitmap byte 1 bit 6 = PCR14 (0x40).
NTSTATUS tpm2_read_pcr14_sha256(HANDLE device, UCHAR digest_out[32]) noexcept
{
    if (device == NULL || digest_out == nullptr) { return STATUS_INVALID_PARAMETER; }
    UCHAR cmd[32], rsp[256];
    ULONG rsp_used = 0;
    const ULONG cmd_len = (ULONG)(sizeof(TPM2_HEADER) + sizeof(ULONG) + sizeof(TPMS_PCR_SELECTION));
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, cmd_len);
    put_be32(p, TPM_CC_PCR_Read);
    put_be32(p, 1u);
    put_be16(p, TPM_ALG_SHA256);
    *p++ = 3u; *p++ = 0x00u; *p++ = 0x40u; *p++ = 0x00u;
    NTSTATUS s = tpm2_submit_command(device, cmd, cmd_len, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (rsp_used < sizeof(TPM2_HEADER) + 4u + 4u + 6u + 4u + 2u + 32u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* q = rsp + sizeof(TPM2_HEADER) + 4u + 4u + 6u;
    const ULONG digest_count = peek_be32(q); q += 4;
    if (digest_count < 1u) { return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT dsize = peek_be16(q); q += 2;
    if (dsize != 32u) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(digest_out, q, 32);
    return STATUS_SUCCESS;
}

// Reads PCRs whose bitmap is (bm_lo|bm_mid|bm_hi) in SHA-256 bank into
// out_digests (N x 32 bytes).
NTSTATUS tpm2_read_pcr_bank_sha256(HANDLE device, UCHAR bm_lo, UCHAR bm_mid, UCHAR bm_hi,
                                   UCHAR* out_digests, ULONG out_capacity,
                                   ULONG* out_count) noexcept
{
    if (device == NULL || out_digests == nullptr || out_count == nullptr) { return STATUS_INVALID_PARAMETER; }
    *out_count = 0;
    UCHAR cmd[32], rsp[1024];
    ULONG rsp_used = 0;
    const ULONG cmd_len = (ULONG)(sizeof(TPM2_HEADER) + sizeof(ULONG) + sizeof(TPMS_PCR_SELECTION));
    UCHAR* p = cmd;
    put_be16(p, TPM_ST_NO_SESSIONS);
    put_be32(p, cmd_len);
    put_be32(p, TPM_CC_PCR_Read);
    put_be32(p, 1u);
    put_be16(p, TPM_ALG_SHA256);
    *p++ = 3u; *p++ = bm_lo; *p++ = bm_mid; *p++ = bm_hi;
    NTSTATUS s = tpm2_submit_command(device, cmd, cmd_len, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (rsp_used < sizeof(TPM2_HEADER) + 18u) { return STATUS_INVALID_BUFFER_SIZE; }
    if (peek_be32(rsp + 6) != TPM_RC_SUCCESS) { return STATUS_DEVICE_DATA_ERROR; }
    const UCHAR* q = rsp + sizeof(TPM2_HEADER) + 4u + 4u + 6u;
    const ULONG digest_count = peek_be32(q); q += 4;
    if (digest_count * 32u > out_capacity) { return STATUS_BUFFER_TOO_SMALL; }
    UCHAR* w = out_digests;
    for (ULONG i = 0; i < digest_count; ++i)
    {
        const USHORT dsize = peek_be16(q); q += 2;
        if (dsize != 32u) { return STATUS_INVALID_BUFFER_SIZE; }
        RtlCopyMemory(w, q, 32);
        q += 32; w += 32;
    }
    *out_count = digest_count;
    return STATUS_SUCCESS;
}

// SHA-256 hash over (PCR0 || PCR1 || ... || PCR7).
NTSTATUS tpm2_boot_chain_digest_sha256(HANDLE device, UCHAR digest_out[32]) noexcept
{
    UCHAR pcrs[8 * 32] = { 0 };
    ULONG count = 0;
    NTSTATUS s = tpm2_read_pcr_bank_sha256(device, 0xFFu, 0x00u, 0x00u, pcrs, sizeof(pcrs), &count);
    if (!NT_SUCCESS(s)) { return s; }
    if (count != 8u) { return STATUS_INVALID_BUFFER_SIZE; }
    return bcrypt_sha256_block(pcrs, sizeof(pcrs), digest_out);
}

// Earlier draft defined vgk_pcr7_whitelist_install and
// vgk_pcr7_whitelist_check here. The PCR7 seed table in SECTION 38 and the
// storage block above were removed because the binary database carries no
// matching anchors. Install / check bodies are kept wrapped in #if 0 below
// for reference.
#if 0
ULONG vgk_pcr7_whitelist_install_REMOVED(const UCHAR digest[32]) noexcept
{
    KIRQL irql;
    KeAcquireSpinLock(&g_vgk_pcr7_whitelist_lock, &irql);
    if (g_vgk_pcr7_whitelist_count < kPcr7WhitelistCapacity)
    {
        RtlCopyMemory(g_vgk_pcr7_whitelist[g_vgk_pcr7_whitelist_count], digest, 32);
        g_vgk_pcr7_whitelist_count += 1u;
    }
    const ULONG c = g_vgk_pcr7_whitelist_count;
    KeReleaseSpinLock(&g_vgk_pcr7_whitelist_lock, irql);
    return c;
}

// Compares a measured PCR7 digest against the installed whitelist. Returns
// TRUE on hit.
BOOLEAN vgk_pcr7_whitelist_check(const UCHAR digest[32]) noexcept
{
    BOOLEAN hit = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_vgk_pcr7_whitelist_lock, &irql);
    for (ULONG i = 0; i < g_vgk_pcr7_whitelist_count; ++i)
    {
        if (RtlEqualMemory(g_vgk_pcr7_whitelist[i], digest, 32)) { hit = TRUE; break; }
    }
    KeReleaseSpinLock(&g_vgk_pcr7_whitelist_lock, irql);
    return hit;
}
#endif

// PLACEHOLDER STUBS: the binary database at 0xFFFFF8013AD40000 carries no
// PCR7 whitelist seed table, no install / check bodies, and no storage. The
// three live call sites in extract_ek / build_hwid_tpm_secureboot /
// vgk_tpm_full_attest still need these symbols to compile, so we provide safe
// no-policy defaults: check() returns TRUE (always-match, never trips
// Pcr7WhitelistMiss) and the count global stays at 0 (so the gated branches
// in the callers short-circuit before reading pcr7_whitelist_match).
static const ULONG g_vgk_pcr7_whitelist_count = 0u;
static inline BOOLEAN vgk_pcr7_whitelist_check(const UCHAR /*digest*/[32]) noexcept
{
    return TRUE;
}

// Captures PCR14 as the baseline value (called at first attestation when
// CustomKernelSigners is known good).
void vgk_pcr14_capture_baseline(const UCHAR digest[32]) noexcept
{
    RtlCopyMemory(g_vgk_pcr14_baseline, digest, 32);
    g_vgk_pcr14_baseline_valid = TRUE;
    KeMemoryBarrier();
}

// Compares a measured PCR14 against the captured baseline.
BOOLEAN vgk_pcr14_check_baseline(const UCHAR digest[32]) noexcept
{
    if (!g_vgk_pcr14_baseline_valid) { return TRUE; }
    return RtlEqualMemory(digest, g_vgk_pcr14_baseline, 32) ? TRUE : FALSE;
}

NTSTATUS tpm12_read_pcr0_sha1(HANDLE device, UCHAR digest_out[20]) noexcept
{
    UCHAR cmd[16], rsp[64];
    ULONG cmd_len = sizeof(cmd), rsp_used = 0;
    NTSTATUS s = tpm12_build_pcr_read(0, cmd, &cmd_len);
    if (!NT_SUCCESS(s)) { return s; }
    s = tpm2_submit_command(device, cmd, cmd_len, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (rsp_used < 30u) { return STATUS_INVALID_BUFFER_SIZE; }
    RtlCopyMemory(digest_out, rsp + 10, 20);
    return STATUS_SUCCESS;
}

NTSTATUS tpm12_read_pubek_sha1(HANDLE device, UCHAR digest_out[20]) noexcept
{
    UCHAR cmd[40], rsp[256];
    ULONG cmd_len = sizeof(cmd), rsp_used = 0;
    NTSTATUS s = tpm12_build_read_pubek(cmd, &cmd_len);
    if (!NT_SUCCESS(s)) { return s; }
    s = tpm2_submit_command(device, cmd, cmd_len, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (rsp_used <= 10u) { return STATUS_INVALID_BUFFER_SIZE; }
    return bcrypt_sha1_block(rsp + 10, rsp_used - 10, digest_out);
}

// TPM2_GetCapability wrappers for the four facts the EK record needs:
// manufacturer ID, firmware version (hi/lo halves), NV buffer max, and the
// supported PCR banks. The EK record carries these alongside the modulus
// hash so the HWID composite can pin both identity and vendor metadata.
// These wrap the SECTION 9 builder and the SECTION 10 helper, populate
// EK_RECORD fields in place, and run on every refresh from the SECTION 20
// EK orchestrator plus the diagnostic dumps. Each helper issues one
// TPM2_GetCapability per property (TPM_PT_MANUFACTURER, TPM_PT_NV_BUFFER_MAX,
// TPM_PT_FIRMWARE_VERSION_1/2, TPM_CAP_PCRS).
// ============================================================================
// SECTION 13 -- capability helpers (manufacturer, firmware, NV buffer max,
//                                    supported PCR banks)
// ============================================================================

NTSTATUS tpm_firmware_facts(HANDLE device, EK_RECORD* rec) noexcept
{
    UCHAR rsp[64];
    ULONG rsp_used = 0;
    NTSTATUS s = tpm2_get_capability(device, rec, TPM_CAP_TPM_PROPERTIES,
        TPM_PT_MANUFACTURER, 1, rsp, sizeof(rsp), &rsp_used);
    if (NT_SUCCESS(s) && rsp_used >= sizeof(TPM2_HEADER) + 17u)
    {
        const ULONG mfg = peek_be32(rsp + sizeof(TPM2_HEADER) + 13);
        rec->manufacturer_id[0] = (UCHAR)((mfg >> 24) & 0xFFu);
        rec->manufacturer_id[1] = (UCHAR)((mfg >> 16) & 0xFFu);
        rec->manufacturer_id[2] = (UCHAR)((mfg >>  8) & 0xFFu);
        rec->manufacturer_id[3] = (UCHAR)((mfg >>  0) & 0xFFu);
        rec->manufacturer_id[4] = 0;
    }
    s = tpm2_get_capability(device, rec, TPM_CAP_TPM_PROPERTIES,
        TPM_PT_FIRMWARE_VERSION_1, 2, rsp, sizeof(rsp), &rsp_used);
    if (NT_SUCCESS(s) && rsp_used >= sizeof(TPM2_HEADER) + 25u)
    {
        rec->firmware_version_hi = peek_be32(rsp + sizeof(TPM2_HEADER) + 13);
        rec->firmware_version_lo = peek_be32(rsp + sizeof(TPM2_HEADER) + 21);
    }
    return STATUS_SUCCESS;
}

ULONG nv_buffer_max(HANDLE device, EK_RECORD* rec) noexcept
{
    UCHAR rsp[64];
    ULONG rsp_used = 0;
    NTSTATUS s = tpm2_get_capability(device, rec, TPM_CAP_TPM_PROPERTIES,
        TPM_PT_NV_BUFFER_MAX, 1, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s) || rsp_used < sizeof(TPM2_HEADER) + 17u) { return TPM_NV_SLICE_MAX; }
    const ULONG v = peek_be32(rsp + sizeof(TPM2_HEADER) + 13);
    if (v == 0u || v > TPM_NV_SLICE_MAX) { return TPM_NV_SLICE_MAX; }
    return v;
}

// Enumerates the PCR banks the TPM has allocated via TPM_CAP_PCRS.
// Up to 5 banks (SHA1, SHA256, SHA384, SHA512, SM3) are reported with their
// 24-bit bitmap of which PCR indexes are present in that bank.
NTSTATUS tpm2_query_pcr_banks(HANDLE device, PCR_BANKS_REPORT* out) noexcept
{
    if (device == NULL || out == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out, sizeof(*out));
    UCHAR rsp[256];
    ULONG rsp_used = 0;
    NTSTATUS s = tpm2_get_capability(device, nullptr, TPM_CAP_PCRS, 0, 1, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s)) { return s; }
    if (rsp_used < sizeof(TPM2_HEADER) + 1u + 4u + 4u) { return STATUS_INVALID_BUFFER_SIZE; }
    const UCHAR* p = rsp + sizeof(TPM2_HEADER) + 1u + 4u;
    const ULONG count = peek_be32(p); p += 4;
    const ULONG eff = (count > 5u) ? 5u : count;
    for (ULONG i = 0; i < eff; ++i)
    {
        out->banks[i].hash_alg       = peek_be16(p); p += 2;
        out->banks[i].size_of_select = *p++;
        const UCHAR copy_n = (out->banks[i].size_of_select < sizeof(out->banks[i].bitmap))
                           ? out->banks[i].size_of_select
                           : (UCHAR)sizeof(out->banks[i].bitmap);
        for (UCHAR j = 0; j < copy_n; ++j) { out->banks[i].bitmap[j] = *p++; }
        if (out->banks[i].size_of_select > copy_n)
        {
            p += (out->banks[i].size_of_select - copy_n);
        }
    }
    out->bank_count = eff;
    return STATUS_SUCCESS;
}

// Bare-bones ASN.1 DER TLV walker -- iterates a DER blob tag/length/value at
// a time so higher layers can pick OIDs and extensions out of an X.509 body.
// The EK certificate is full X.509 DER, so we need OID matching and
// extension extraction to validate the TCG EK cert profile. This is the
// foundation for SECTION 15's EK cert profile validation -- pure parser, no
// I/O. Cold path: called once per EK cert read, and only on EK change.
// Mechanically reads the tag UCHAR, then short-form or long-form length,
// then emits the (tag, value-span) pair to the caller.
// ============================================================================
// SECTION 14 -- ASN.1 DER walker
// ============================================================================

BOOLEAN asn1_read_tlv(const UCHAR*& cursor, const UCHAR* end,
                      UCHAR& out_tag, Asn1View& out_value) noexcept
{
    if (cursor >= end) { return FALSE; }
    out_tag = *cursor++;
    if (cursor >= end) { return FALSE; }
    UCHAR first = *cursor++;
    ULONG len   = 0;
    if (first < 0x80u) { len = first; }
    else
    {
        const UCHAR nlen = (UCHAR)(first & 0x7Fu);
        if (nlen == 0u || nlen > 4u || cursor + nlen > end) { return FALSE; }
        for (UCHAR i = 0; i < nlen; ++i) { len = (len << 8) | *cursor++; }
    }
    if (cursor + len > end) { return FALSE; }
    out_value.data = cursor;
    out_value.len  = len;
    cursor += len;
    return TRUE;
}

BOOLEAN asn1_oid_equals(const Asn1View& v, const UCHAR* expected, ULONG expected_len) noexcept
{
    if (v.len != expected_len) { return FALSE; }
    return RtlEqualMemory(v.data, expected, expected_len);
}

// EK certificate profile validator -- parses the SubjectAltName, checks the
// TCG-mandated OIDs (OID_TPM_MANUFACTURER, OID_TPM_MODEL, OID_TPM_VERSION,
// OID_TCG_EKCERT, OID_BASIC_CONSTRAINTS, OID_EXT_KEY_USAGE), and scrapes the
// vendor metadata into the EK record. The TCG EK Credential Profile mandates
// a specific SAN and extension layout per vendor, so this is the gate that
// declares whether an EK cert is genuinely a TCG-compliant EK. Sits on the
// SECTION 14 ASN.1 walker, populates EK_RECORD vendor + serial + extension
// fields, and runs one pass per EK change driven by SECTION 16 or 20.
// ============================================================================
// SECTION 15 -- EK cert ASN.1 profile validation
// ============================================================================

BOOLEAN cert_parse_san_inner(const UCHAR* data, ULONG len, EK_RECORD* rec) noexcept
{
    const UCHAR* p   = data;
    const UCHAR* end = data + len;
    UCHAR        tag;
    Asn1View     value;
    if (!asn1_read_tlv(p, end, tag, value) || tag != ASN1_TAG_SEQUENCE) { return FALSE; }

    const UCHAR* gn_p   = value.data;
    const UCHAR* gn_end = value.data + value.len;
    while (gn_p < gn_end)
    {
        UCHAR    gn_tag;
        Asn1View gn_val;
        if (!asn1_read_tlv(gn_p, gn_end, gn_tag, gn_val)) { return FALSE; }
        if (gn_tag != 0xA4u) { continue; }
        const UCHAR* dn_p   = gn_val.data;
        const UCHAR* dn_end = gn_val.data + gn_val.len;
        UCHAR    dn_tag;
        Asn1View dn_seq;
        if (!asn1_read_tlv(dn_p, dn_end, dn_tag, dn_seq) || dn_tag != ASN1_TAG_SEQUENCE) { return FALSE; }

        const UCHAR* rdn_p   = dn_seq.data;
        const UCHAR* rdn_end = dn_seq.data + dn_seq.len;
        while (rdn_p < rdn_end)
        {
            UCHAR    set_tag;
            Asn1View set_val;
            if (!asn1_read_tlv(rdn_p, rdn_end, set_tag, set_val)) { return FALSE; }
            if (set_tag != ASN1_TAG_SET) { continue; }
            const UCHAR* atv_p   = set_val.data;
            const UCHAR* atv_end = set_val.data + set_val.len;
            UCHAR    atv_tag;
            Asn1View atv_seq;
            if (!asn1_read_tlv(atv_p, atv_end, atv_tag, atv_seq) || atv_tag != ASN1_TAG_SEQUENCE) { continue; }
            const UCHAR* tv_p   = atv_seq.data;
            const UCHAR* tv_end = atv_seq.data + atv_seq.len;
            UCHAR    oid_tag;
            Asn1View oid_val;
            if (!asn1_read_tlv(tv_p, tv_end, oid_tag, oid_val) || oid_tag != ASN1_TAG_OID) { continue; }
            UCHAR    str_tag;
            Asn1View str_val;
            if (!asn1_read_tlv(tv_p, tv_end, str_tag, str_val)) { return FALSE; }
            if (asn1_oid_equals(oid_val, OID_TPM_MANUFACTURER, sizeof(OID_TPM_MANUFACTURER)))
            {
                const ULONG n = (str_val.len < sizeof(rec->cert_tpm_manuf) - 1u)
                              ? str_val.len : (sizeof(rec->cert_tpm_manuf) - 1u);
                RtlCopyMemory(rec->cert_tpm_manuf, str_val.data, n);
                rec->cert_tpm_manuf[n] = 0;
            }
            else if (asn1_oid_equals(oid_val, OID_TPM_MODEL, sizeof(OID_TPM_MODEL)))
            {
                const ULONG n = (str_val.len < sizeof(rec->cert_tpm_model) - 1u)
                              ? str_val.len : (sizeof(rec->cert_tpm_model) - 1u);
                RtlCopyMemory(rec->cert_tpm_model, str_val.data, n);
                rec->cert_tpm_model[n] = 0;
            }
            else if (asn1_oid_equals(oid_val, OID_TPM_VERSION, sizeof(OID_TPM_VERSION)))
            {
                const ULONG n = (str_val.len < sizeof(rec->cert_tpm_version) - 1u)
                              ? str_val.len : (sizeof(rec->cert_tpm_version) - 1u);
                RtlCopyMemory(rec->cert_tpm_version, str_val.data, n);
                rec->cert_tpm_version[n] = 0;
            }
        }
    }
    return TRUE;
}

BOOLEAN cert_parse_basic_constraints(const UCHAR* data, ULONG len, EK_RECORD* rec) noexcept
{
    const UCHAR* p   = data;
    const UCHAR* end = data + len;
    UCHAR    tag;
    Asn1View seq;
    if (!asn1_read_tlv(p, end, tag, seq) || tag != ASN1_TAG_SEQUENCE) { return FALSE; }
    const UCHAR* sp   = seq.data;
    const UCHAR* send = seq.data + seq.len;
    UCHAR    inner_tag;
    Asn1View inner_val;
    if (asn1_read_tlv(sp, send, inner_tag, inner_val) && inner_tag == ASN1_TAG_BOOLEAN)
    {
        rec->cert_basic_constraints_ca = (inner_val.len >= 1u && inner_val.data[0] != 0u);
    }
    else
    {
        rec->cert_basic_constraints_ca = FALSE;
    }
    return TRUE;
}

BOOLEAN cert_parse_eku(const UCHAR* data, ULONG len, EK_RECORD* rec) noexcept
{
    const UCHAR* p   = data;
    const UCHAR* end = data + len;
    UCHAR    tag;
    Asn1View seq;
    if (!asn1_read_tlv(p, end, tag, seq) || tag != ASN1_TAG_SEQUENCE) { return FALSE; }
    const UCHAR* sp   = seq.data;
    const UCHAR* send = seq.data + seq.len;
    while (sp < send)
    {
        UCHAR    oid_tag;
        Asn1View oid_val;
        if (!asn1_read_tlv(sp, send, oid_tag, oid_val)) { return FALSE; }
        if (oid_tag != ASN1_TAG_OID) { continue; }
        if (asn1_oid_equals(oid_val, OID_TCG_EKCERT, sizeof(OID_TCG_EKCERT)))
        {
            rec->cert_eku_ekcert_ok = TRUE;
        }
    }
    return TRUE;
}

NTSTATUS cert_hash_dn(const UCHAR* tlv_start, ULONG tlv_total_len, UCHAR out[32]) noexcept
{
    return bcrypt_sha256_block(tlv_start, tlv_total_len, out);
}

NTSTATUS cert_validate_tcg_ek_profile(EK_RECORD* rec) noexcept
{
    if (rec == nullptr || rec->cert_len == 0u || !rec->have_cert) { return STATUS_INVALID_PARAMETER; }
    const UCHAR* p   = rec->cert_der;
    const UCHAR* end = rec->cert_der + rec->cert_len;
    UCHAR    tag;
    Asn1View outer;
    if (!asn1_read_tlv(p, end, tag, outer) || tag != ASN1_TAG_SEQUENCE) { return STATUS_DATA_ERROR; }
    const UCHAR* tp   = outer.data;
    const UCHAR* tend = outer.data + outer.len;
    UCHAR    tbs_tag;
    Asn1View tbs;
    if (!asn1_read_tlv(tp, tend, tbs_tag, tbs) || tbs_tag != ASN1_TAG_SEQUENCE) { return STATUS_DATA_ERROR; }

    const UCHAR* fp   = tbs.data;
    const UCHAR* fend = tbs.data + tbs.len;
    UCHAR    inner_tag;
    Asn1View inner_val;

    if (!asn1_read_tlv(fp, fend, inner_tag, inner_val)) { return STATUS_DATA_ERROR; }
    if (inner_tag == 0xA0u)
    {
        if (!asn1_read_tlv(fp, fend, inner_tag, inner_val)) { return STATUS_DATA_ERROR; }
    }
    rec->cert_serial_len = (inner_val.len <= sizeof(rec->cert_serial)) ? inner_val.len : sizeof(rec->cert_serial);
    RtlCopyMemory(rec->cert_serial, inner_val.data, rec->cert_serial_len);

    if (!asn1_read_tlv(fp, fend, inner_tag, inner_val)) { return STATUS_DATA_ERROR; }

    Asn1View issuer;
    if (!asn1_read_tlv(fp, fend, inner_tag, issuer)) { return STATUS_DATA_ERROR; }
    cert_hash_dn(issuer.data, issuer.len, rec->cert_issuer_hash);

    if (!asn1_read_tlv(fp, fend, inner_tag, inner_val)) { return STATUS_DATA_ERROR; }

    Asn1View subject;
    if (!asn1_read_tlv(fp, fend, inner_tag, subject)) { return STATUS_DATA_ERROR; }
    cert_hash_dn(subject.data, subject.len, rec->cert_subject_hash);

    if (!asn1_read_tlv(fp, fend, inner_tag, inner_val)) { return STATUS_DATA_ERROR; }

    while (fp < fend)
    {
        UCHAR    ext_tag;
        Asn1View ext_val;
        if (!asn1_read_tlv(fp, fend, ext_tag, ext_val)) { return STATUS_DATA_ERROR; }
        if (ext_tag != 0xA3u) { continue; }
        const UCHAR* ep   = ext_val.data;
        const UCHAR* eend = ext_val.data + ext_val.len;
        UCHAR    seq_tag;
        Asn1View seq_val;
        if (!asn1_read_tlv(ep, eend, seq_tag, seq_val)) { continue; }
        const UCHAR* sp   = seq_val.data;
        const UCHAR* send = seq_val.data + seq_val.len;
        while (sp < send)
        {
            UCHAR    ext_seq_tag;
            Asn1View ext_seq;
            if (!asn1_read_tlv(sp, send, ext_seq_tag, ext_seq)) { return STATUS_DATA_ERROR; }
            if (ext_seq_tag != ASN1_TAG_SEQUENCE) { continue; }
            const UCHAR* xp   = ext_seq.data;
            const UCHAR* xend = ext_seq.data + ext_seq.len;
            UCHAR    oid_tag;
            Asn1View oid_val;
            if (!asn1_read_tlv(xp, xend, oid_tag, oid_val) || oid_tag != ASN1_TAG_OID) { continue; }
            UCHAR    next_tag;
            Asn1View next_val;
            if (!asn1_read_tlv(xp, xend, next_tag, next_val)) { return STATUS_DATA_ERROR; }
            if (next_tag == ASN1_TAG_BOOLEAN)
            {
                if (asn1_oid_equals(oid_val, OID_SAN, sizeof(OID_SAN)))
                {
                    rec->cert_subjectalt_critical = (next_val.len >= 1u && next_val.data[0] != 0u);
                }
                if (!asn1_read_tlv(xp, xend, next_tag, next_val)) { return STATUS_DATA_ERROR; }
            }
            if (next_tag != ASN1_TAG_OCTET_STRING) { continue; }
            if (asn1_oid_equals(oid_val, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS)))
            {
                cert_parse_basic_constraints(next_val.data, next_val.len, rec);
            }
            else if (asn1_oid_equals(oid_val, OID_SAN, sizeof(OID_SAN)))
            {
                cert_parse_san_inner(next_val.data, next_val.len, rec);
            }
            else if (asn1_oid_equals(oid_val, OID_EXT_KEY_USAGE, sizeof(OID_EXT_KEY_USAGE)))
            {
                cert_parse_eku(next_val.data, next_val.len, rec);
            }
        }
    }

    if (rec->cert_basic_constraints_ca || !rec->cert_eku_ekcert_ok)
    {
        return STATUS_INVALID_PARAMETER_MIX;
    }
    rec->cert_parsed_ok = TRUE;
    return STATUS_SUCCESS;
}

// EK certificate extraction. Issues TPM2_NV_ReadPublic to learn the index
// size, then loops TPM2_NV_Read with offset += chunk until the full DER blob
// is in the caller's buffer. The full EK cert lives in TPM NV at indexes
// like TPM_NV_INDEX_RSA2048_EKCERT (0x01C00002), and the body is typically
// several kilobytes -- larger than any single NV_Read can return -- which is
// why the chunked loop exists. Wraps the SECTION 9 builders, with the
// resulting cert handed to the SECTION 15 profile validator. Cold path:
// runs on first execution and whenever the SECTION 21 change-detector flags
// an EK churn.
// ============================================================================
// SECTION 16 -- EK certificate extraction (NV_ReadPublic + chunked NV_Read)
// ============================================================================

NTSTATUS extract_ek_certificate(HANDLE device, EK_RECORD* rec, ULONG nv_index) noexcept
{
    UCHAR cmd[64];
    ULONG cmd_len = sizeof(cmd);
    UCHAR rsp[1280];
    ULONG rsp_used = 0;
    NTSTATUS s = tpm2_build_nv_read_public(nv_index, cmd, &cmd_len);
    if (!NT_SUCCESS(s)) { return s; }
    s = tpm2_submit_command(device, cmd, cmd_len, rsp, sizeof(rsp), &rsp_used);
    if (!NT_SUCCESS(s) || rsp_used < sizeof(TPM2_HEADER) + 16u)
    {
        rec->reason = TpmReason::NvReadCertFailed; return s;
    }
    const ULONG rc = peek_be32(rsp + 6);
    if (rc != TPM_RC_SUCCESS)
    {
        if (rc == TPM_RC_NV_NOT_AVAILABLE) { rec->reason = TpmReason::NvNotAvailable; }
        else                                { rec->reason = TpmReason::NvReadCertFailed; }
        rec->last_tpm_rc = rc;
        return STATUS_DEVICE_DATA_ERROR;
    }
    update_wire_digest(rec, rsp, rsp_used);

    const ULONG auth_policy_off = sizeof(TPM2_HEADER) + 2u + 4u + 2u + 4u;
    if (rsp_used < auth_policy_off + 2u) { rec->reason = TpmReason::NvReadCertFailed; return STATUS_INVALID_BUFFER_SIZE; }
    const USHORT auth_policy_size = peek_be16(rsp + auth_policy_off);
    const ULONG data_size_off = auth_policy_off + 2u + auth_policy_size;
    if (rsp_used < data_size_off + 2u) { rec->reason = TpmReason::NvReadCertFailed; return STATUS_INVALID_BUFFER_SIZE; }
    const ULONG data_size = peek_be16(rsp + data_size_off);
    if (data_size == 0u || data_size > TPM_EK_CERT_MAX)
    {
        rec->reason = TpmReason::NvReadCertFailed;
        return STATUS_INVALID_BUFFER_SIZE;
    }

    const ULONG slice = nv_buffer_max(device, rec);
    USHORT offset = 0;
    while (offset < (USHORT)data_size)
    {
        const USHORT chunk = (USHORT)((data_size - offset) > slice ? slice : (data_size - offset));
        UCHAR nvr_cmd[64];
        ULONG nvr_cmd_len = sizeof(nvr_cmd);
        s = tpm2_build_nv_read(nv_index, chunk, offset, nvr_cmd, &nvr_cmd_len);
        if (!NT_SUCCESS(s)) { return s; }
        UCHAR nvr_rsp[1280];
        ULONG nvr_used = 0;
        s = tpm2_submit_command(device, nvr_cmd, nvr_cmd_len, nvr_rsp, sizeof(nvr_rsp), &nvr_used);
        if (!NT_SUCCESS(s) || nvr_used < sizeof(TPM2_HEADER) + 4u)
        {
            rec->reason = TpmReason::NvReadCertFailed;
            return s;
        }
        update_wire_digest(rec, nvr_rsp, nvr_used);
        const ULONG nvr_rc = peek_be32(nvr_rsp + 6);
        if (nvr_rc != TPM_RC_SUCCESS)
        {
            rec->last_tpm_rc = nvr_rc;
            rec->reason = TpmReason::NvReadCertFailed;
            return STATUS_DEVICE_DATA_ERROR;
        }
        const USHORT read_size = peek_be16(nvr_rsp + sizeof(TPM2_HEADER) + 4);
        if (read_size == 0u || (ULONG)(offset + read_size) > data_size)
        {
            rec->reason = TpmReason::NvReadCertFailed;
            return STATUS_INVALID_BUFFER_SIZE;
        }
        RtlCopyMemory(rec->ek_cert + offset,
                      nvr_rsp + sizeof(TPM2_HEADER) + 6u,
                      read_size);
        offset = (USHORT)(offset + read_size);
    }
    rec->ek_cert_len = data_size;
    rec->cert_present = TRUE;
    return STATUS_SUCCESS;
}

BOOLEAN pcr0_pattern_emulator_hint(HANDLE device, EK_RECORD* rec) noexcept
{
    UCHAR pcr0[32] = { 0 };
    NTSTATUS s = tpm2_read_pcr0_sha256(device, pcr0);
    if (!NT_SUCCESS(s)) { return FALSE; }
    update_wire_digest(rec, pcr0, sizeof(pcr0));
    UCHAR a = 0, b = 0xFFu;
    for (ULONG i = 0; i < sizeof(pcr0); ++i) { a |= pcr0[i]; b &= pcr0[i]; }
    if (a == 0u || b == 0xFFu) { rec->emulator_detected = TRUE; return TRUE; }
    return FALSE;
}

// PPI registry probe -- reads the TPM Physical Presence Interface keys from
// the Windows TPM service registry hive. PPI tells me whether the platform
// can issue physical-presence TPM operations at boot, which gates several
// administrative TPM commands. Hangs off the SECTION 19 composite and the
// SECTION 24 HWID report, pure registry I/O, no TPM traffic. Called once
// per HWID poll cycle from the SECTION 39 orchestrator. Mechanically:
// ZwOpenKey + ZwQueryValueKey on the XOR-decoded TPM registry path.
// ============================================================================
// SECTION 18 -- PPI registry probe
// ============================================================================

void ppi_query(EK_RECORD* rec) noexcept
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return; }
    wchar_t root_buf[64];
    UNICODE_STRING root = emit_reg_tpm_root(root_buf);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &root, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE k_root = NULL;
    NTSTATUS s = ZwOpenKey(&k_root, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) { return; }
    UNICODE_STRING sub; RtlInitUnicodeString(&sub, L"AdminTpmActions");
    InitializeObjectAttributes(&oa, &sub, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, k_root, NULL);
    HANDLE k_sub = NULL;
    s = ZwOpenKey(&k_sub, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) { ZwClose(k_root); return; }
    UCHAR buf[64]; ULONG used = 0;
    UNICODE_STRING name1; RtlInitUnicodeString(&name1, L"TpmPhysicalPresenceEnabled");
    s = ZwQueryValueKey(k_sub, &name1, KeyValuePartialInformation, buf, sizeof(buf), &used);
    if (NT_SUCCESS(s))
    {
        KEY_VALUE_PARTIAL_INFORMATION* pi = (KEY_VALUE_PARTIAL_INFORMATION*)buf;
        if (pi->Type == REG_DWORD && pi->DataLength >= 4u)
        {
            const ULONG v = *(const ULONG*)pi->Data;
            if (v == 0u) { rec->reason = TpmReason::PpiDisabled; }
        }
    }
    UNICODE_STRING name2; RtlInitUnicodeString(&name2, L"TpmEnabledState");
    s = ZwQueryValueKey(k_sub, &name2, KeyValuePartialInformation, buf, sizeof(buf), &used);
    if (NT_SUCCESS(s))
    {
        KEY_VALUE_PARTIAL_INFORMATION* pi = (KEY_VALUE_PARTIAL_INFORMATION*)buf;
        if (pi->Type == REG_DWORD && pi->DataLength >= 4u)
        {
            const ULONG v = *(const ULONG*)pi->Data;
            if (v == 0u) { rec->reason = TpmReason::PpiDisabled; }
        }
    }
    ZwClose(k_sub); ZwClose(k_root);
}

// Composite projection -- folds all of the TPM, Secure-Boot, and PPI signals
// into one EK_RECORD slot. Downstream HWID code only ever sees one record,
// so this is where everything gets glued together into a single slot the
// composite_field bytes are copied from. Sits between the SECTION 18 PPI
// probe and the SECTION 20 EK master, drawing on the EK cache and history
// globals from SECTION 3. Runs once per HWID refresh, after every per-bank
// reader finishes; field-by-field copy with a fallback fill so missing TPM
// fields stay deterministic across reboots.
// ============================================================================
// SECTION 19 -- composite projection + fallback fill
// ============================================================================

void project_composite_field(EK_RECORD* rec) noexcept
{
    RtlCopyMemory(rec->composite_field, rec->modulus_sha256, VGK_HWID_SIZE_TPM_EK_HASH);
}

void fallback_zero_fill(EK_RECORD* rec) noexcept
{
    RtlZeroMemory(rec, sizeof(*rec));
    rec->reason = TpmReason::FallbackPath;
    vgk::susp::accumulate(kEkAbsentBit, 50);
}

// EK extraction master plus the ek_read_public_wrapped end-to-end
// orchestrator. I needed one entry point that returns a fully populated
// EK_RECORD or a typed TpmReason explaining the failure, otherwise every
// caller would have to redo the open/ReadPublic/NV_Read/cert-parse dance.
// Sits on the SECTION 16 cert extractor, the SECTION 13 capability helpers,
// and the SECTION 15 cert validator. Runs once per HWID composite refresh
// and on every EK-change event raised by SECTION 21. The mechanic: open the
// device, ReadPublic, NV_Read the cert, parse it, pull capabilities, then
// populate EK_RECORD in place.
// ============================================================================
// SECTION 20 -- EK extraction master + ek_read_public_wrapped
// ============================================================================

NTSTATUS ek_read_public_wrapped(HANDLE device, EK_RECORD* rec, ULONG ek_handle,
                                UCHAR* rsp_buf, ULONG rsp_cap, ULONG* rsp_used) noexcept
{
    NTSTATUS s = tpm2_read_ek_public(device, ek_handle, rsp_buf, rsp_cap, rsp_used);
    if (!NT_SUCCESS(s) || *rsp_used < sizeof(TPM2_HEADER))
    {
        rec->reason = TpmReason::ReadPubFailed; return s;
    }
    const ULONG rc = peek_be32(rsp_buf + 6);
    if (rc != TPM_RC_SUCCESS)
    {
        rec->last_tpm_rc = rc;
        rec->reason      = TpmReason::ReadPubFailed;
        return STATUS_DEVICE_DATA_ERROR;
    }
    update_wire_digest(rec, rsp_buf, *rsp_used);
    return STATUS_SUCCESS;
}

BOOLEAN  detect_ek_change(EK_RECORD* rec) noexcept;
NTSTATUS van68_emit_orchestrator(EK_RECORD* rec) noexcept;
BOOLEAN  ready_for_tpm_attestation(void) noexcept;

NTSTATUS extract_ek(EK_RECORD* out_record) noexcept
{
    if (out_record == nullptr) { return STATUS_INVALID_PARAMETER; }
    RtlZeroMemory(out_record, sizeof(*out_record));
    if (!ready_for_tpm_attestation())
    {
        out_record->reason = TpmReason::Absent;
        fallback_zero_fill(out_record);
        return STATUS_DEVICE_NOT_READY;
    }

    HANDLE device = NULL;
    NTSTATUS s = tpm2_open(&device);
    out_record->open_status = s;
    if (!NT_SUCCESS(s))
    {
        out_record->reason = TpmReason::OpenFailed;
        ppi_query(out_record);
        fallback_zero_fill(out_record);
        return s;
    }

    tpm_firmware_facts(device, out_record);
    emulator_detect(device, out_record);

    UCHAR rsp[1024];
    ULONG rsp_used = 0;
    ULONG handles[] = { TPM_EK_HANDLE_RSA2048, TPM_EK_HANDLE_ECC_P256,
                        TPM_EK_HANDLE_RSA3072, TPM_EK_HANDLE_RSA4096 };
    NTSTATUS read_status = STATUS_NOT_FOUND;
    for (ULONG i = 0; i < sizeof(handles) / sizeof(handles[0]); ++i)
    {
        rsp_used = 0;
        read_status = ek_read_public_wrapped(device, out_record, handles[i],
            rsp, sizeof(rsp), &rsp_used);
        if (NT_SUCCESS(read_status))
        {
            out_record->ek_handle = handles[i];
            break;
        }
    }
    if (!NT_SUCCESS(read_status))
    {
        ppi_query(out_record);
        tpm2_close(&device);
        fallback_zero_fill(out_record);
        van68_emit_orchestrator(out_record);
        return read_status;
    }

    const UCHAR* pub_bytes = rsp + sizeof(TPM2_HEADER) + 2u;
    const USHORT pub_size  = peek_be16(rsp + sizeof(TPM2_HEADER));
    parse_read_public_public_area(rsp, rsp_used, out_record);
    hash_ek_material(out_record, pub_bytes, pub_size);
        if (NT_SUCCESS(read_status))
        {
            out_record->ek_handle = handles[i];
            break;
        }
    }
    if (!NT_SUCCESS(read_status))
    {
        ppi_query(out_record);
        tpm2_close(&device);
        fallback_zero_fill(out_record);
        van68_emit_orchestrator(out_record);
        return read_status;
    }

    if (NT_SUCCESS(tpm2_read_pcr7_sha256(device, out_record->pcr7_sha256)))
    {
        out_record->pcr7_whitelist_match = vgk_pcr7_whitelist_check(out_record->pcr7_sha256);
        if (g_vgk_pcr7_whitelist_count > 0u && !out_record->pcr7_whitelist_match)
        {
            out_record->reason = TpmReason::Pcr7WhitelistMiss;
        }
    }

    tpm2_read_pcr14_sha256(device, out_record->pcr14_sha256);
    if (!vgk_pcr14_check_baseline(out_record->pcr14_sha256))
    {
        out_record->reason = TpmReason::EventLogMismatch;
    }

    detect_ek_change(out_record);
    tpm2_close(&device);

    if (out_record->reason != TpmReason::None)
    {
        van68_emit_orchestrator(out_record);
    }
    return STATUS_SUCCESS;
}

// EK change detection plus the history ring and churn analyser for EK
// rotations. An EK change means the TPM was reset, re-provisioned, or
// physically swapped, all of which are huge signals downstream -- attesters
// must reject a previously trusted identity if the underlying endorsement
// key rolls. Reads g_ek_cache and g_ek_history (the kEkHistoryDepth ring),
// emits VAN 68 deltas through the SECTION 22 emitter. The comparison runs
// every HWID poll; ring entries are retained for one Vanguard heartbeat
// window each. Mechanically: hash-compare current EK against every ring
// entry, bump the churn counter on mismatch, and raise the severity tier
// when the count crosses kAbsentEscalateCount.
// ============================================================================
// SECTION 21 -- EK change detection + history ring + churn analyser
// ============================================================================
    tpm2_read_pcr14_sha256(device, out_record->pcr14_sha256);
    if (!vgk_pcr14_check_baseline(out_record->pcr14_sha256))
    {
        out_record->reason = TpmReason::EventLogMismatch;
    }

    detect_ek_change(out_record);
    tpm2_close(&device);

    if (out_record->reason != TpmReason::None)
    {
        van68_emit_orchestrator(out_record);
    }
    return STATUS_SUCCESS;
}
    KeReleaseSpinLock(&g_ek_cache.lock, irql);
    if (diff)
    {
        rec->reason = TpmReason::EkChanged;
        vgk::susp::accumulate(kEkChangedBit, 200);
        return TRUE;
    }
    return FALSE;
}

void history_push(const EK_RECORD* rec) noexcept
{
    KIRQL irql;
    KeAcquireSpinLock(&g_ek_history.lock, &irql);
    EkHistoryEntry* e = &g_ek_history.entries[g_ek_history.head];
    e->observed_at_qpc = (ULONGLONG)KeQueryInterruptTime();
    RtlCopyMemory(e->modulus_sha256,  rec->modulus_sha256,  32);
    RtlCopyMemory(e->manufacturer_id, rec->manufacturer_id, 5);
    e->reason         = rec->reason;
    e->emulator_flag  = rec->emulator_detected ? 1u : 0u;
    e->wire_code      = (ULONG)reason_to_wire_code(rec->reason);
    g_ek_history.head = (g_ek_history.head + 1u) % kEkHistoryDepth;
    if (g_ek_history.count < kEkHistoryDepth) { g_ek_history.count++; }
    KeReleaseSpinLock(&g_ek_history.lock, irql);
}

NTSTATUS history_analyse_churn(void) noexcept
{
    EkHistoryEntry local[kEkHistoryDepth];
    ULONG          count;
    KIRQL          irql;
    KeAcquireSpinLock(&g_ek_history.lock, &irql);
    count = g_ek_history.count;
    if (count > 0u)
    {
        RtlCopyMemory(local, g_ek_history.entries, sizeof(EkHistoryEntry) * count);
    }
    KeReleaseSpinLock(&g_ek_history.lock, irql);

    BOOLEAN modulus_changed = FALSE;
    BOOLEAN mfg_changed     = FALSE;
    BOOLEAN emulator_blip   = FALSE;
    for (ULONG i = 1; i < count; ++i)
    {
        if (!RtlEqualMemory(local[i - 1].modulus_sha256,  local[i].modulus_sha256,  32)) { modulus_changed = TRUE; }
        if (!RtlEqualMemory(local[i - 1].manufacturer_id, local[i].manufacturer_id, 5))  { mfg_changed     = TRUE; }
        if (local[i - 1].emulator_flag == 1u && local[i].emulator_flag == 0u)            { emulator_blip   = TRUE; }
    }
    if (modulus_changed || mfg_changed || emulator_blip)
    {
        EK_RECORD synth = { 0 };
        synth.reason = emulator_blip ? TpmReason::EmulatorDetected : TpmReason::EkChanged;
        van68_emit_orchestrator(&synth);
    }
    return STATUS_SUCCESS;
}

// Severity classification and VAN 68 evidence emission for EK and TPM
// anomalies. Vanguard's central evidence pipeline expects VAN code packets
// wrapped in a 40-byte VAN68_EVIDENCE_HEADER, not raw EK deltas, so this is
// where the SECTION 21 churn output gets bucketed and serialized. Sits on
// the SECTION 21 churn analyser and feeds the SECTION 25 evidence packet
// writer. Runs per EK-anomaly classification on the heartbeat thread.
// Mechanically: classify_band buckets the delta into Notice/Soft/Warn/Hard/
// Lethal tiers from the Van68SubCause enum, then van68_emit_orchestrator
// stamps a packet with tag VAN68_TAG_TPM/MODINT/BCRYPT/etc.
// ============================================================================
// SECTION 22 -- severity classification + VAN 68 emission
// ============================================================================

void classify_band(const EK_RECORD* rec, const EK_CACHE* cache,
                   Band* out_band, UCHAR* out_severity) noexcept
{
    Band  band = Band::Notice;
    UCHAR sev  = 2;
    switch (rec->reason)
    {
        case TpmReason::PpiDisabled:        band = Band::Notice; sev = 2; break;
        case TpmReason::FallbackPath:
            if (cache != nullptr && cache->consecutive_failures >= kAbsentEscalateCount)
            { band = Band::Warn; sev = 5; }
            else { band = Band::Notice; sev = 2; }
            break;
        case TpmReason::EmulatorDetected:
            if (cache != nullptr && cache->baseline_valid) { band = Band::Hard; sev = 6; }
            else { band = Band::Warn; sev = 5; }
            break;
        case TpmReason::EkChanged:
        case TpmReason::AntiTamperMismatch: band = Band::Hard; sev = 6; break;
        case TpmReason::Pcr7WhitelistMiss:
        case TpmReason::EventLogMismatch:
        case TpmReason::QuoteFailed:        band = Band::Hard; sev = 6; break;
        case TpmReason::ReadPubFailed:
        case TpmReason::NvReadCertFailed:
        case TpmReason::CertParseFailed:
        case TpmReason::Absent:
        case TpmReason::OpenFailed:
        case TpmReason::CapabilityFailed:
        case TpmReason::SelfTestFailed:
        case TpmReason::Sha256Failed:
        case TpmReason::NvNotAvailable:     band = Band::Warn; sev = 5; break;
        default:                            band = Band::Notice; sev = 2; break;
    }
    if (out_band     != nullptr) { *out_band     = band; }
    if (out_severity != nullptr) { *out_severity = sev;  }
}

Van68SubCause reason_to_wire_code(TpmReason r) noexcept
{
    switch (r)
    {
        case TpmReason::Sha256Failed:      return Van68SubCause::BCrypt1;
        case TpmReason::QuoteFailed:       return Van68SubCause::QuoteSigBad;
        case TpmReason::Pcr7WhitelistMiss: return Van68SubCause::Pcr7Mismatch;
        case TpmReason::EventLogMismatch:  return Van68SubCause::EventLogBad;
        default:                            return Van68SubCause::TpmOrModule;
    }
}

NTSTATUS build_van68_payload(const EK_RECORD* rec, Band band, UCHAR severity,
                             Van68SubCause wire_code,
                             void* out_buf, ULONG out_cap, ULONG* out_len) noexcept
{
    if (out_buf == nullptr || out_len == nullptr || rec == nullptr) { return STATUS_INVALID_PARAMETER; }
    const ULONG record_bytes = (rec->cert_len > 0u && rec->cert_len < TPM_EK_CERT_MAX)
        ? (ULONG)(sizeof(EK_RECORD) - (TPM_EK_CERT_MAX - rec->cert_len))
        : (ULONG)sizeof(EK_RECORD);
    const ULONG total = sizeof(VAN68_EVIDENCE_HEADER) + 4u + record_bytes;
    if (out_cap < total) { *out_len = total; return STATUS_BUFFER_TOO_SMALL; }
    RtlZeroMemory(out_buf, total);

    VAN68_EVIDENCE_HEADER* hdr = (VAN68_EVIDENCE_HEADER*)out_buf;
    hdr->tag          = VAN68_TAG_TPM;
    hdr->length       = total - sizeof(VAN68_EVIDENCE_HEADER);
    hdr->wire_code    = (ULONG)wire_code;
    hdr->van_number   = VAN68_NUMBER;
    hdr->band         = (UCHAR)band;
    hdr->route        = (UCHAR)Route::B_LauncherPopup;
    hdr->audience     = (UCHAR)Audience::Launcher;
    hdr->severity     = severity;
    hdr->timestamp    = (ULONGLONG)KeQueryInterruptTime();
    ULONGLONG canary = 0;
    for (ULONG i = 0; i < 8u; ++i) { canary |= ((ULONGLONG)rec->wire_digest[i]) << (i * 8); }
    hdr->canary_delta = canary;

    UCHAR* w = (UCHAR*)out_buf + sizeof(VAN68_EVIDENCE_HEADER);
    *(ULONG*)w = (ULONG)rec->reason;
    w += 4u;
    RtlCopyMemory(w, rec, record_bytes);
    *out_len = total;
    return STATUS_SUCCESS;
}

NTSTATUS van68_push_evidence(const void* payload, ULONG payload_len) noexcept
{
    if (payload == nullptr || payload_len < sizeof(VAN68_EVIDENCE_HEADER)) { return STATUS_INVALID_PARAMETER; }
    const VAN68_EVIDENCE_HEADER* hdr = (const VAN68_EVIDENCE_HEADER*)payload;
    return vgk::evidence::push_packet(hdr->tag, payload, payload_len);
}

NTSTATUS van68_emit_orchestrator(EK_RECORD* rec) noexcept
{
    Band  band = Band::Notice;
    UCHAR sev  = 2;
    classify_band(rec, &g_ek_cache, &band, &sev);
    const Van68SubCause wire = reason_to_wire_code(rec->reason);
    UCHAR buffer[sizeof(VAN68_EVIDENCE_HEADER) + 4u + sizeof(EK_RECORD)];
    ULONG used = 0;
    NTSTATUS s = build_van68_payload(rec, band, sev, wire, buffer, sizeof(buffer), &used);
    if (!NT_SUCCESS(s)) { return s; }
    s = van68_push_evidence(buffer, used);
    if (!NT_SUCCESS(s)) { return s; }
    canary_feed(rec->wire_digest);
    ULONG mag = 100;
    if (band == Band::Notice) { mag = 50; }
    else if (band == Band::Hard) { mag = 200; }
    ULONG bit = kEkAbsentBit;
    if      (rec->reason == TpmReason::EkChanged)         { bit = kEkChangedBit; }
    else if (rec->reason == TpmReason::EmulatorDetected)  { bit = kEkEmulatorBit; }
    else if (rec->reason == TpmReason::CertParseFailed)   { bit = kEkCertBadBit; }
    else if (rec->reason == TpmReason::QuoteFailed)       { bit = kEkQuoteBadBit; }
    else if (rec->reason == TpmReason::Pcr7WhitelistMiss) { bit = kEkPcr7BadBit; }
    else if (rec->reason == TpmReason::EventLogMismatch)  { bit = kEkEventLogBadBit; }
    vgk::susp::accumulate(bit, mag);
    return STATUS_SUCCESS;
}

NTSTATUS read_secureboot_policy_hash(UCHAR out[32]) noexcept
{
    ULONG required = 0;
    NTSTATUS s = ZwQuerySystemInformation(SystemSecureBootPolicyInformation, NULL, 0, &required);
    if (s != STATUS_INFO_LENGTH_MISMATCH && s != STATUS_BUFFER_TOO_SMALL) { return s; }
    if (required == 0u || required > 0x10000u) { return STATUS_NOT_SUPPORTED; }
    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, required, 'oBcS');
    if (buf == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    ULONG got = 0;
    s = ZwQuerySystemInformation(SystemSecureBootPolicyInformation, buf, required, &got);
    if (NT_SUCCESS(s)) { s = bcrypt_sha256_block(buf, got, out); }
    ExFreePoolWithTag(buf, 'oBcS');
    return s;
}

NTSTATUS hash_uefi_variable(const UNICODE_STRING* name, const GUID* guid,
                            BCRYPT_HASH_HANDLE hash) noexcept
{
    ULONG sz = 0; ULONG attrs = 0;
    NTSTATUS s = ExGetFirmwareEnvironmentVariable((PUNICODE_STRING)name, (LPGUID)guid, NULL, &sz, &attrs);
    if (s != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(s)) { return s; }
    if (sz == 0u) { return STATUS_SUCCESS; }
    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, sz, 'oBcS');
    if (buf == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    s = ExGetFirmwareEnvironmentVariable((PUNICODE_STRING)name, (LPGUID)guid, buf, &sz, &attrs);
    if (NT_SUCCESS(s)) { s = BCryptHashData(hash, (PUCHAR)buf, sz, 0); }
    ExFreePoolWithTag(buf, 'oBcS');
    return s;
}

NTSTATUS secureboot_variable_chain_hash(UCHAR out[32]) noexcept
{
    static const GUID kEfiGlobal = { 0x8be4df61, 0x93ca, 0x11d2,
        { 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c } };
    static const GUID kEfiImageSecDb = { 0xd719b2cb, 0x3d3a, 0x4596,
        { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } };
    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) { return s; }
    s = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (NT_SUCCESS(s))
    {
        UNICODE_STRING pk;    RtlInitUnicodeString(&pk,    L"PK");
        UNICODE_STRING kek;   RtlInitUnicodeString(&kek,   L"KEK");
        UNICODE_STRING db;    RtlInitUnicodeString(&db,    L"db");
        UNICODE_STRING dbx;   RtlInitUnicodeString(&dbx,   L"dbx");
        UNICODE_STRING setup; RtlInitUnicodeString(&setup, L"SetupMode");
        hash_uefi_variable(&pk,    &kEfiGlobal,     hash);
        hash_uefi_variable(&kek,   &kEfiGlobal,     hash);
        hash_uefi_variable(&db,    &kEfiImageSecDb, hash);
        hash_uefi_variable(&dbx,   &kEfiImageSecDb, hash);
        hash_uefi_variable(&setup, &kEfiGlobal,     hash);
        s = BCryptFinishHash(hash, out, 32, 0);
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return s;
}

// HWID_TPM_SB_REPORT assembler -- the final TPM-plus-SecureBoot evidence blob
// that wraps everything from the upstream readers into a fixed-layout struct.
// The boot driver expects a single binary blob per HWID slot, so this is
// where EK digests, PCR0/PCR7/PCR14 digests, SetupMode/SecureBoot bits, and
// boot environment data get packed in stable byte order. Output of SECTIONS
// 19-21 feeds in; the SECTION 25 evidence packet writer consumes the result.
// Runs once per HWID composite cycle (one boot pass plus each runtime poll).
// Mechanically a sequential field-by-field pack into HWID_TPM_SB_REPORT with
// no padding.
// ============================================================================
