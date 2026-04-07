/*
 * Kerberos Protocol Structures and Definitions
 * Based on RFC 4120 and Windows Kerberos implementation
 */

#ifndef _KRB5_STRUCT_H_
#define _KRB5_STRUCT_H_

/* Must include winsock2 before windows.h to avoid conflicts */
#include <winsock2.h>
#include <windows.h>

/* Include Windows security headers */
#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>

/* Basic types */
typedef unsigned int uint;
typedef unsigned char byte;
#ifndef __cplusplus
#ifndef bool
typedef int bool;
#define true 1
#define false 0
#endif
#endif

/* NTSTATUS if not defined */
#ifndef _NTDEF_
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* ============================================================================
 * Kerberos Protocol Constants (RFC 4120)
 * ============================================================================ */

/* Kerberos Protocol Version */
#define KRB5_PVNO 5

/* Message Types */
#define KRB5_AS_REQ     10
#define KRB5_AS_REP     11
#define KRB5_TGS_REQ    12
#define KRB5_TGS_REP    13
#define KRB5_AP_REQ     14
#define KRB5_AP_REP     15
#define KRB5_SAFE       20
#define KRB5_PRIV       21
#define KRB5_CRED       22
#define KRB5_ERROR      30

/* Encryption Types */
#define ETYPE_DES_CBC_CRC           1
#define ETYPE_DES_CBC_MD4           2
#define ETYPE_DES_CBC_MD5           3
#define ETYPE_DES3_CBC_MD5          5
#define ETYPE_DES3_CBC_SHA1         7
#define ETYPE_DES3_CBC_SHA1_KD      16
#define ETYPE_AES128_CTS_HMAC_SHA1  17
#define ETYPE_AES256_CTS_HMAC_SHA1  18
#define ETYPE_RC4_HMAC              23
#define ETYPE_RC4_HMAC_EXP          24

/* Principal Name Types */
#define KRB5_NT_UNKNOWN        0
#define KRB5_NT_PRINCIPAL      1
#define KRB5_NT_SRV_INST       2
#define KRB5_NT_SRV_HST        3
#define KRB5_NT_SRV_XHST       4
#define KRB5_NT_UID            5
#define KRB5_NT_X500_PRINCIPAL 6
#define KRB5_NT_SMTP_NAME      7
#define KRB5_NT_ENTERPRISE     10

/* KDC Options Flags */
#define KDCOPTION_FORWARDABLE       0x40000000
#define KDCOPTION_FORWARDED         0x20000000
#define KDCOPTION_PROXIABLE         0x10000000
#define KDCOPTION_PROXY             0x08000000
#define KDCOPTION_ALLOW_POSTDATE    0x04000000
#define KDCOPTION_POSTDATED         0x02000000
#define KDCOPTION_RENEWABLE         0x00800000
#define KDCOPTION_CANONICALIZE      0x00010000
#define KDCOPTION_RENEW             0x00000002
#define KDCOPTION_VALIDATE          0x00000001

/* Ticket Flags */
#define TICKETFLAG_FORWARDABLE      0x40000000
#define TICKETFLAG_FORWARDED        0x20000000
#define TICKETFLAG_PROXIABLE        0x10000000
#define TICKETFLAG_PROXY            0x08000000
#define TICKETFLAG_MAY_POSTDATE     0x04000000
#define TICKETFLAG_POSTDATED        0x02000000
#define TICKETFLAG_INVALID          0x01000000
#define TICKETFLAG_RENEWABLE        0x00800000
#define TICKETFLAG_INITIAL          0x00400000
#define TICKETFLAG_PRE_AUTHENT      0x00200000
#define TICKETFLAG_HW_AUTHENT       0x00100000
#define TICKETFLAG_OK_AS_DELEGATE   0x00040000

/* Pre-Authentication Data Types */
#define PADATA_TGS_REQ              1
#define PADATA_ENC_TIMESTAMP        2
#define PADATA_ETYPE_INFO           11
#define PADATA_ETYPE_INFO2          19
#define PADATA_FOR_USER             129
#define PADATA_PAC_REQUEST          128

/* Kerberos Error Codes */
#define KDC_ERR_NONE                    0
#define KDC_ERR_C_PRINCIPAL_UNKNOWN     6
#define KDC_ERR_S_PRINCIPAL_UNKNOWN     7
#define KDC_ERR_ETYPE_NOSUPP            14
#define KDC_ERR_CLIENT_REVOKED          18
#define KDC_ERR_PREAUTH_FAILED          24
#define KDC_ERR_PREAUTH_REQUIRED        25
#define KRB_AP_ERR_BAD_INTEGRITY        31
#define KRB_AP_ERR_TKT_EXPIRED          32
#define KRB_AP_ERR_SKEW                 37
#define KRB_AP_ERR_MODIFIED             41

/* ASN.1 Tags */
#define ASN1_BOOLEAN         0x01
#define ASN1_INTEGER         0x02
#define ASN1_BITSTRING       0x03
#define ASN1_OCTETSTRING     0x04
#define ASN1_NULL            0x05
#define ASN1_OID             0x06
#define ASN1_ENUMERATED      0x0A
#define ASN1_UTF8STRING      0x0C
#define ASN1_SEQUENCE        0x30
#define ASN1_SET             0x31
#define ASN1_PRINTABLESTRING 0x13
#define ASN1_IA5STRING       0x16
#define ASN1_UTCTIME         0x17
#define ASN1_GENERALIZEDTIME 0x18
#define ASN1_GENERALSTRING   0x1B
#define ASN1_CONTEXT(x)      (0xA0 | (x))
#define ASN1_APP(x)          (0x60 | (x))

/* Key Usage Values */
#define KRB_KEY_USAGE_AS_REQ_PA_ENC_TS       1
#define KRB_KEY_USAGE_AS_REP_TGS_REP         2

/* Kerberos Port */
#define KRB5_PORT 88

/* ============================================================================
 * Custom Kerberos Structures
 * ============================================================================ */

/* Buffer structure */
typedef struct _KRB_BUFFER {
    BYTE*  data;
    SIZE_T length;
    SIZE_T capacity;
} KRB_BUFFER, *PKRB_BUFFER;

/* Principal Name */
typedef struct _KRB_PRINCIPAL {
    int   nameType;
    int   nameCount;
    char* nameStrings[10];
    char* realm;
} KRB_PRINCIPAL, *PKRB_PRINCIPAL;

/* Encryption Key */
typedef struct _KRB_ENCKEY {
    int   keyType;
    BYTE* keyValue;
    int   keyLength;
} KRB_ENCKEY, *PKRB_ENCKEY;

/* Encrypted Data */
typedef struct _KRB_ENCDATA {
    int   etype;
    int   kvno;
    BYTE* cipher;
    int   cipherLen;
} KRB_ENCDATA, *PKRB_ENCDATA;

/* Ticket */
typedef struct _KRB_TICKET {
    int           tktVno;
    char*         realm;
    KRB_PRINCIPAL sname;
    KRB_ENCDATA   encPart;
} KRB_TICKET, *PKRB_TICKET;

/* Times */
typedef struct _KRB_TIMES {
    FILETIME authTime;
    FILETIME startTime;
    FILETIME endTime;
    FILETIME renewTill;
} KRB_TIMES, *PKRB_TIMES;

/* Error code to string mapping - using if-else to avoid MSVC jump tables */
static const char* krb5_error_string(int code) {
    if (code == KDC_ERR_NONE) return "KDC_ERR_NONE";
    if (code == KDC_ERR_C_PRINCIPAL_UNKNOWN) return "Client not found in Kerberos database";
    if (code == KDC_ERR_S_PRINCIPAL_UNKNOWN) return "Server not found in Kerberos database";
    if (code == KDC_ERR_PREAUTH_REQUIRED) return "Pre-authentication required";
    if (code == KDC_ERR_PREAUTH_FAILED) return "Pre-authentication failed";
    if (code == KDC_ERR_CLIENT_REVOKED) return "Client's credentials have been revoked";
    if (code == KDC_ERR_ETYPE_NOSUPP) return "Encryption type not supported";
    if (code == KRB_AP_ERR_BAD_INTEGRITY) return "Integrity check failed";
    if (code == KRB_AP_ERR_TKT_EXPIRED) return "Ticket has expired";
    if (code == KRB_AP_ERR_SKEW) return "Clock skew too great";
    if (code == KRB_AP_ERR_MODIFIED) return "Message stream modified";
    return "Unknown error";
}

/* Encryption type to string mapping - using if-else to avoid MSVC jump tables */
static const char* etype_string(int etype) {
    if (etype == ETYPE_DES_CBC_CRC) return "DES-CBC-CRC";
    if (etype == ETYPE_DES_CBC_MD5) return "DES-CBC-MD5";
    if (etype == ETYPE_DES3_CBC_SHA1_KD) return "DES3-CBC-SHA1";
    if (etype == ETYPE_AES128_CTS_HMAC_SHA1) return "AES128-CTS-HMAC-SHA1-96";
    if (etype == ETYPE_AES256_CTS_HMAC_SHA1) return "AES256-CTS-HMAC-SHA1-96";
    if (etype == ETYPE_RC4_HMAC) return "RC4-HMAC";
    if (etype == ETYPE_RC4_HMAC_EXP) return "RC4-HMAC-EXP";
    return "Unknown";
}

#endif /* _KRB5_STRUCT_H_ */
