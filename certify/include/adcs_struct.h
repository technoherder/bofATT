/*
 * adcs_struct.h - Active Directory Certificate Services Structures
 *
 * Structures and definitions for AD CS enumeration and abuse
 */

#ifndef ADCS_STRUCT_H
#define ADCS_STRUCT_H

/* Include winsock2.h before windows.h to prevent conflicts */
#include <winsock2.h>
#include <windows.h>
#include <winldap.h>
#include <winber.h>

/* Certificate Template OIDs and Flags */
#define szOID_CERTIFICATE_TEMPLATE "1.3.6.1.4.1.311.21.7"
#define szOID_ENROLL_CERTTYPE_EXTENSION "1.3.6.1.4.1.311.20.2"
#define szOID_APPLICATION_CERT_POLICIES "1.3.6.1.4.1.311.21.10"
#define szOID_CERT_MANIFOLD "1.3.6.1.4.1.311.20.3"

/* Extended Key Usage OIDs */
#define szOID_CLIENT_AUTHENTICATION "1.3.6.1.5.5.7.3.2"
#define szOID_PKIX_KP_CLIENT_AUTH "1.3.6.1.5.5.7.3.2"
#define szOID_PKIX_KP_SERVER_AUTH "1.3.6.1.5.5.7.3.1"
#define szOID_SMART_CARD_LOGON "1.3.6.1.4.1.311.20.2.2"
#define szOID_KP_SMARTCARD_LOGON "1.3.6.1.4.1.311.20.2.2"
#define szOID_ANY_APPLICATION_POLICY "1.3.6.1.4.1.311.10.12.1"
#define szOID_ENROLLMENT_AGENT "1.3.6.1.4.1.311.20.2.1"
#define szOID_PKIX_KP_EMAIL_PROTECTION "1.3.6.1.5.5.7.3.4"
#define szOID_PKIX_KP_CODE_SIGNING "1.3.6.1.5.5.7.3.3"

/* Certificate Template Schema Version */
#define CERTTYPE_SCHEMA_VERSION_1 1
#define CERTTYPE_SCHEMA_VERSION_2 2
#define CERTTYPE_SCHEMA_VERSION_3 3
#define CERTTYPE_SCHEMA_VERSION_4 4

/* Enrollment Flags */
#define CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS    0x00000001
#define CT_FLAG_PEND_ALL_REQUESTS               0x00000002
#define CT_FLAG_PUBLISH_TO_KRA_CONTAINER        0x00000004
#define CT_FLAG_PUBLISH_TO_DS                   0x00000008
#define CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS   0x00000010
#define CT_FLAG_AUTO_ENROLLMENT                 0x00000020
#define CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT 0x00000040
#define CT_FLAG_USER_INTERACTION_REQUIRED       0x00000100
#define CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE 0x00000400
#define CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF       0x00000800
#define CT_FLAG_ADD_OCSP_NOCHECK                0x00001000
#define CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL 0x00002000
#define CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS   0x00004000
#define CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS 0x00008000
#define CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT 0x00010000
#define CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST  0x00020000

/* msPKI-Certificate-Name-Flag */
#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT       0x00000001
#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME 0x00010000
#define CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS  0x00400000
#define CT_FLAG_SUBJECT_ALT_REQUIRE_SPN         0x00800000
#define CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID 0x01000000
#define CT_FLAG_SUBJECT_ALT_REQUIRE_UPN         0x02000000
#define CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL       0x04000000
#define CT_FLAG_SUBJECT_ALT_REQUIRE_DNS         0x08000000
#define CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN       0x10000000
#define CT_FLAG_SUBJECT_REQUIRE_EMAIL           0x20000000
#define CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME     0x40000000
#define CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH  0x80000000

/* msPKI-Private-Key-Flag */
#define CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL    0x00000001
#define CT_FLAG_EXPORTABLE_KEY                  0x00000010
#define CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED  0x00000020
#define CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM 0x00000040
#define CT_FLAG_REQUIRE_SAME_KEY_RENEWAL        0x00000080
#define CT_FLAG_USE_LEGACY_PROVIDER             0x00000100
#define CT_FLAG_ATTEST_NONE                     0x00000000
#define CT_FLAG_ATTEST_REQUIRED                 0x00002000
#define CT_FLAG_ATTEST_PREFERRED                0x00001000
#define CT_FLAG_ATTESTATION_WITHOUT_POLICY      0x00004000
#define CT_FLAG_EK_TRUST_ON_USE                 0x00000200
#define CT_FLAG_EK_VALIDATE_CERT                0x00000400
#define CT_FLAG_EK_VALIDATE_KEY                 0x00000800
#define CT_FLAG_HELLO_LOGON_KEY                 0x00200000

/* msPKI-RA-Signature */
#define CT_FLAG_RA_SIGNATURE_REQUIRED           0x00000001

/* Certificate Enrollment Web Services */
#define WS_ENROLLMENT_POLICY_ENDPOINT           L"/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"
#define WS_ENROLLMENT_SERVICE_ENDPOINT          L"/CES_Kerberos/service.svc/CES"

/* LDAP Attributes for Certificate Templates */
#define LDAP_ATTR_CN                            "cn"
#define LDAP_ATTR_DISPLAY_NAME                  "displayName"
#define LDAP_ATTR_OBJECT_CLASS                  "objectClass"
#define LDAP_ATTR_MSPKI_CERT_TEMPLATE_OID       "msPKI-Cert-Template-OID"
#define LDAP_ATTR_MSPKI_CERTIFICATE_NAME_FLAG   "msPKI-Certificate-Name-Flag"
#define LDAP_ATTR_MSPKI_ENROLLMENT_FLAG         "msPKI-Enrollment-Flag"
#define LDAP_ATTR_MSPKI_PRIVATE_KEY_FLAG        "msPKI-Private-Key-Flag"
#define LDAP_ATTR_MSPKI_RA_SIGNATURE            "msPKI-RA-Signature"
#define LDAP_ATTR_MSPKI_MINIMAL_KEY_SIZE        "msPKI-Minimal-Key-Size"
#define LDAP_ATTR_MSPKI_TEMPLATE_SCHEMA_VERSION "msPKI-Template-Schema-Version"
#define LDAP_ATTR_PKI_EXTENDED_KEY_USAGE        "pKIExtendedKeyUsage"
#define LDAP_ATTR_PKI_EXPIRATION_PERIOD         "pKIExpirationPeriod"
#define LDAP_ATTR_PKI_OVERLAP_PERIOD            "pKIOverlapPeriod"
#define LDAP_ATTR_PKI_DEFAULT_CSPS              "pKIDefaultCSPs"
#define LDAP_ATTR_PKI_DEFAULT_KEY_SPEC          "pKIDefaultKeySpec"
#define LDAP_ATTR_CERTIFICATE_TEMPLATES         "certificateTemplates"
#define LDAP_ATTR_SECURITY_DESCRIPTOR           "nTSecurityDescriptor"

/* LDAP Attributes for Certificate Authorities */
#define LDAP_ATTR_CA_CERTIFICATE                "cACertificate"
#define LDAP_ATTR_CA_CERTIFICATE_DN             "cACertificateDN"
#define LDAP_ATTR_DNS_HOST_NAME                 "dNSHostName"
#define LDAP_ATTR_CERTIFICATE_REVOCATION_LIST   "certificateRevocationList"

/* Access Rights for Certificate Templates */
#define CERTIFICATE_ENROLL                      0x00000004
#define CERTIFICATE_AUTOENROLL                  0x00000020

/* Well-known SIDs */
#define SID_AUTHENTICATED_USERS                 "S-1-5-11"
#define SID_DOMAIN_USERS                        "S-1-5-21-*-513"
#define SID_DOMAIN_COMPUTERS                    "S-1-5-21-*-515"
#define SID_EVERYONE                            "S-1-1-0"

/* Certificate Request Disposition */
#define CR_DISP_INCOMPLETE                      0
#define CR_DISP_ERROR                           1
#define CR_DISP_DENIED                          2
#define CR_DISP_ISSUED                          3
#define CR_DISP_ISSUED_OUT_OF_BAND              4
#define CR_DISP_UNDER_SUBMISSION                5
#define CR_DISP_REVOKED                         6

/* CA Flags */
#define CA_FLAG_SUPPORTS_NT_AUTHENTICATION      0x00000001
#define CA_FLAG_CA_SUPPORTS_MANUAL_AUTHENTICATION 0x00000002
#define CA_FLAG_CA_SERVERTYPE_ADVANCED          0x00000004

/* Vulnerability types */
typedef enum {
    VULN_NONE = 0,
    VULN_ESC1 = 1,           /* Template allows client auth + enrollee supplies subject */
    VULN_ESC2 = 2,           /* Template has Any Purpose or no EKU */
    VULN_ESC3 = 3,           /* Certificate Request Agent template */
    VULN_ESC4 = 4,           /* Vulnerable template ACLs */
    VULN_ESC5 = 5,           /* Vulnerable PKI object ACLs */
    VULN_ESC6 = 6,           /* EDITF_ATTRIBUTESUBJECTALTNAME2 on CA */
    VULN_ESC7 = 7,           /* Vulnerable CA ACLs */
    VULN_ESC8 = 8,           /* NTLM Relay to HTTP enrollment */
    VULN_ESC9 = 9,           /* No security extension */
    VULN_ESC10 = 10,         /* Weak cert mapping */
    VULN_ESC11 = 11,         /* IF_ENFORCEENCRYPTICERTREQUEST not set */
    VULN_ESC13 = 13,         /* Issuance policy with group link */
    VULN_ESC14 = 14,         /* Weak explicit mappings */
    VULN_ESC15 = 15,         /* Application policies in schema v1 */
} VULN_TYPE;

/* Certificate Template Info Structure */
typedef struct _CERT_TEMPLATE_INFO {
    WCHAR* name;
    WCHAR* displayName;
    WCHAR* oid;
    DWORD schemaVersion;
    DWORD enrollmentFlag;
    DWORD certificateNameFlag;
    DWORD privateKeyFlag;
    DWORD raSignature;
    DWORD minKeySize;
    WCHAR** ekus;
    DWORD ekuCount;
    WCHAR** enrollmentPrincipals;
    DWORD enrollmentPrincipalCount;
    VULN_TYPE* vulnerabilities;
    DWORD vulnCount;
    BOOL clientAuthentication;
    BOOL enrolleeSuppliesSubject;
    BOOL requiresManagerApproval;
    BOOL authorizedSignaturesRequired;
} CERT_TEMPLATE_INFO, *PCERT_TEMPLATE_INFO;

/* Certificate Authority Info Structure */
typedef struct _CA_INFO {
    WCHAR* name;
    WCHAR* dnsHostName;
    WCHAR* caName;
    WCHAR* distinguishedName;
    WCHAR** certificateTemplates;
    DWORD templateCount;
    BOOL webEnrollmentEnabled;
    BOOL editfAttributeSubjectAltName2;
    VULN_TYPE* vulnerabilities;
    DWORD vulnCount;
} CA_INFO, *PCA_INFO;

/* DER/ASN.1 Constants */
#define ASN1_SEQUENCE           0x30
#define ASN1_SET                0x31
#define ASN1_INTEGER            0x02
#define ASN1_BITSTRING          0x03
#define ASN1_OCTETSTRING        0x04
#define ASN1_NULL               0x05
#define ASN1_OID                0x06
#define ASN1_UTF8STRING         0x0C
#define ASN1_PRINTABLESTRING    0x13
#define ASN1_IA5STRING          0x16
#define ASN1_UTCTIME            0x17
#define ASN1_GENERALIZEDTIME    0x18
#define ASN1_CONTEXT(n)         (0xA0 | (n))

/* Certificate Request Format */
#define X509_ASN_ENCODING       0x00000001
#define PKCS_7_ASN_ENCODING     0x00010000
#define ENCODING_TYPE           (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#endif /* ADCS_STRUCT_H */
