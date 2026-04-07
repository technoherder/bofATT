# Untested / Undocumented BOFs

BOFs that exist as compiled binaries but are **not yet documented or tested** in `BOF_REFERENCE.md`.

**Total:** 38 Kerberos + 4 Certify = **42 BOFs to test**

---

## Kerberos BOFs (kerbeus/bin/)

### Ticket Operations
- [ ] **krb_asktgs** - Request a Ticket Granting Service (TGS) ticket
- [ ] **krb_asktgtrc4** - Request TGT specifically with RC4 encryption
- [ ] **krb_ptt** - Pass-the-ticket (import ticket into session)
- [ ] **krb_tgtdeleg** - TGT delegation trick (extract usable TGT from delegation)
- [ ] **krb_renew** - Renew an existing Kerberos ticket
- [ ] **krb_kirbi** - Convert tickets to/from .kirbi format
- [ ] **krb_ccache** - Convert tickets to/from ccache format
- [ ] **krb_asrep2kirbi** - Convert AS-REP response to .kirbi ticket
- [ ] **krb_tgssub** - TGS ticket substitution/manipulation

### Roasting & Credential Attacks
- [ ] **krb_asreproasting** - AS-REP roasting (manual, vs _auto version)
- [ ] **krb_preauthscan** - Scan users for disabled pre-authentication
- [ ] **krb_brute** - Kerberos brute-force / password spraying
- [ ] **krb_spray** - Password spray attack via Kerberos

### Ticket Forging
- [ ] **krb_golden** - Golden ticket creation (forged TGT)
- [ ] **krb_silver** - Silver ticket creation (forged TGS)
- [ ] **krb_diamond** - Diamond ticket creation (modified legitimate TGT)
- [ ] **krb_nopac** - NoPac / sAMAccountName spoofing attack (CVE-2021-42287)

### Delegation Attacks
- [ ] **krb_s4u** - S4U2Self / S4U2Proxy constrained delegation abuse
- [ ] **krb_rbcd** - Resource-Based Constrained Delegation attack
- [ ] **krb_bronzebit** - Bronze Bit attack (CVE-2020-17049, S4U2Proxy bypass)
- [ ] **krb_delegenum** - Enumerate delegation configurations in domain
- [ ] **krb_unconstrained_enum** - Enumerate hosts with unconstrained delegation

### Coercion & Lateral Movement
- [ ] **krb_printerbug** - SpoolService/PrinterBug coercion (force auth)
- [ ] **krb_petitpotam** - PetitPotam coercion (EFSRPC abuse)
- [ ] **krb_dcsync** - DCSync attack (replicate credentials from DC)
- [ ] **krb_crossdomain** - Cross-domain/trust ticket operations
- [ ] **krb_u2u** - User-to-User Kerberos authentication attack

### Session & Process Management
- [ ] **krb_createnetonly** - Create process with NETWORK_ONLY logon (for ticket injection)
- [ ] **krb_monitor** - Monitor for new Kerberos tickets (continuous)
- [ ] **krb_harvest** - Harvest tickets from all logon sessions

### Credential & Account Manipulation
- [ ] **krb_changepw** - Change user password via Kerberos
- [ ] **krb_resetpw** - Reset user password via Kerberos

### Enumeration & Recon
- [ ] **krb_showall** - Show all Kerberos-related information
- [ ] **krb_anonldap** - Anonymous LDAP enumeration
- [ ] **krb_stats** - Kerberos statistics/info
- [ ] **krb_pac** - PAC (Privilege Attribute Certificate) inspection

### Misc / Advanced
- [ ] **krb_opsec** - OPSEC-safe Kerberos operations
- [ ] **krb_kdcproxy** - KDC Proxy support (Kerberos over HTTPS)

---

## Certify BOFs (certify/bin/)

- [ ] **cert_download** - Download a certificate from CA
- [ ] **cert_forge** - Forge certificates (Golden Cert / ESC7)
- [ ] **cert_manageca** - CA management operations (backup CA, manage officers)
- [ ] **cert_pkiobjects** - Enumerate PKI objects in AD

---

## Already Documented (16 Kerberos + 4 Certify + 1 Other)

For reference, these are already in `BOF_REFERENCE.md`:

| BOF | Category |
|-----|----------|
| krb_klist | Ticket listing |
| krb_asreproast_auto | AS-REP roasting (auto) |
| krb_spnenum | SPN enumeration |
| krb_spnroast | Kerberoasting (targeted) |
| krb_asktgt | Request TGT |
| krb_currentluid | Get current LUID |
| krb_hash | Calculate password hashes |
| krb_triage | Quick ticket triage |
| krb_kerberoasting | Kerberoasting |
| krb_dump | Dump cached tickets |
| krb_unconstrained | Unconstrained delegation monitor |
| krb_overpass | Overpass-the-hash |
| krb_purge | Purge ticket cache |
| krb_logonsession | Logon session enumeration |
| krb_shadowcred | Shadow Credentials attack |
| krb_describe | Describe ticket structure |
| cert_find | Find vulnerable templates |
| cert_cas | Enumerate CAs |
| cert_request | Request certificate |
| cert_request_agent | Enrollment agent request |
| memdumper | Process memory dump |

---

## Priority Suggestions

**High priority (common in CTF/HTB):**
1. `krb_golden` / `krb_silver` / `krb_diamond` - Ticket forging
2. `krb_dcsync` - Domain credential dump
3. `krb_s4u` / `krb_rbcd` - Delegation attacks
4. `krb_ptt` - Pass-the-ticket
5. `krb_nopac` - sAMAccountName spoofing
6. `cert_forge` - Golden cert attacks

**Medium priority:**
7. `krb_asktgs` - TGS requests
8. `krb_printerbug` / `krb_petitpotam` - Coercion
9. `krb_brute` / `krb_spray` - Password attacks
10. `krb_delegenum` / `krb_unconstrained_enum` - Delegation recon

**Lower priority (utility):**
11. `krb_kirbi` / `krb_ccache` / `krb_asrep2kirbi` - Format conversion
12. `krb_changepw` / `krb_resetpw` - Password ops
13. `krb_createnetonly` / `krb_monitor` / `krb_harvest` - Session mgmt
