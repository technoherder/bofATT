#!/usr/bin/env python3
import struct, os, sys

def der_length(length):
    if length < 0x80: return bytes([length])
    elif length < 0x100: return bytes([0x81, length])
    elif length < 0x10000: return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else: raise ValueError("too large")

def der_tlv(tag, value):
    if isinstance(value, int): value = bytes([value])
    return bytes([tag]) + der_length(len(value)) + value

def der_integer(value):
    if value == 0: return der_tlv(0x02, bytes([0]))
    byte_len = (value.bit_length() + 8) // 8
    raw = value.to_bytes(byte_len, byteorder="big", signed=False)
    while len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80: raw = raw[1:]
    return der_tlv(0x02, raw)

def der_gs(s): return der_tlv(0x1B, s.encode("ascii"))
def der_gt(s): return der_tlv(0x18, s.encode("ascii"))
def der_bs(data): return der_tlv(0x03, bytes([0]) + data)
def der_seq(c): return der_tlv(0x30, c)
def der_sof(items): return der_tlv(0x30, b"".join(items))
def der_ctx(n, c): return der_tlv(0xA0 | n, c)

def build_asreq(username, realm, nonce=None):
    if nonce is None: nonce = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
    print(f"[*] Building AS-REQ for {username}@{realm}")
    print(f"[*] Nonce: {nonce} (0x{nonce:08X})")
    f0 = der_ctx(0, der_bs(struct.pack(">I", 0x40810010)))
    f1 = der_ctx(1, der_seq(der_ctx(0, der_integer(1)) + der_ctx(1, der_sof([der_gs(username)]))))
    f2 = der_ctx(2, der_gs(realm))
    f3 = der_ctx(3, der_seq(der_ctx(0, der_integer(2)) + der_ctx(1, der_sof([der_gs("krbtgt"), der_gs(realm)]))))
    f5 = der_ctx(5, der_gt("20370913024805Z"))
    f7 = der_ctx(7, der_integer(nonce))
    f8 = der_ctx(8, der_sof([der_integer(23)]))
    body = der_seq(f0 + f1 + f2 + f3 + f5 + f7 + f8)
    inner = der_ctx(1, der_integer(5)) + der_ctx(2, der_integer(10)) + der_ctx(4, body)
    return bytes([0x6A]) + der_length(len(inner)) + inner, nonce

def hexdump(data):
    for i in range(0, len(data), 16):
        c = data[i:i+16]
        h = " ".join(f"{b:02X}" for b in c)
        a = "".join(chr(b) if 32<=b<127 else "." for b in c)
        print(f"  {i:04X}  {h:<48s}  {a}")

def annotate(data, indent=0):
    o = 0; pfx = "  " * indent
    while o < len(data):
        tb = data[o]; to = o; o += 1
        tc = (tb>>6)&3; con = bool(tb&0x20); tn = tb&0x1F
        if o >= len(data): break
        lb = data[o]; o += 1
        if lb < 0x80: ln = lb
        elif lb == 0x81: ln = data[o]; o += 1
        elif lb == 0x82: ln = (data[o]<<8)|data[o+1]; o += 2
        else: return
        val = data[o:o+ln]
        nm_map = {0x02:"INTEGER",0x03:"BIT STRING",0x18:"GenTime",0x1B:"GenString",0x30:"SEQUENCE"}
        if tc==0: nm = nm_map.get(tb, f"Univ({tn})")
        elif tc==1: nm = f"APPLICATION {tn}"
        elif tc==2: nm = f"[{tn}]"
        else: nm = f"PRIV {tn}"
        vp = ""
        if tc==0 and not con:
            if tb==0x02: vp = f" = {int.from_bytes(val, byteorder='big', signed=True) if val else 0}"
            elif tb==0x1B or tb==0x18: vp = " = " + val.decode()
            elif tb==0x03: vp = f" unused={val[0]} flags=0x{val[1:].hex()}"
        print(f"{pfx}@{to:3d} 0x{tb:02X} {nm:28s} len={ln:3d}{vp}")
        if con and ln > 0: annotate(val, indent+1)
        o += ln

def validate(data):
    print()
    print("[*] Validation:")
    assert data[0] == 0x6A; print("  [OK] APPLICATION 10 (0x6A)")
    o = 1
    if data[o]<0x80: ol=data[o]; o+=1
    elif data[o]==0x81: ol=data[o+1]; o+=2
    assert o+ol==len(data); print(f"  [OK] Length={ol} total={len(data)}")
    inn = data[o:]
    assert inn[0]==0xA1; print("  [OK] pvno [1]")
    pcl=inn[1]; pi=inn[2:2+pcl]
    pv=int.from_bytes(pi[2:2+pi[1]], byteorder="big"); assert pv==5; print(f"  [OK] pvno={pv}")
    p=2+pcl; assert inn[p]==0xA2; print("  [OK] msg-type [2]")
    mcl=inn[p+1]; mi=inn[p+2:p+2+mcl]
    mv=int.from_bytes(mi[2:2+mi[1]], byteorder="big"); assert mv==10; print(f"  [OK] msg-type={mv}")
    p+=2+mcl
    assert inn[p]==0xA4, f"Expected [4], got 0x{inn[p]:02X}"; print("  [OK] req-body [4] (NO [3] padata)")
    ro=p+1
    if inn[ro]<0x80: rl=inn[ro]; ro+=1
    elif inn[ro]==0x81: rl=inn[ro+1]; ro+=2
    rb=inn[ro:ro+rl]
    assert rb[0]==0x30; print("  [OK] req-body is SEQUENCE")
    so=1
    if rb[so]<0x80: so+=1
    elif rb[so]==0x81: so+=2
    bf=rb[so:]
    assert bf[0]==0xA0; print("  [OK] kdc-options [0]")
    ol2=bf[1]; oi=bf[2:2+ol2]
    assert oi[0]==0x03; assert oi[2]==0x00
    fv=int.from_bytes(oi[3:7], byteorder="big")
    assert fv==0x40810010; print(f"  [OK] kdc-options=0x{fv:08X}")
    print()
    print("  === ALL CHECKS PASSED ===")

def main():
    asreq, nonce = build_asreq("bob", "CHILD.HTB.LOCAL", nonce=0x12345678)
    hs = asreq.hex()
    print("AS-REQ hex (" + str(len(asreq)) + " bytes):")
    print(hs)
    print()
    print("Hex dump:")
    hexdump(asreq)
    print()
    print("ASN.1 structure:")
    print("=" * 70)
    annotate(asreq)
    print("=" * 70)
    validate(asreq)
    bp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asreq.bin")
    with open(bp, "wb") as f: f.write(asreq)
    print("Binary written to: " + bp)
    try:
        with open("/tmp/asreq.bin", "wb") as f: f.write(asreq)
        print("Also written to: /tmp/asreq.bin")
    except: pass

if __name__ == "__main__":
    main()
