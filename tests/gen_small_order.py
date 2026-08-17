#!/usr/bin/env python3
"""Regenerate the small-order public-key table in tests/test_vl_core.c.

For each of the 14 canonical small-order Ed25519 encodings, forges a signature
against it with NO private key: set S = 0 and search the ord(A) <= 8 multiples
of A for an R satisfying S*B - h*A == R, bumping a message counter until one
hits. Every one of these was accepted before unpackneg() started rejecting
low-order and non-canonically-encoded public keys.

Independent of core/ on purpose: pure-Python reference arithmetic, so it can
disagree with the C. Run it, paste the table, watch the test go red on the old
code and green on the new.
"""
import hashlib
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, q-2, q) % q
I = pow(2, (q-1)//4, q)
def inv(x): return pow(x, q-2, q)
def ed(P,Q):
    x1,y1=P; x2,y2=Q
    k = d*x1*x2*y1*y2 % q
    return ((x1*y2+x2*y1)*inv(1+k)%q, (y1*y2+x1*x2)*inv(1-k)%q)
def smul(P,e):
    R=(0,1)
    e%= (8*l)
    while e:
        if e&1: R=ed(R,P)
        P=ed(P,P); e>>=1
    return R
def enc(P):
    x,y=P
    return bytes(((y|((x&1)<<255))>>(8*i))&0xFF for i in range(32))
def decode_c(s):
    """Exactly what core/vl_ed25519.c unpack25519+unpackneg decode, returning +A."""
    y=(int.from_bytes(s,'little')&((1<<255)-1))%q
    xx=(y*y-1)*inv(d*y*y+1)%q
    x=pow(xx,(q+3)//8,q)
    if (x*x-xx)%q!=0: x=x*I%q
    if (x*x-xx)%q!=0: return None
    if (x&1)!=((s[31]>>7)&1): x=(q-x)%q
    return (x,y)
def order(P):
    for t in (1,2,4,8):
        if smul(P,t)==(0,1): return t
    return None

KEYS=["0000000000000000000000000000000000000000000000000000000000000000",
"0100000000000000000000000000000000000000000000000000000000000000",
"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
"0000000000000000000000000000000000000000000000000000000000000080",
"0100000000000000000000000000000000000000000000000000000000000080",
"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]

print("key  order  on-curve")
for k in KEYS:
    A=decode_c(bytes.fromhex(k))
    print(k[:16]+"...", None if A is None else order(A))

def forge(pkhex, base=b"VectiLicense small-order forgery"):
    pk=bytes.fromhex(pkhex); A=decode_c(pk); t=order(A)
    for n in range(0,4096):
        msg=base+bytes([n])
        for k in range(t):
            R=enc(smul(A,k))
            h=int.from_bytes(hashlib.sha512(R+pk+msg).digest(),'little')%l
            if enc(smul(A,(-h)%t))==R:
                return msg, R+bytes(32)
    return None

print()
for k in KEYS:
    r=forge(k)
    assert r, k
    msg,sig=r
    print('  { "%s",\n    "%s",\n    %d },' % (k, sig.hex(), msg[-1]))
