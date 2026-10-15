"""monero_tx.py — разбор Monero-транзакции и проверка CLSAG.

Верификация сверена с настоящей транзакцией из Monero GUI.
"""
from xmr import *


class R:
    """Побайтовый ридер: varint / u8 / фиксированные поля."""
    def __init__(s, b, p=0): s.b = b; s.p = p
    def u8(s):
        v = s.b[s.p]; s.p += 1; return v
    def var(s):
        r = 0; sh = 0
        while True:
            c = s.b[s.p]; s.p += 1
            r |= (c & 0x7f) << sh; sh += 7
            if not c & 0x80: return r
    def k(s, n=32):
        v = s.b[s.p:s.p+n]; s.p += n; return v


def neg(P):
    X, Y, Z, T = P
    return ((-X) % Q, Y, Z, (-T) % Q)


def parse_tx2(b,start=0,pseudo_first=False):
    r=R(b,start); tx={}
    tx['version']=r.var(); tx['unlock']=r.var()
    n=r.var(); tx['vin']=[]
    for i in range(n):
        t=r.u8(); amt=r.var(); no=r.var()
        offs=[r.var() for _ in range(no)]; ki=r.k()
        tx['vin'].append(dict(amount=amt,offsets=offs,ki=ki))
    n=r.var(); tx['vout']=[]
    for i in range(n):
        amt=r.var(); t=r.u8(); key=r.k(); vt=r.u8() if t==3 else None
        tx['vout'].append(dict(amount=amt,tag=t,key=key,view_tag=vt))
    el=r.var(); tx['extra']=r.k(el)
    tx['prefix']=b[start:r.p]
    bs=r.p
    tx['rct_type']=r.u8(); tx['fee']=r.var()
    nout=len(tx['vout']); nin=len(tx['vin'])
    tx['ecdh']=[r.k(8) for _ in range(nout)]
    tx['outPk']=[r.k() for _ in range(nout)]
    tx['base']=b[bs:r.p]
    nbp=r.var(); bps=[]
    for _ in range(nbp):
        d={}
        for f in ['A','A1','B','r1','s1','d1']: d[f]=r.k()
        nl=r.var(); d['L']=[r.k() for _ in range(nl)]
        nr=r.var(); d['R']=[r.k() for _ in range(nr)]
        bps.append(d)
    tx['bpp']=bps
    if pseudo_first:
        tx['pseudoOuts']=[r.k() for _ in range(nin)]
    cl=[]
    for j in range(nin):
        nr=len(tx['vin'][j]['offsets'])
        cl.append({'s':[r.k() for _ in range(nr)],'c1':r.k(),'D':r.k()})
    tx['clsag']=cl
    if not pseudo_first:
        tx['pseudoOuts']=[r.k() for _ in range(nin)]
    tx['end']=r.p
    return tx

def bp_hash(bpp):
    kv=b''
    for p in bpp:
        for f in ['A','A1','B','r1','s1','d1']: kv+=p[f]
        for x in p['L']: kv+=x
        for x in p['R']: kv+=x
    return cn(kv)

def clsag_verify(msg,P,Cnz,Coffset,I,sig):
    n=len(P)
    dom=b'CLSAG_agg_0'+b'\0'*(32-11)
    dom1=b'CLSAG_agg_1'+b'\0'*(32-11)
    body=b''.join(P)+b''.join(Cnz)+I+sig['D']+Coffset
    muP=hs(dom+body); muC=hs(dom1+body)
    rnd=b'CLSAG_round'+b'\0'*(32-11)
    pre=rnd+b''.join(P)+b''.join(Cnz)+Coffset+msg
    Ip=decode(I); Dp=smul(decode(sig['D']),8)
    Coff=decode(Coffset)
    c=sig['c1']
    for i in range(n):
        cp=sc(si(c)*si(muP)); cc=sc(si(c)*si(muC))
        Ci=add(decode(Cnz[i]),neg(Coff))
        L=add(add(smul(B,si(sig['s'][i])),smul(decode(P[i]),si(cp))),smul(Ci,si(cc)))
        Rr=add(add(smul(hash_to_point(P[i]),si(sig['s'][i])),smul(Ip,si(cp))),smul(Dp,si(cc)))
        c=hs(pre+encode(L)+encode(Rr))
    return c==sig['c1'],c


def parse_uts_rings(plain):
    """Кольца всех входов из расшифрованного unsigned_tx_set.

    Возвращает список: для каждого источника — список (global_index, P, C).
    """
    n_src = plain[2]
    r = R(plain, 3)
    rings = []
    for s in range(n_src):
        n = r.var(); ring = []
        for i in range(n):
            mk = r.u8()
            assert mk == 2, 'ожидался маркер пары 0x02, получен 0x%02x' % mk
            idx = r.var(); ring.append((idx, r.k(), r.k()))
        rings.append(ring)
        r.p += 8 + 32                      # real_output, real_out_tx_key
        n_add = r.var()
        r.p += n_add * 32                  # additional_tx_keys
        r.p += 8 + 8 + 1 + 32 + 128        # idx_in_tx, amount, rct, mask, multisig
    return rings


H_POINT = decode(bytes.fromhex(
    '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94'))


def varint(v):
    o = bytearray()
    while v >= 0x80:
        o.append((v & 0x7f) | 0x80); v >>= 7
    o.append(v)
    return bytes(o)
