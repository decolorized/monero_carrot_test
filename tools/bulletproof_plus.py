"""bulletproof_plus.py — верификатор Bulletproofs+ (порт rct::bulletproof_plus_VERIFY).

Откалиброван на настоящей транзакции Monero GUI: на ней verify() возвращает True.
"""
from xmr import *

INV8=si(bytes.fromhex("792fdce229e50661d0da1c7db39dd30700000000000000000000000000000006"))
HB=bytes.fromhex("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
Hpt = decode(HB)

def inv(x):
    return pow(x, L - 2, L)
def varint(v):
    o=bytearray()
    while v>=0x80: o.append((v&0x7f)|0x80); v>>=7
    o.append(v); return bytes(o)
def hp3(k):  # monero hash_to_p3(key)
    return hash_to_point(k)
def get_exponent(base, idx):
    # Monero: hash_to_p3(cn_fast_hash(base || "bulletproof_plus" || varint(idx)))
    # то есть keccak ДВАЖДЫ, потом ge_fromfe, потом *8.
    return hp3(cn(base + b"bulletproof_plus" + varint(idx)))
class BP:
    """Генераторы Gi/Hi и начальный transcript (кэшируются)."""
    def __init__(self):
        self.gi = {}; self.hi = {}
        self.it = encode(hp3(cn(b"bulletproof_plus_transcript")))
    def Gi(self, i):
        if i not in self.gi: self.gi[i] = get_exponent(HB, 2*i + 1)
        return self.gi[i]
    def Hi(self, i):
        if i not in self.hi: self.hi[i] = get_exponent(HB, 2*i)
        return self.hi[i]
def tu(t,*u): return hs(t+b''.join(u))
def m8(b): return smul(decode(b),8)
def verify(proof, outpk, bp=None, verbose=False):
    if bp is None: bp = BP()
    logN=6;N=64
    nV=len(outpk)
    M=1
    logM=0
    while M<nV: M*=2; logM+=1
    MN=M*N; rounds=logM+logN
    if len(proof['L'])!=rounds: return ('rounds mismatch',len(proof['L']),rounds)
    # V (stored form) = outPk*inv8 ; proof8_V = outPk
    V=[encode(smul(decode(o),INV8)) for o in outpk]
    t = tu(bp.it, hs(b''.join(V)))
    y = tu(t, proof['A'])
    z = hs(y)          # Monero: z = hash_to_scalar(y), а не Hs(transcript||y)
    t = z
    ch=[]
    for j in range(rounds):
        c=tu(t,proof['L'][j],proof['R'][j]); t=c; ch.append(c)
    e=tu(t,proof['A1'],proof['B'])
    Y=si(y); Z=si(z); E=si(e)
    yinv=pow(Y,L-2,L)
    y_MN=pow(Y,MN,L); y_MN_1=pow(Y,MN+1,L)
    z2=Z*Z%L; e2=E*E%L
    chi=[pow(si(c),L-2,L) for c in ch]
    cache=[0]*(1<<rounds)
    cache[0]=chi[0]; cache[1]=si(ch[0])
    for j in range(1,rounds):
        slots=1<<(j+1)
        for s in range(slots-1,0,-2):
            cache[s]=cache[s//2]*si(ch[j])%L
            cache[s-1]=cache[s//2]*chi[j]%L
    def dval(i):
        j=i//N;k=i%N
        return pow(z2,j+1,L)*pow(2,k,L)%L
    Gs=[0]*MN; Hs=[0]*MN
    e_r1_w_y=E*si(proof['r1'])%L
    e_s1_w=E*si(proof['s1'])%L
    e2z=e2*Z%L; me2z=(-e2z)%L
    me2wy=(-e2)%L*y_MN%L
    for i in range(MN):
        g=(e_r1_w_y*cache[i]+e2z)%L
        h=(e_s1_w*cache[(~i)&(MN-1)]+me2z)%L
        Gs[i]=g
        Hs[i]=(me2wy*dval(i)+h)%L
        e_r1_w_y=e_r1_w_y*yinv%L
        me2wy=me2wy*yinv%L
    sum_y=0;yp=Y
    for i in range(MN): sum_y=(sum_y+yp)%L; yp=yp*Y%L
    sum_d=0
    for i in range(MN): sum_d=(sum_d+dval(i))%L
    Gsc=si(proof['d1'])
    Hsc=(si(proof['r1'])*Y%L*si(proof['s1'])+e2*((y_MN_1*Z%L*sum_d + (z2-Z)%L*sum_y)%L))%L
    R=ZERO
    temp=(-e2)%L
    for j in range(nV):
        temp=temp*z2%L
        R=add(R,smul(decode(outpk[j]),temp*y_MN_1%L))
    R=add(R,smul(m8(proof['B']),(-1)%L))
    R=add(R,smul(m8(proof['A1']),(-E)%L))
    R=add(R,smul(m8(proof['A']),(-e2)%L))
    R=add(R,smul(B,Gsc))
    R=add(R,smul(decode(HB),Hsc))
    for i in range(MN):
        if Gs[i]: R=add(R,smul(bp.Gi(i),Gs[i]))
        if Hs[i]: R=add(R,smul(bp.Hi(i),Hs[i]))
    for j in range(rounds):
        R=add(R,smul(m8(proof['L'][j]),(-e2)*si(ch[j])%L*si(ch[j])%L))
        R=add(R,smul(m8(proof['R'][j]),(-e2)*chi[j]%L*chi[j]%L))
    return encode(R)==encode(ZERO)
