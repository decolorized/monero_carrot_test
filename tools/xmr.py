# minimal monero crypto primitives, pure python
RC=[0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M=(1<<64)-1
def rol(x,n): return ((x<<n)|(x>>(64-n)))&M
def keccak_f(A):
    for rnd in range(24):
        C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(5): A[x][y]^=D[x]
        B=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2*x+3*y)%5]=rol(A[x][y],ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y]=B[x][y]^((~B[(x+1)%5][y])&M&B[(x+2)%5][y])
        A[0][0]^=RC[rnd]
    return A
def keccak256(data):
    rate=136
    P=bytearray(data)
    P.append(0x01)
    while len(P)%rate!=0: P.append(0)
    P[-1]^=0x80
    A=[[0]*5 for _ in range(5)]
    for blk in range(0,len(P),rate):
        b=P[blk:blk+rate]
        for i in range(rate//8):
            x=i%5; y=i//5
            A[x][y]^=int.from_bytes(b[i*8:i*8+8],'little')
        keccak_f(A)
    out=b''
    for i in range(4):
        x=i%5;y=i//5
        out+=A[x][y].to_bytes(8,'little')
    return out
cn=keccak256

Q=2**255-19
L=2**252+27742317777372353535851937790883648493
d=(-121665*pow(121666,Q-2,Q))%Q
I=pow(2,(Q-1)//4,Q)
def inv(x): return pow(x,Q-2,Q)
def xrecover(y):
    xx=(y*y-1)*inv(d*y*y+1)
    x=pow(xx,(Q+3)//8,Q)
    if (x*x-xx)%Q!=0: x=(x*I)%Q
    if x%2!=0: x=Q-x
    return x
By=4*inv(5); Bx=xrecover(By)
# extended coords (X,Y,Z,T)
def pt_ext(P):
    x,y=P; return (x%Q,y%Q,1,(x*y)%Q)
B=pt_ext((Bx,By))
ZERO=(0,1,1,0)
def add(P,Q_):
    X1,Y1,Z1,T1=P; X2,Y2,Z2,T2=Q_
    A=((Y1-X1)*(Y2-X2))%Q
    Bb=((Y1+X1)*(Y2+X2))%Q
    C=(T1*2*d*T2)%Q
    D=(Z1*2*Z2)%Q
    E=Bb-A; F=D-C; G=D+C; H=Bb+A
    return ((E*F)%Q,(G*H)%Q,(F*G)%Q,(E*H)%Q)
def dbl(P):
    return add(P,P)
def smul(P,e):
    e%= (L*8)
    R=ZERO
    Pp=P
    while e:
        if e&1: R=add(R,Pp)
        Pp=dbl(Pp); e>>=1
    return R
def encode(P):
    X,Y,Z,T=P
    zi=inv(Z); x=(X*zi)%Q; y=(Y*zi)%Q
    return ((y)|((x&1)<<255)).to_bytes(32,'little')
def decode(s):
    n=int.from_bytes(s,'little')
    sign=n>>255; y=n&((1<<255)-1)
    if y>=Q: return None
    x=xrecover(y)
    if x&1!=sign: x=Q-x
    P=(x,y,1,(x*y)%Q)
    # check on curve
    X,Y,Z,T=P
    if (-X*X+Y*Y-1-d*X*X*Y*Y)%Q!=0: return None
    return P
def sc_reduce32(b): return (int.from_bytes(b,'little')%L).to_bytes(32,'little')
def hs(data): return sc_reduce32(cn(data))
def sc(x): return (x%L).to_bytes(32,'little')
def si(b): return int.from_bytes(b,'little')


A_=486662
fe_ma=(-A_)%Q
fe_ma2=(-A_*A_)%Q
sqrtm1=I
def _sqrt(a):
    a%=Q
    x=pow(a,(Q+3)//8,Q)
    if (x*x-a)%Q!=0: x=(x*I)%Q
    assert (x*x-a)%Q==0, "not a square"
    return x
FFFB1=57192811444617977854858898469001663971726463542204390960804972474891788632558
FFFB2=34838897745748397871374137087405348832069628406613012804793447631241588021984
FFFB3=46719087769223307720043111813545796356806574765024592941723029582131464514662
FFFB4=11880190023474909848668974726140447524736946358411580136929581950889876492678
def divpowm1(u,v):
    v3=pow(v,3,Q); uv3=(u*v3)%Q
    uv7=(uv3*pow(v,4,Q))%Q
    return (uv3*pow(uv7,(Q-5)//8,Q))%Q
def ge_fromfe(s32):
    u=int.from_bytes(s32,'little')%Q
    v=(2*u*u)%Q
    w=(v+1)%Q
    x=(w*w)%Q
    y=(fe_ma2*v)%Q
    x=(x+y)%Q
    rX=divpowm1(w,x)
    y=(rX*rX)%Q
    x=(y*x)%Q
    y=(w-x)%Q
    z=fe_ma
    sign=0
    if y%Q!=0:
        y=(w+x)%Q
        if y%Q!=0:
            # negative branch
            x=(x*sqrtm1)%Q
            y=(w-x)%Q
            if y%Q!=0:
                rX=(rX*FFFB3)%Q
            else:
                rX=(rX*FFFB4)%Q
            z=fe_ma
            sign=1
        else:
            rX=(rX*FFFB1)%Q
            rX=(rX*u)%Q
            z=(z*v)%Q
            sign=0
    else:
        rX=(rX*FFFB2)%Q
        rX=(rX*u)%Q
        z=(z*v)%Q
        sign=0
    if (rX%2)!=sign:
        rX=(-rX)%Q
    rZ=(z+w)%Q
    rY=(z-w)%Q
    rX=(rX*rZ)%Q
    zi=inv(rZ)
    xx=(rX*zi)%Q; yy=(rY*zi)%Q
    return (xx,yy,1,(xx*yy)%Q)
def hash_to_point(data):
    h=cn(data)
    P=ge_fromfe(h)
    return smul(P,8)
H_BYTES=None
def init_H():
    global H_BYTES
    H_BYTES=encode(hash_to_point(encode(B)))
init_H()
