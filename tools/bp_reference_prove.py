"""bp_reference_prove.py — эталонный prover Bulletproofs+ на Python.

Нужен, чтобы сверять bp_plus.c пошагово: при одинаковой случайности
(alpha, dL/dR, r, s, d, eta) прошивка обязана выдавать те же A, L, R,
challenges, A1, B, r1, s1, d1. Первое расхождение и есть место бага.
"""
from xmr import *
from bulletproof_plus import BP, INV8, HB, varint, Hpt, inv


def prove(amounts, gammas, rnd, bp=None):
    if bp is None: bp = BP()
    """rnd: dict с alpha, dL[i], dR[i], r,s,d_,eta (int). Возвращает proof + промежуточные."""
    N=64
    nV=len(amounts)
    M=1; logM=0
    while M<nV: M*=2; logM+=1
    MN=M*N; rounds=logM+logN if False else logM+6
    dbg={}
    V=[encode(smul(add(smul(B,gammas[j]),smul(Hpt,amounts[j])),INV8)) for j in range(nV)]
    dbg['V']=V
    aL=[0]*MN; aR=[0]*MN
    for j in range(M):
        v=amounts[j] if j<nV else 0
        for i in range(N):
            bit=(v>>i)&1
            aL[j*N+i]=bit
            aR[j*N+i]=(bit-1)%L
    alpha=rnd['alpha']
    acc=ZERO
    for i in range(MN):
        if aL[i]: acc=add(acc,smul(bp.Gi(i),aL[i]))
        if aR[i]: acc=add(acc,smul(bp.Hi(i),aR[i]))
    acc=add(acc,smul(B,alpha))
    A=encode(smul(acc,INV8))
    dbg['A']=A
    t=bp.it
    t=hs(t+hs(b''.join(V)))
    y=hs(t+A); t=y
    z=hs(y); t=z
    Y=si(y); Z=si(z); z2=Z*Z%L
    dbg['y']=y; dbg['z']=z
    ypow=[1]*(MN+2)
    for i in range(1,MN+2): ypow[i]=ypow[i-1]*Y%L
    d=[0]*MN
    for j in range(M):
        for i in range(N):
            d[j*N+i]=pow(z2,j+1,L)*pow(2,i,L)%L
    aL1=[(aL[i]-Z)%L for i in range(MN)]
    aR1=[(aR[i]+Z+d[i]*ypow[MN-i])%L for i in range(MN)]
    alpha1=alpha
    tmp=1
    for j in range(nV):
        tmp=tmp*z2%L
        alpha1=(alpha1+ypow[MN+1]*tmp%L*gammas[j])%L
    yinv=inv(Y)
    yinvpow=[1]*(MN+1)
    for i in range(1,MN+1): yinvpow[i]=yinvpow[i-1]*yinv%L
    Gp=[bp.Gi(i) for i in range(MN)]
    Hp=[bp.Hi(i) for i in range(MN)]
    ap=list(aL1); bp_=list(aR1)
    Ls=[];Rs=[];chs=[]
    nprime=MN; rnd_i=0
    def wip(a,b,yv):
        # sum a_i*b_i*y^{i+1}
        r=0
        for i in range(len(a)): r=(r+a[i]*b[i]%L*pow(yv,i+1,L))%L
        return r
    while nprime>1:
        nprime//=2
        cL=wip(ap[:nprime],bp_[nprime:2*nprime],Y)
        a_sc=[ap[nprime+k]*ypow[nprime]%L for k in range(nprime)]
        cR=wip(a_sc,bp_[:nprime],Y)
        dL=rnd['dL'][rnd_i]; dR=rnd['dR'][rnd_i]
        dbg.setdefault('cL',[]).append(cL); dbg.setdefault('cR',[]).append(cR)
        # L = ( sum_{i<n} Gp[n+i]^{ap[i]*yinv^n} + sum_{i<n} Hp[i]^{bp[n+i]} + cL*H + dL*G )*inv8
        acc=ZERO
        for k in range(nprime):
            acc=add(acc,smul(Gp[nprime+k],ap[k]*yinvpow[nprime]%L))
            acc=add(acc,smul(Hp[k],bp_[nprime+k]))
        acc=add(acc,smul(Hpt,cL)); acc=add(acc,smul(B,dL))
        Lr=encode(smul(acc,INV8))
        acc=ZERO
        for k in range(nprime):
            acc=add(acc,smul(Gp[k],ap[nprime+k]*ypow[nprime]%L))
            acc=add(acc,smul(Hp[nprime+k],bp_[k]))
        acc=add(acc,smul(Hpt,cR)); acc=add(acc,smul(B,dR))
        Rr=encode(smul(acc,INV8))
        Ls.append(Lr); Rs.append(Rr)
        e=hs(t+Lr+Rr); t=e; chs.append(e)
        E=si(e); Ei=inv(E)
        nG=[];nH=[]
        for k in range(nprime):
            nG.append(add(smul(Gp[k],Ei),smul(Gp[nprime+k],yinvpow[nprime]*E%L)))
            nH.append(add(smul(Hp[k],E),smul(Hp[nprime+k],Ei)))
        Gp=nG;Hp=nH
        na=[];nb=[]
        for k in range(nprime):
            na.append((E*ap[k]+Ei*ypow[nprime]%L*ap[nprime+k])%L)
            nb.append((Ei*bp_[k]+E*bp_[nprime+k])%L)
        ap=na;bp_=nb
        alpha1=(alpha1+dL*E%L*E+dR*Ei%L*Ei)%L
        rnd_i+=1
    dbg['L']=Ls; dbg['R']=Rs; dbg['ch']=chs
    dbg['aprime0']=ap[0]; dbg['bprime0']=bp_[0]; dbg['alpha1']=alpha1
    dbg['Gprime0']=encode(Gp[0]); dbg['Hprime0']=encode(Hp[0])
    r_=rnd['r']; s_=rnd['s']; d_=rnd['d_']; eta=rnd['eta']
    acc=add(smul(Gp[0],r_),smul(Hp[0],s_))
    acc=add(acc,smul(Hpt,(r_*Y%L*bp_[0]+s_*Y%L*ap[0])%L))
    acc=add(acc,smul(B,d_))
    A1=encode(smul(acc,INV8))
    acc=add(smul(Hpt,r_*Y%L*s_%L),smul(B,eta))
    Bk=encode(smul(acc,INV8))
    e=hs(t+A1+Bk); E=si(e)
    r1=(r_+ap[0]*E)%L; s1=(s_+bp_[0]*E)%L
    d1=(eta+d_*E+alpha1*E%L*E)%L
    proof={'A':A,'A1':A1,'B':Bk,'r1':sc(r1),'s1':sc(s1),'d1':sc(d1),'L':Ls,'R':Rs}
    dbg['A1']=A1; dbg['B']=Bk; dbg['e']=e
    return proof,dbg,V
