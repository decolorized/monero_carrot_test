import sys
def varint(b,p):
    v=0;s=0
    while True:
        c=b[p];p+=1;v|=(c&0x7f)<<s;s+=7
        if c<0x80:return v,p
def parse(b):
    p=0; ver,p=varint(b,p); assert ver==1
    ntx,p=varint(b,p)
    for _ in range(ntx):
        p+=32; n,p=varint(b,p); p+=32*n
        nn,p=varint(b,p)
        for _ in range(nn):
            fl=b[p]; p+=1+64+(8 if fl&2 else 0); _,p=varint(b,p)
        ns,p=varint(b,p)
        for _ in range(ns):
            for _ in range(4): _,p=varint(b,p)
        _,p=varint(b,p); _,p=varint(b,p); el,p=varint(b,p); p+=el
    props_end=p
    n,p=varint(b,p); si=[]
    for _ in range(n):
        assert b[p]==2; ki=b[p+1:p+33]; assert b[p+33]==2; ota=b[p+34:p+66]; p+=66
        l,p=varint(b,p); p+=l; si.append((ki.hex()[:16],ota.hex()[:16]))
    n,p=varint(b,p); oth=[]
    for _ in range(n):
        assert b[p]==2; ota=b[p+1:p+33]; assert b[p+33]==2; ki=b[p+34:p+66]; p+=66; tag=b[p]; p+=1
        if tag==0x23: p+=64
        else: l,p=varint(b,p); p+=l
        oth.append((ota.hex()[:16],ki.hex()[:16],hex(tag)))
    assert p==len(b)
    return props_end,si,sorted(oth)
for f in sys.argv[1:]:
    print(f, parse(open(f,'rb').read()))
