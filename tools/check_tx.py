#!/usr/bin/env python3
"""check_tx.py — полная проверка подписанной транзакции без обращения к демону.

    python3 check_tx.py out.bin [out.bin.uts]

Что проверяется:
  1. транзакция разбирается целиком, без хвоста;
  2. баланс:  sum(outPk.mask) + fee*H == pseudoOut;
  3. key_offsets в vin соответствуют кольцу из unsigned_tx_set;
  4. key images в vin строго убывают (консенсусное правило с HF7);
  5. CLSAG-подпись (message = keccak(prefix_hash || H(rctSigBase) || H(bulletproofs)));
  6. Bulletproofs+ range proof;
  7. выходы, адресованные этому кошельку, находятся своим view-ключом,
     сумма расшифровывается, коммитмент сходится.

Последняя проверка читает ключи из ../secrets.h.
"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xmr import *
from monero_tx import parse_tx2, parse_uts_rings, clsag_verify, bp_hash, H_POINT, varint
from bulletproof_plus import BP, verify as bp_verify


def wallet_keys():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'secrets.h')
    s = open(p).read()
    spend = re.search(r'SPEND_SECRET_KEY_HEX\s+"([0-9a-fA-F]{64})"', s)
    view  = re.search(r'VIEW_SECRET_KEY_HEX\s+"([0-9a-fA-F]{64})"', s)
    if not (spend and view): return None, None
    return bytes.fromhex(spend.group(1)), bytes.fromhex(view.group(1))


def scan_output(t, i, deriv, spend_pub):
    """Смотрим на выход i глазами получателя с данной derivation."""
    s = hs(deriv + varint(i))
    P = encode(add(smul(B, si(s)), decode(spend_pub)))
    if P != t['vout'][i]['key']:
        return None
    vt = cn(b'view_tag' + deriv + varint(i))[0]
    amount = int.from_bytes(
        bytes(x ^ y for x, y in zip(t['ecdh'][i], cn(b'amount' + s)[:8])), 'little')
    mask = hs(b'commitment_mask' + s)
    commit_ok = encode(add(smul(B, si(mask)), smul(H_POINT, amount))) == t['outPk'][i]
    return dict(index=i, amount=amount,
                view_tag_ok=(vt == t['vout'][i]['view_tag']), commitment_ok=commit_ok)


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    path = sys.argv[1]
    uts_path = sys.argv[2] if len(sys.argv) > 2 else path + '.uts'
    blob = open(path, 'rb').read()
    t = parse_tx2(blob, 0, False)
    res = {}

    res['разбор транзакции'] = (t['end'] == len(blob))

    # Консенсус с HF7: key images во входах должны строго убывать.
    kis = [v['ki'] for v in t['vin']]
    res['порядок key images'] = all(kis[i] > kis[i+1] for i in range(len(kis) - 1))

    S = ZERO
    for o in t['outPk']:
        S = add(S, decode(o))
    P = ZERO
    for o in t['pseudoOuts']:
        P = add(P, decode(o))
    res['баланс'] = encode(add(S, smul(H_POINT, t['fee']))) == encode(P)

    ring = None
    if os.path.exists(uts_path):
        uts_rings = parse_uts_rings(open(uts_path, 'rb').read())
        rings = []
        ok = len(uts_rings) == len(t['vin'])
        for j in range(len(t['vin'])):
            offs = t['vin'][j]['offsets']
            absolute = [offs[0]]
            for d in offs[1:]:
                absolute.append(absolute[-1] + d)
            match = None
            for cand in uts_rings:
                if [x[0] for x in cand] == absolute:
                    match = cand; break
            if match is None:
                ok = False
            rings.append(match)
        res['key_offsets'] = ok
        msg = cn(cn(t['prefix']) + cn(t['base']) + bp_hash(t['bpp']))
        ok = True
        for j in range(len(t['vin'])):
            rj = rings[j] if j < len(rings) else None
            if rj is None:
                ok = False; break
            good, _ = clsag_verify(msg, [x[1] for x in rj], [x[2] for x in rj],
                                   t['pseudoOuts'][j], t['vin'][j]['ki'], t['clsag'][j])
            if not good:
                ok = False; break
        res['CLSAG'] = ok
    else:
        print('нет %s — CLSAG и key_offsets пропущены '
              '(кольцо есть только в unsigned_tx_set)\n' % uts_path)

    res['Bulletproofs+'] = bp_verify(t['bpp'][0], t['outPk'], BP())

    spend_sk, view_sk = wallet_keys()
    mine = []
    if view_sk:
        spend_pub = encode(smul(B, si(spend_sk)))
        keys = [t['extra'][1:33]] if t['extra'][:1] == b'\x01' else []
        # доп. публичные ключи (tag 0x04), если есть
        p = 33
        while p < len(t['extra']):
            tag = t['extra'][p]
            if tag == 0x02:
                p += 2 + t['extra'][p+1]
            elif tag == 0x04:
                n = t['extra'][p+1]
                keys += [t['extra'][p+2+32*k:p+2+32*(k+1)] for k in range(n)]
                p += 2 + 32*n
            else:
                break
        for i in range(len(t['vout'])):
            for R_ in keys:
                d = encode(smul(smul(decode(R_), si(view_sk)), 8))
                r = scan_output(t, i, d, spend_pub)
                if r:
                    mine.append(r); break
        if mine:
            res['свои выходы находятся'] = all(
                m['view_tag_ok'] and m['commitment_ok'] for m in mine)

    print('%s  (%d байт)' % (path, len(blob)))
    print('  версия=%d  входов=%d  выходов=%d  rct.type=%d  комиссия=%d'
          % (t['version'], len(t['vin']), len(t['vout']), t['rct_type'], t['fee']))
    print()
    width = max(len(k) for k in res)
    for k, v in res.items():
        print('  [%s] %s' % ('OK  ' if v else 'FAIL', k.ljust(width)))
    if not mine:
        print('  [ --  ] своих выходов нет — этому кошельку в транзакции ничего не')
        print('          адресовано (в обычном переводе так быть не должно: сдача)')
    for m in mine:
        print('       выход[%d]: %d пиконеро, view_tag %s, коммитмент %s'
              % (m['index'], m['amount'],
                 'ok' if m['view_tag_ok'] else 'FAIL',
                 'ok' if m['commitment_ok'] else 'FAIL'))
    failed = [k for k, v in res.items() if not v]
    print()
    print('ИТОГ: ' + ('всё сходится' if not failed else 'НЕ ПРОШЛО: ' + ', '.join(failed)))
    return 0 if not failed else 1


if __name__ == '__main__':
    sys.exit(main())
