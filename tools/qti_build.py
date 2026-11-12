#!/usr/bin/env python3
"""Dựng và khóa trang Quang Tri Weekly Index (bao-cao-tuan.html) từ bảng điều khiển trên Claude.

Không chứa số điện thoại hay khóa nào. Mọi khóa được dẫn xuất từ một khóa chủ M; M nằm trong phần
được mở bằng số điện thoại của chủ trang, danh sách người được xem nằm trong trang, mã hóa bằng M.

Cập nhật số liệu hằng tuần (giữ nguyên danh sách người xem, không cần số điện thoại của ai khác):
  python3 qti_build.py build --page bao-cao-tuan.html --index index.html --data DIR --owner SĐT_CHỦ --out bao-cao-tuan.html
Đổi danh sách người xem (khóa lại toàn bộ):
  python3 qti_build.py build ... --roster roster.json      (roster: [{ten, sdt, btv|null}], chủ trang có trong danh sách)
Kiểm tra: python3 qti_build.py check --page bao-cao-tuan.html --phone SĐT  (in tên, phạm vi, số dòng dữ liệu)
DIR chứa <tên bộ dữ liệu>.json (danh sách dòng) cho mọi bộ dữ liệu của bảng điều khiển.
"""
import argparse, base64, gzip, hashlib, hmac, json, os, re, sys, unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RIENG = ['xa', 'kt', 'da', 'tc', 'ndt', 'dat', 'tg', 'ls']   # số liệu theo địa bàn, lọc theo Ủy viên BTV
IT = 250000
b64 = lambda b: base64.b64encode(b).decode()
ub = base64.b64decode
nfc = lambda s: unicodedata.normalize('NFC', str(s or '')).strip()

def chuan(p):
    d = re.sub(r'\D', '', str(p))
    if d.startswith('84'): d = '0' + d[2:]
    if len(d) == 9: d = '0' + d
    return d

def kdf(phone, salt):
    return hashlib.pbkdf2_hmac('sha256', chuan(phone).encode(), bytes.fromhex(salt), IT, 64)

def sub(m, label): return hmac.new(m, label.encode(), hashlib.sha256).digest()
def ma(key, data: bytes): iv = os.urandom(12); return {'i': b64(iv), 'c': b64(AESGCM(key).encrypt(iv, data, None))}
def giai(key, g): return AESGCM(key).decrypt(ub(g['i']), ub(g['c']), None)
def ma_gz(key, text): return ma(key, gzip.compress(text.encode('utf-8'), 9, mtime=0))
def giai_gz(key, g): return gzip.decompress(giai(key, g)).decode('utf-8')
def nhan(b, salt): return 'all' if not b else hashlib.sha256((b + salt).encode()).hexdigest()[:12]

def doc_trang(path):
    t = open(path, encoding='utf-8').read()
    m = re.search(r"const SALT = '(\w+)', IT = (\d+), W = ", t)
    dec = json.JSONDecoder()
    W, e1 = dec.raw_decode(t, m.end())
    gpos = t.index('G = ', e1) + 4
    G, e2 = dec.raw_decode(t, gpos)
    tpl = t[:m.start()] + '__KHOA__' + t[e2:]
    return tpl, m.group(1), int(m.group(2)), W, G

def mo_khoa(W, salt, phone):
    d = kdf(phone, salt)
    w = next((x for x in W if x['t'] == d[32:40].hex()), None)
    if not w: sys.exit('Số điện thoại không có quyền.')
    return json.loads(giai(d[:32], w).decode())

def xa_cua(btv_names, index_html):
    i = index_html.index('QX_BTV=[')
    out = {}
    for m in re.finditer(r"\{ten:'([^']+)',chuc_vu:'[^']*',xa:\[([^\]]*)\]\}", index_html[i:i + 20000]):
        out[m.group(1)] = set(re.findall(r"'([^']+)'", m.group(2)))
    miss = [b for b in btv_names if b not in out]
    if miss: sys.exit('Không thấy địa bàn của: ' + ', '.join(miss))
    return out

def loc(rows, ds, xs):
    ten = [x.split(' ', 1)[1] if ' ' in x else x for x in xs]
    def giu(r):
        if 'xa' in r:
            v = r['xa']
            if v in (None, ''): return True
            v = v if isinstance(v, list) else [v]
            return not v or any(nfc(x) in xs for x in v)
        if ds in ('dat', 'tg'):
            s = nfc(r.get('dia_diem', '')) + ' ' + nfc(r.get('ten', ''))
            return any(t in s for t in ten)
        return True
    return [r for r in rows if giu(r)]

def dung_shell(shell_cu, index_html, chung):
    s = shell_cu
    a = s.index('const RAW = Object.assign(') + len('const RAW = Object.assign(')
    _, e = json.JSONDecoder().raw_decode(s, a)
    s = s[:a] + json.dumps(chung, ensure_ascii=False) + s[e:]
    b0 = s.index('<body><div id="dash-root">\n') + len('<body><div id="dash-root">\n')
    b1 = s.rindex('\n</div>\n<style>')
    body = index_html.replace('<meta name="dash-one-writer">\n', '', 1).rstrip('\n') + '\n'
    return s[:b0] + body + s[b1:]

def build(a):
    tpl, salt, it, W, G = doc_trang(a.page)
    assert it == IT
    v = mo_khoa(W, salt, a.owner)
    index_html = open(a.index, encoding='utf-8').read()
    data = {f[:-5]: json.load(open(os.path.join(a.data, f), encoding='utf-8')) for f in os.listdir(a.data) if f.endswith('.json')}
    if 'm' in v:
        m = ub(v['m']); shell_cu = giai_gz(sub(m, 'shell'), G['s'])
        roster = json.loads(giai_gz(sub(m, 'ds'), G['ds']))
    else:   # trang cũ chưa có khóa chủ
        if not a.roster: sys.exit('Trang chưa có khóa chủ, cần --roster để khóa lại lần đầu.')
        m = None; shell_cu = giai_gz(ub(v['k']), G['s']); roster = None
    if a.roster:
        roster = json.load(open(a.roster, encoding='utf-8'))
        if not any(chuan(r['sdt']) == chuan(a.owner) for r in roster): sys.exit('Chủ trang phải có trong danh sách.')
        m = os.urandom(32); salt = os.urandom(16).hex(); W = None
    chung = {k: v_ for k, v_ in data.items() if k not in RIENG}
    rieng = {k: data.get(k, []) for k in RIENG}
    btvs = sorted({r['btv'] for r in roster if r.get('btv')})
    dia = xa_cua(btvs, index_html)
    G2 = {'s': ma_gz(sub(m, 'shell'), dung_shell(shell_cu, index_html, chung)),
          'ds': ma_gz(sub(m, 'ds'), json.dumps(roster, ensure_ascii=False)),
          'all': ma_gz(sub(m, 'all'), json.dumps(rieng, ensure_ascii=False))}
    for b in btvs:
        G2[nhan(b, salt)] = ma_gz(sub(m, 'btv:' + b), json.dumps({k: loc(r, k, dia[b]) for k, r in rieng.items()}, ensure_ascii=False))
    if W is None:
        W = []
        for r in roster:
            d = kdf(r['sdt'], salt); b = r.get('btv') or None
            vv = {'k': b64(sub(m, 'shell')), 'd': b64(sub(m, 'btv:' + b) if b else sub(m, 'all')), 'b': b, 'n': r['ten'], 'p': chuan(r['sdt'])}
            if chuan(r['sdt']) == chuan(a.owner): vv['m'] = b64(m)
            W.append({'t': d[32:40].hex(), **ma(d[:32], json.dumps(vv, ensure_ascii=False).encode())})
        W.sort(key=lambda x: x['t'])
    khoa = "const SALT = '%s', IT = %d, W = %s, G = %s" % (salt, IT, json.dumps(W), json.dumps(G2))
    open(a.out, 'w', encoding='utf-8').write(tpl.replace('__KHOA__', khoa, 1))
    print('Đã dựng', a.out, '| người xem', len(W), '| nhóm địa bàn', len(btvs), '| bộ dữ liệu chung', sorted(chung), '| riêng', RIENG)

def check(a):
    tpl, salt, it, W, G = doc_trang(a.page)
    v = mo_khoa(W, salt, a.phone)
    shell = giai_gz(ub(v['k']), G['s']); r = json.loads(giai_gz(ub(v['d']), G[nhan(v.get('b'), salt)]))
    print(v['n'], '| phạm vi:', v.get('b') or 'toàn tỉnh', '| khóa chủ:', 'm' in v, '| shell', len(shell), '|', {k: len(x) for k, x in r.items()})

if __name__ == '__main__':
    p = argparse.ArgumentParser(); sp = p.add_subparsers(dest='cmd', required=True)
    b = sp.add_parser('build'); [b.add_argument('--' + x, required=x != 'roster') for x in ('page', 'index', 'data', 'owner', 'out', 'roster')]
    c = sp.add_parser('check'); c.add_argument('--page', required=True); c.add_argument('--phone', required=True)
    a = p.parse_args(); build(a) if a.cmd == 'build' else check(a)
