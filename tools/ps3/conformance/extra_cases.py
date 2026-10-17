# Extra conformance cases written for this fork (not from ps3recomp): XER[OV]/[SO] of the OE
# forms, cr0 of record forms that were missing it, and cr6 of the vector compares. Expected
# values are computed here from the PowerISA definitions (64-bit mode, as Cell user code runs).
#
# Usage: python extra_cases.py   # -> extra.json, then: python gen_harness.py cases.json extra.json
import json, struct

M = (1 << 64) - 1
def s64(x): x &= M; return x - (1 << 64) if x >> 63 else x
def s32(x): x &= 0xFFFFFFFF; return x - (1 << 32) if x >> 31 else x
def tdiv(a, b): q = abs(a) // abs(b); return -q if (a < 0) != (b < 0) else q
def rotl32(x, n): x &= 0xFFFFFFFF; n &= 31; return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF if n else x
def rotl64(x, n): x &= M; n &= 63; return ((x << n) | (x >> (64 - n))) & M if n else x
def mask64(mb, me):  # IBM bit numbering
    m = 0
    for i in range(64):
        if (mb <= me and mb <= i <= me) or (mb > me and (i >= mb or i <= me)): m |= 1 << (63 - i)
    return m
def crnib(v, so):
    v = s64(v)
    return (8 if v < 0 else 4 if v > 0 else 2) | so

cases, vcases = [], []
def case(name, word, regs, rt, res, ca=None, exp_ca=None, so=0, exp_ov=None, rc=False):
    exp_so = so | (exp_ov or 0)
    cases.append({"name": name, "word": word, "in_regs": {str(k): v & M for k, v in regs.items()},
                  "expects": [[rt, res & M, M]] if res is not None else [], "in_ca": ca, "exp_ca": exp_ca,
                  "exp_cr": [crnib(res, exp_so), 28] if rc else None, "may_trap": False,
                  "in_mem": {}, "exp_mem": {}, "in_fpr": {}, "exp_fpr": [],
                  "in_so": so, "exp_ov": exp_ov, "exp_so": exp_so if exp_ov is not None or rc else None})

def xo(x, oe, rc, rt=3, ra=4, rb=5): return (31 << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (oe << 10) | (x << 1) | rc
def xform(x, rc, rs=4, ra=3, rb=5): return (31 << 26) | (rs << 21) | (ra << 16) | (rb << 11) | (x << 1) | rc

# --- OE forms: OV from the 64-bit result ---------------------------------------------------
def addov(x, y, c):
    r = (x + y + c) & M
    return r, ((x ^ r) & (y ^ r)) >> 63 & 1, int(x + y + c > M)
vals = [(0, 0), (1, 2), (0x7FFFFFFFFFFFFFFF, 1), (0x8000000000000000, 0xFFFFFFFFFFFFFFFF),
        (0x7FFFFFFF, 1), (0xFFFFFFFFFFFFFFFF, 1), (0x8000000000000000, 0x8000000000000000)]
for rc in (0, 1):
    d = "." if rc else ""
    for a, b in vals:
        for so in (0, 1):
            r, ov, cy = addov(a, b, 0)
            case(f"addo{d} a={a:#x} b={b:#x} so={so}", xo(266, 1, rc), {4: a, 5: b}, 3, r, so=so, exp_ov=ov, rc=rc)
            case(f"addco{d} a={a:#x} b={b:#x} so={so}", xo(10, 1, rc), {4: a, 5: b}, 3, r, ca=0, exp_ca=cy, so=so, exp_ov=ov, rc=rc)
            r, ov, _ = addov(~a & M, b, 1)
            case(f"subfo{d} a={a:#x} b={b:#x} so={so}", xo(40, 1, rc), {4: a, 5: b}, 3, r, so=so, exp_ov=ov, rc=rc)
            for c in (0, 1):
                r, ov, cy = addov(a, b, c)
                case(f"addeo{d} a={a:#x} b={b:#x} ca={c} so={so}", xo(138, 1, rc), {4: a, 5: b}, 3, r, ca=c, exp_ca=cy, so=so, exp_ov=ov, rc=rc)
                r, ov, cy = addov(~a & M, b, c)
                case(f"subfeo{d} a={a:#x} b={b:#x} ca={c} so={so}", xo(136, 1, rc), {4: a, 5: b}, 3, r, ca=c, exp_ca=cy, so=so, exp_ov=ov, rc=rc)
    for a in (0, 1, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF):
        for c in (0, 1):
            r, ov, cy = addov(a, 0, c)
            case(f"addzeo{d} a={a:#x} ca={c}", xo(202, 1, rc, rb=0), {4: a}, 3, r, ca=c, exp_ca=cy, exp_ov=ov, rc=rc)
            r, ov, cy = addov(a, M, c)
            case(f"addmeo{d} a={a:#x} ca={c}", xo(234, 1, rc, rb=0), {4: a}, 3, r, ca=c, exp_ca=cy, exp_ov=ov, rc=rc)
            r, ov, cy = addov(~a & M, 0, c)
            case(f"subfzeo{d} a={a:#x} ca={c}", xo(200, 1, rc, rb=0), {4: a}, 3, r, ca=c, exp_ca=cy, exp_ov=ov, rc=rc)
            r, ov, cy = addov(~a & M, M, c)
            case(f"subfmeo{d} a={a:#x} ca={c}", xo(232, 1, rc, rb=0), {4: a}, 3, r, ca=c, exp_ca=cy, exp_ov=ov, rc=rc)
        case(f"nego{d} a={a:#x}", xo(104, 1, rc, rb=0), {4: a}, 3, -a, exp_ov=int(a == 0x8000000000000000), rc=rc)
    for a, b in [(3, 4), (0x7FFFFFFF, 2), (0x80000000, 0xFFFFFFFF), (0x10000, 0x8000), (0xFFFFFFFF, 0xFFFFFFFF)]:
        p = s32(a) * s32(b)
        # mullw. sets cr0 from the 64-bit product
        case(f"mullwo{d} a={a:#x} b={b:#x}", xo(235, 1, rc), {4: a, 5: b}, 3, p, exp_ov=int(p != s32(p)), rc=rc)
    for a, b in [(3, 4), (0x7FFFFFFFFFFFFFFF, 2), (0x8000000000000000, 0xFFFFFFFFFFFFFFFF), (1 << 32, 1 << 31), (1 << 32, 1 << 32)]:
        p = s64(a) * s64(b)
        case(f"mulldo{d} a={a:#x} b={b:#x}", xo(233, 1, rc), {4: a, 5: b}, 3, p, exp_ov=int(p != s64(p)), rc=rc)
    for a, b in [(7, 2), (0x80000000, 0xFFFFFFFF), (5, 0), (0xFFFFFFF9, 2)]:
        ov = int(s32(b) == 0 or (s32(a) == -2**31 and s32(b) == -1))
        # The word divides leave the high half of rD undefined (and cr0 with it): check OV only
        case(f"divwo{d} a={a:#x} b={b:#x}", xo(491, 1, rc), {4: a, 5: b}, 3, None, exp_ov=ov)
        case(f"divwuo{d} a={a:#x} b={b:#x}", xo(459, 1, rc), {4: a, 5: b}, 3, None, exp_ov=int(b & 0xFFFFFFFF == 0))
    for a, b in [(7, 2), (0x8000000000000000, M), (5, 0), (M - 6, 2)]:
        ov = int(s64(b) == 0 or (s64(a) == -2**63 and s64(b) == -1))
        q = 0 if ov else tdiv(s64(a), s64(b))
        case(f"divdo{d} a={a:#x} b={b:#x}", xo(489, 1, rc), {4: a, 5: b}, 3, q, exp_ov=ov, rc=rc)
        q = 0 if b == 0 else a // b
        case(f"divduo{d} a={a:#x} b={b:#x}", xo(457, 1, rc), {4: a, 5: b}, 3, q, exp_ov=int(b == 0), rc=rc)

# --- Record forms that did not set cr0 ----------------------------------------------------
ins = [(0, 0), (0x8000000000000000, 1), (0x00000000FFFF0000, 0x10), (0x123456789ABCDEF0, 0x3F), (1, 0x40)]
for a, b in ins:
    for so in (0, 1):
        n = f"a={a:#x} b={b:#x} so={so}"
        case(f"nand. {n}", xform(476, 1), {4: a, 5: b}, 3, ~(a & b), so=so, rc=1)
        case(f"nor. {n}", xform(124, 1), {4: a, 5: b}, 3, ~(a | b), so=so, rc=1)
        case(f"orc. {n}", xform(412, 1), {4: a, 5: b}, 3, a | ~b, so=so, rc=1)
    w = a & 0xFFFFFFFF
    case(f"cntlzw. a={a:#x}", xform(26, 1, rb=0), {4: a}, 3, 32 - w.bit_length(), rc=1)
    case(f"cntlzd. a={a:#x}", xform(58, 1, rb=0), {4: a}, 3, 64 - a.bit_length(), rc=1)
    sh = b & 0x7F
    case(f"sld. a={a:#x} b={b:#x}", xform(27, 1), {4: a, 5: b}, 3, 0 if sh & 0x40 else a << sh, rc=1)
    case(f"srd. a={a:#x} b={b:#x}", xform(539, 1), {4: a, 5: b}, 3, 0 if sh & 0x40 else a >> sh, rc=1)
    case(f"srad. a={a:#x} b={b:#x}", xform(794, 1), {4: a, 5: b}, 3, s64(a) >> min(sh, 63), ca=0,
         exp_ca=int(s64(a) < 0 and (a & ((1 << min(sh, 64)) - 1)) != 0), rc=1)
    for s in (0, 4, 32, 63):
        case(f"sradi. a={a:#x} sh={s}", (31 << 26) | (4 << 21) | (3 << 16) | ((s & 31) << 11) | (413 << 2) | ((s >> 5) << 1) | 1,
             {4: a}, 3, s64(a) >> s, ca=0, exp_ca=int(s64(a) < 0 and (a & ((1 << s) - 1)) != 0), rc=1)
    case(f"mulld. a={a:#x} b={b:#x}", xo(233, 0, 1), {4: a, 5: b}, 3, s64(a) * s64(b), rc=1)
    case(f"mulhd. a={a:#x} b={b:#x}", xo(73, 0, 1), {4: a, 5: b}, 3, (s64(a) * s64(b)) >> 64, rc=1)
    case(f"mulhdu. a={a:#x} b={b:#x}", xo(9, 0, 1), {4: a, 5: b}, 3, (a * b) >> 64, rc=1)
    if b:
        case(f"divd. a={a:#x} b={b:#x}", xo(489, 0, 1), {4: a, 5: b}, 3, tdiv(s64(a), s64(b)), rc=1)
    # rotlw. (rlwnm mb=0 me=31): mask 32..63, so the result is the zero-extended 32-bit rotate
    for mb, me in [(16, 23), (28, 3)]:
        r = rotl32(a, b); r = (r << 32) | r
        case(f"rlwnm. a={a:#x} b={b:#x} mb={mb} me={me}", (23 << 26) | (4 << 21) | (3 << 16) | (5 << 11) | (mb << 6) | (me << 1) | 1, {4: a, 5: b}, 3, r & mask64(mb + 32, me + 32), rc=1)
    case(f"rotlw. a={a:#x} b={b:#x}", (23 << 26) | (4 << 21) | (3 << 16) | (5 << 11) | (0 << 6) | (31 << 1) | 1, {4: a, 5: b}, 3, rotl32(a, b), rc=1)
def md(xop, sh, mb, rc=1): return (30 << 26) | (4 << 21) | (3 << 16) | ((sh & 31) << 11) | ((((mb & 31) << 1) | (mb >> 5)) << 5) | (xop << 2) | ((sh >> 5) << 1) | rc
for a in (0, 0x8000000000000000, 0x123456789ABCDEF0, 0xFF):
    for sh, mb in [(0, 32), (0, 1), (8, 0), (60, 4), (4, 63)]:
        case(f"rldicl. a={a:#x} sh={sh} mb={mb}", md(0, sh, mb), {4: a}, 3, rotl64(a, sh) & mask64(mb, 63), rc=1)
        case(f"rldic. a={a:#x} sh={sh} mb={mb}", md(2, sh, mb), {4: a}, 3, rotl64(a, sh) & mask64(mb, 63 - sh), rc=1)
        old = 0x5555555555555555
        m = mask64(mb, 63 - sh)
        case(f"rldimi. a={a:#x} sh={sh} mb={mb}", md(3, sh, mb), {4: a, 3: old}, 3, (rotl64(a, sh) & m) | (old & ~m), rc=1)
    for b in (0, 8, 63):
        case(f"rotld. a={a:#x} b={b}", (30 << 26) | (4 << 21) | (3 << 16) | (5 << 11) | (8 << 1) | 1, {4: a, 5: b}, 3, rotl64(a, b), rc=1)
    for sh, mb, me in [(0, 0, 31), (8, 16, 23), (31, 0, 0), (4, 28, 3)]:
        old = 0xAAAAAAAAAAAAAAAA
        r = rotl32(a, sh); r = (r << 32) | r
        m = mask64(mb + 32, me + 32)
        case(f"rlwimi. a={a:#x} sh={sh} mb={mb} me={me}", (20 << 26) | (4 << 21) | (3 << 16) | (sh << 11) | (mb << 6) | (me << 1) | 1,
             {4: a, 3: old}, 3, (r & m) | (old & ~m), rc=1)

# --- Vector compares: result and cr6 (bit 0 = all true, bit 2 = all false) ------------------
def vx(x, rc, vd=1, va=2, vb=3): return (4 << 26) | (vd << 21) | (va << 16) | (vb << 11) | (rc << 10) | x
def lanes(b, w): return [int.from_bytes(b[i:i + w], "big") for i in range(0, 16, w)]
def pack(vs, w): return b"".join(v.to_bytes(w, "big") for v in vs)
def sx(v, w): return v - (1 << (8 * w)) if v >> (8 * w - 1) else v
def fl(v):  # the Cell VMX unit flushes denormal inputs to zero
    return 0.0 if (v >> 23) & 0xFF == 0 else struct.unpack(">f", struct.pack(">I", v))[0]
ops = {"vcmpequb": (6, 1, lambda a, b: a == b), "vcmpequh": (70, 2, lambda a, b: a == b), "vcmpequw": (134, 4, lambda a, b: a == b),
       "vcmpgtub": (518, 1, lambda a, b: a > b), "vcmpgtuh": (582, 2, lambda a, b: a > b), "vcmpgtuw": (646, 4, lambda a, b: a > b),
       "vcmpgtsb": (774, 1, None), "vcmpgtsh": (838, 2, None), "vcmpgtsw": (902, 4, None),
       "vcmpeqfp": (198, 4, lambda a, b: fl(a) == fl(b)), "vcmpgefp": (454, 4, lambda a, b: fl(a) >= fl(b)), "vcmpgtfp": (710, 4, lambda a, b: fl(a) > fl(b))}
inputs = {
    "mixed": (bytes(range(16)), bytes(range(15, -1, -1))),
    "equal": (bytes(range(16)), bytes(range(16))),
    "gt": (bytes([0x70] * 16), bytes([0x10] * 16)),
    "lt": (bytes([0x10] * 16), bytes([0x70] * 16)),
    "highhalf": (bytes.fromhex("00010000" * 4), bytes.fromhex("00000000" * 4)),  # only the high halfword of each word is greater
    "sign": (bytes([0x80] * 16), bytes([0x01] * 16)),
    "float": (pack([0x3F800000, 0x40000000, 0xBF800000, 0x00000000], 4), pack([0x3F800000, 0x3F800000, 0x3F800000, 0x80000000], 4)),
}
for name, (x, w, f) in ops.items():
    for iname, (va, vb) in inputs.items():
        A, B = lanes(va, w), lanes(vb, w)
        if f is None: res = [sx(a, w) > sx(b, w) for a, b in zip(A, B)]
        else: res = [f(a, b) for a, b in zip(A, B)]
        out = pack([(1 << (8 * w)) - 1 if t else 0 for t in res], w)
        nib = (8 if all(res) else 0) | (2 if not any(res) else 0)
        vcases.append({"name": f"{name}. {iname}", "word": vx(x, 1), "va_reg": 2, "vb_reg": 3, "vc_reg": None, "vd_reg": 1,
                       "va_bytes": va.hex(), "vb_bytes": vb.hex(), "vc_bytes": None, "exp_bytes": out.hex(), "exp_cr": [nib, 4]})

json.dump({"cases": cases, "vcases": vcases}, open("extra.json", "w"), indent=0)
print(len(cases), "scalar cases,", len(vcases), "vector cases")
