# Dumps the test cases of ps3recomp's PPU lifter conformance suite (tools/test_ppu_lift.py,
# https://github.com/sp00nznet/ps3recomp, MIT, Copyright (c) 2026 Ned Heller / sp00nznet)
# to cases.json, for gen_harness.py.
#
# Usage: python dump_cases.py <ps3recomp>/tools
import sys, json
sys.path.insert(0, sys.argv[1])
import test_ppu_lift as t
def conv(o):
    if isinstance(o, bytes): return o.hex()
    if isinstance(o, dict): return {str(k): conv(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)): return [conv(x) for x in o]
    return o
json.dump({"cases": conv(t.CASES), "vcases": conv(t.VCASES)}, open("cases.json", "w"), indent=0)
print(len(t.CASES), "scalar cases,", len(t.VCASES), "vector cases")
