import re
from packaging.version import Version, InvalidVersion

def normalize(v: str) -> str:
    v = (v or "").strip()
    v = v.split(":",1)[-1]
    v = re.sub(r"[^0-9A-Za-z\.\-\+~]", "", v)
    return v

def parse(v: str):
    try:
        return Version(normalize(v))
    except InvalidVersion:
        return None

def match_expr(installed: str, expr: str) -> bool:
    inst = parse(installed)
    if not inst:
        return False
    parts = expr.split()
    ok = True
    i = 0
    while i < len(parts):
        op = parts[i]; v = parts[i+1]; i += 2
        pv = parse(v)
        if not pv:
            return False
        if op == "<": ok = ok and (inst < pv)
        elif op == "<=": ok = ok and (inst <= pv)
        elif op == ">": ok = ok and (inst > pv)
        elif op == ">=": ok = ok and (inst >= pv)
        elif op == "==": ok = ok and (inst == pv)
        else: return False
    return ok
