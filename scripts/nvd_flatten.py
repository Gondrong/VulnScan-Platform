#!/usr/bin/env python3
import argparse, json, sys
from typing import Any, Dict, List, Optional

def pick_cvss(metrics: Dict[str, Any]) -> tuple[Optional[float], str]:
    """
    NVD 2.0 stores metrics under:
      metrics: { cvssMetricV31: [...], cvssMetricV30: [...], cvssMetricV2: [...] }
    We'll prefer V3.1, then V3.0, then V2.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not arr:
            continue
        # choose first "Primary" if present else first
        chosen = None
        for m in arr:
            if (m.get("type") or "").lower() == "primary":
                chosen = m
                break
        if chosen is None:
            chosen = arr[0]
        cvss = chosen.get("cvssData", {}) or {}
        score = cvss.get("baseScore")
        sev = (cvss.get("baseSeverity") or "").lower()
        if isinstance(score, (int, float)):
            return float(score), sev
    return None, ""

def normalize_severity(sev: str, score: Optional[float]) -> str:
    if sev in ("critical", "high", "medium", "low"):
        return sev
    if score is None:
        return "medium"
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0: return "low"
    return "info"

def first_desc(cve: Dict[str, Any]) -> str:
    descs = ((cve.get("descriptions") or []) if isinstance(cve.get("descriptions"), list) else [])
    for d in descs:
        if (d.get("lang") or "") == "en" and d.get("value"):
            return d["value"]
    for d in descs:
        if d.get("value"):
            return d["value"]
    return ""

def refs(cve: Dict[str, Any]) -> List[str]:
    rs = []
    for r in (cve.get("references") or []):
        url = r.get("url")
        if url:
            rs.append(url)
    # limit to keep file small
    return rs[:10]

def extract_cpe_matches(configurations: Any) -> List[Dict[str, Any]]:
    """
    NVD 2.0 'configurations' field is not always consistent.
    It can be:
      - dict: { "nodes": [...] }
      - list: [ node, node, ... ]
      - missing/None

    We traverse nodes recursively and collect vulnerable cpeMatch entries.

    Output keeps:
      cpe23, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding
    """
    out: List[Dict[str, Any]] = []

    # Normalize configurations -> nodes list
    nodes: List[Dict[str, Any]] = []
    if configurations is None:
        nodes = []
    elif isinstance(configurations, dict):
        raw_nodes = configurations.get("nodes") or []
        if isinstance(raw_nodes, list):
            nodes = raw_nodes
        else:
            nodes = []
    elif isinstance(configurations, list):
        nodes = configurations
    else:
        nodes = []

    stack = [n for n in nodes if isinstance(n, dict)]

    while stack:
        node = stack.pop()

        # children can be under "children" or sometimes nested nodes
        children = node.get("children") or []
        if isinstance(children, list):
            for c in children:
                if isinstance(c, dict):
                    stack.append(c)

        # some feeds might use "nodes" nesting too
        nested_nodes = node.get("nodes") or []
        if isinstance(nested_nodes, list):
            for c in nested_nodes:
                if isinstance(c, dict):
                    stack.append(c)

        cpe_matches = node.get("cpeMatch") or []
        if not isinstance(cpe_matches, list):
            continue

        for m in cpe_matches:
            if not isinstance(m, dict):
                continue

            # only vulnerable entries (some use True/False; if absent treat as vulnerable)
            if m.get("vulnerable") is False:
                continue

            cpe = m.get("criteria") or m.get("cpe23Uri")
            if not cpe:
                continue

            item = {
                "cpe23": cpe,
                "versionStartIncluding": m.get("versionStartIncluding"),
                "versionStartExcluding": m.get("versionStartExcluding"),
                "versionEndIncluding": m.get("versionEndIncluding"),
                "versionEndExcluding": m.get("versionEndExcluding"),
            }
            item = {k: v for k, v in item.items() if v not in (None, "")}
            out.append(item)

    # de-dup
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for x in out:
        key = (
            x.get("cpe23"),
            x.get("versionStartIncluding"),
            x.get("versionStartExcluding"),
            x.get("versionEndIncluding"),
            x.get("versionEndExcluding"),
        )
        if key in seen:
            continue
        seen.add(key)
        uniq.append(x)

    return uniq

def load_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True, help="NVD 2.0 JSON files (recent/modified/year)")
    ap.add_argument("--out", required=True, help="output flattened json")
    ap.add_argument("--max", type=int, default=0, help="optional limit for debugging")
    args = ap.parse_args()

    flattened = {}
    count=0

    for inp in args.inputs:
        doc = load_file(inp)
        vulns = doc.get("vulnerabilities") or []
        for v in vulns:
            cve = (v.get("cve") or {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            metrics = cve.get("metrics") or {}
            score, sev = pick_cvss(metrics)
            sev = normalize_severity(sev, score)
            summary = first_desc(cve)
            matches = extract_cpe_matches(cve.get("configurations") or {})

            # store (prefer modified over recent; but easiest is overwrite)
            flattened[cve_id] = {
                "cve": cve_id,
                "summary": summary,
                "severity": sev,
                "cvss": score,
                "refs": refs(cve),
                "matches": matches
            }

            count += 1
            if args.max and count >= args.max:
                break
        if args.max and count >= args.max:
            break

    # Convert dict->list
    out_list = list(flattened.values())

    # Keep file size reasonable: drop entries with no matches (optional)
    out_list = [x for x in out_list if x.get("matches")]

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_list, f, ensure_ascii=False)

    print(f"Flattened: {len(out_list)} CVEs with CPE matches -> {args.out}")

if __name__ == "__main__":
    main()
