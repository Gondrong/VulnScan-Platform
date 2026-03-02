#!/usr/bin/env python3
"""
Flatten NVD CVE data into a simple JSON format for the VulnScan platform.

Supports BOTH:
  - Old NVD JSON feeds (retired Dec 2023): {"CVE_Items": [...]}
  - NVD API 2.0 responses: {"vulnerabilities": [{"cve": {...}}, ...]}
"""
import argparse, json, sys
from typing import Any, Dict, List, Optional


def pick_cvss(metrics: Dict[str, Any]) -> tuple:
    """Extract CVSS score and severity from NVD metrics."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not arr:
            continue
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
    descs = cve.get("descriptions") or []
    if not isinstance(descs, list):
        return ""
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
    return rs[:10]


def extract_cpe_matches(configurations: Any) -> List[Dict[str, Any]]:
    """
    Extract CPE matches from NVD configurations.
    Handles both API 2.0 format and old feed format.
    """
    out: List[Dict[str, Any]] = []

    nodes: List[Dict[str, Any]] = []
    if configurations is None:
        return out
    elif isinstance(configurations, dict):
        raw_nodes = configurations.get("nodes") or []
        nodes = raw_nodes if isinstance(raw_nodes, list) else []
    elif isinstance(configurations, list):
        nodes = configurations
    else:
        return out

    stack = [n for n in nodes if isinstance(n, dict)]

    while stack:
        node = stack.pop()

        for child_key in ("children", "nodes"):
            children = node.get(child_key) or []
            if isinstance(children, list):
                for c in children:
                    if isinstance(c, dict):
                        stack.append(c)

        cpe_matches = node.get("cpeMatch") or []
        if not isinstance(cpe_matches, list):
            continue

        for m in cpe_matches:
            if not isinstance(m, dict):
                continue
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

    # De-duplicate
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
        if key not in seen:
            seen.add(key)
            uniq.append(x)
    return uniq


def extract_vulns(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract vulnerability list from either format:
    - NVD API 2.0: {"vulnerabilities": [{"cve": {...}}, ...]}
    - Old feed: {"CVE_Items": [{"cve": {...}, "configurations": {...}}, ...]}
    """
    # API 2.0 format
    if "vulnerabilities" in doc:
        return doc["vulnerabilities"]

    # Old feed format
    if "CVE_Items" in doc:
        return doc["CVE_Items"]

    # Might be a bare list
    if isinstance(doc, list):
        return doc

    return []


def extract_cve_obj(vuln_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the CVE object from a vulnerability entry."""
    # API 2.0: {"cve": {"id": "CVE-...", "metrics": {}, "configurations": [...]}}
    if "cve" in vuln_entry and isinstance(vuln_entry["cve"], dict):
        return vuln_entry["cve"]
    # Some formats have it at top level
    return vuln_entry


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True, help="NVD JSON files")
    ap.add_argument("--out", required=True, help="output flattened json")
    ap.add_argument("--max", type=int, default=0, help="optional limit for debugging")
    args = ap.parse_args()

    flattened = {}
    count = 0

    for inp in args.inputs:
        try:
            with open(inp, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load {inp}: {e}", file=sys.stderr)
            continue

        vulns = extract_vulns(doc)
        print(f"  Processing {inp}: {len(vulns)} entries")

        for v in vulns:
            cve = extract_cve_obj(v)
            cve_id = cve.get("id") or cve.get("cveId") or ""

            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            metrics = cve.get("metrics") or {}
            score, sev = pick_cvss(metrics)
            sev = normalize_severity(sev, score)
            summary = first_desc(cve)

            # configurations can be at cve level or vuln_entry level
            configs = cve.get("configurations") or v.get("configurations") or {}
            matches = extract_cpe_matches(configs)

            flattened[cve_id] = {
                "cve": cve_id,
                "summary": summary,
                "severity": sev,
                "cvss": score,
                "refs": refs(cve),
                "matches": matches,
            }

            count += 1
            if args.max and count >= args.max:
                break
        if args.max and count >= args.max:
            break

    # Convert dict -> list, keep only entries with CPE matches
    out_list = [x for x in flattened.values() if x.get("matches")]

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_list, f, ensure_ascii=False)

    print(f"Flattened: {len(out_list)} CVEs with CPE matches (of {len(flattened)} total) -> {args.out}")


if __name__ == "__main__":
    main()
