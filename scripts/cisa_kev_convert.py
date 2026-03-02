#!/usr/bin/env python3
"""
Convert CISA KEV JSON into the flat format used by the VulnScan platform.
"""
import argparse, json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.inp, "r", encoding="utf-8") as f:
        doc = json.load(f)

    vulns = doc.get("vulnerabilities") or []
    out = []
    for v in vulns:
        cve = (v.get("cveID") or v.get("cve") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        out.append({
            "cve": cve,
            "vendorProject": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "dateAdded": v.get("dateAdded", ""),
            "dueDate": v.get("dueDate", ""),
            "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", ""),
            "notes": v.get("shortDescription") or v.get("notes") or "",
            "refs": [v.get("notes", "")] if isinstance(v.get("notes"), str) else [],
        })

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)

    print(f"KEV converted: {len(out)} entries -> {args.out}")


if __name__ == "__main__":
    main()
