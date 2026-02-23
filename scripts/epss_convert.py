#!/usr/bin/env python3
import argparse, csv, json
from datetime import date

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    today = str(date.today())
    out = []
    with open(args.inp, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            cve = (row.get("cve") or "").strip()
            if not cve.startswith("CVE-"):
                continue
            try:
                epss = float(row.get("epss", "0") or 0)
                pct = float(row.get("percentile", "0") or 0)
            except:
                continue
            out.append({"cve": cve, "epss": epss, "percentile": pct, "date": today})

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)

    print(f"EPSS converted: {len(out)} -> {args.out}")

if __name__ == "__main__":
    main()
