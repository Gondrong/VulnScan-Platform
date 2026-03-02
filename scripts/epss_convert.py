#!/usr/bin/env python3
"""
Convert EPSS CSV scores into JSON for the VulnScan platform.

The EPSS CSV file from https://epss.cyentia.com has a comment line at the top:
  #model_version:v2023.03.01,score_date:2026-02-26T00:00:00+0000
  cve,epss,percentile
  CVE-2014-6271,0.97565,0.99996
  ...

This script skips that comment line before parsing.
"""
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
        # Skip comment lines at the top (EPSS CSV starts with #model_version:...)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            if not line.startswith("#"):
                f.seek(pos)  # put back the non-comment line (CSV header)
                break

        r = csv.DictReader(f)
        for row in r:
            cve = (row.get("cve") or "").strip()
            if not cve.startswith("CVE-"):
                continue
            try:
                epss = float(row.get("epss", "0") or 0)
                pct = float(row.get("percentile", "0") or 0)
            except (ValueError, TypeError):
                continue
            out.append({"cve": cve, "epss": epss, "percentile": pct, "date": today})

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)

    print(f"EPSS converted: {len(out)} entries -> {args.out}")


if __name__ == "__main__":
    main()
