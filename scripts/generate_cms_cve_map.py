#!/usr/bin/env python3
"""
Generate a CMS CVE map from the flattened NVD data.

Scans nvd_cpe_cve.json for entries that match known CMS products
(WordPress, Joomla, Drupal, Magento, etc.) and outputs a simplified
cms_cve_map.json for the VulnScan cms_match plugin.

Usage:
    python3 generate_cms_cve_map.py --nvd data/cve/nvd_cpe_cve.json --out data/cve/cms_cve_map.json
"""
import argparse
import json
import re
import sys


# Known CMS products and their CPE vendor:product patterns
CMS_PATTERNS = {
    "wordpress": [
        ("wordpress", "wordpress"),
        ("automattic", "wordpress"),
    ],
    "joomla": [
        ("joomla", "joomla"),
        ("joomla", "joomla\\!"),
    ],
    "drupal": [
        ("drupal", "drupal"),
    ],
    "magento": [
        ("magento", "magento"),
        ("adobe", "magento"),
    ],
    "typo3": [
        ("typo3", "typo3"),
    ],
    "prestashop": [
        ("prestashop", "prestashop"),
    ],
    "ghost": [
        ("ghost", "ghost"),
    ],
    "mediawiki": [
        ("mediawiki", "mediawiki"),
    ],
    "moodle": [
        ("moodle", "moodle"),
    ],
    "phpmyadmin": [
        ("phpmyadmin", "phpmyadmin"),
    ],
    "grafana": [
        ("grafana", "grafana"),
    ],
    "nextcloud": [
        ("nextcloud", "nextcloud_server"),
        ("nextcloud", "nextcloud"),
    ],
    "gitlab": [
        ("gitlab", "gitlab"),
    ],
    "jenkins": [
        ("jenkins", "jenkins"),
        ("cloudbees", "jenkins"),
    ],
}


def cpe_matches_cms(cpe23: str, vendor_pat: str, product_pat: str) -> bool:
    """Check if a CPE string matches a vendor:product pattern."""
    parts = cpe23.split(":")
    if len(parts) < 6:
        return False
    vendor = parts[3].lower()
    product = parts[4].lower()
    return (
        re.match(vendor_pat, vendor, re.I) is not None
        and re.match(product_pat, product, re.I) is not None
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvd", required=True, help="Path to nvd_cpe_cve.json")
    ap.add_argument("--out", required=True, help="Output cms_cve_map.json")
    args = ap.parse_args()

    try:
        with open(args.nvd, "r", encoding="utf-8") as f:
            nvd_data = json.load(f)
    except Exception as e:
        print(f"Error loading NVD data: {e}", file=sys.stderr)
        sys.exit(1)

    cms_entries = []
    seen = set()

    for item in nvd_data:
        cve_id = item.get("cve", "")
        if not cve_id.startswith("CVE-"):
            continue

        matches = item.get("matches", [])
        for m in matches:
            cpe23 = m.get("cpe23", "")
            for cms_name, patterns in CMS_PATTERNS.items():
                for vendor_pat, product_pat in patterns:
                    if cpe_matches_cms(cpe23, vendor_pat, product_pat):
                        key = (cve_id, cms_name)
                        if key not in seen:
                            seen.add(key)
                            cms_entries.append({
                                "cve": cve_id,
                                "cms": cms_name,
                                "severity": item.get("severity", "medium"),
                                "summary": item.get("summary", "")[:300],
                                "cvss": item.get("cvss"),
                                "refs": item.get("refs", [])[:3],
                            })

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cms_entries, f, ensure_ascii=False)

    print(f"CMS CVE map: {len(cms_entries)} entries for {len(set(e['cms'] for e in cms_entries))} CMS products -> {args.out}")


if __name__ == "__main__":
    main()
