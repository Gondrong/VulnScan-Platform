"""
CVE dataset loader — reads JSON files from disk.
Datasets can be NVD JSON feeds, custom lists, or compliance maps.
"""
import json
import logging
import os

logger = logging.getLogger("vulnscan.cve")


def load_json(path: str) -> list[dict]:
    """
    Load a JSON dataset from the given file path.
    Supports:
      - A JSON array:  [{...}, {...}]
      - NVD feed format: {"CVE_Items": [{...}]}
    Returns an empty list on any error.
    """
    if not os.path.isfile(path):
        logger.warning("Dataset file not found: %s", path)
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error("Failed to parse dataset %s: %s", path, e)
        return []

    if isinstance(data, list):
        return data

    # NVD feed format
    if isinstance(data, dict):
        if "CVE_Items" in data:
            return data["CVE_Items"]
        if "vulnerabilities" in data:
            return data["vulnerabilities"]
        # Single-item dict — wrap it
        return [data]

    logger.warning("Unexpected dataset format in %s", path)
    return []
