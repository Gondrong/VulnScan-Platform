"""
GeoIP lookup using MaxMind GeoLite2-City database.

Falls back gracefully to the raw IP when the database is missing.
Download the free database from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
and place it at the path configured by GEOIP_DB_PATH (default: /data/GeoLite2-City.mmdb).
"""
import logging

from app.core.config import settings

logger = logging.getLogger("vulnscan.geoip")

_reader = None
_init_done = False


def _get_reader():
    global _reader, _init_done
    if _init_done:
        return _reader
    _init_done = True
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
        logger.info("GeoIP database loaded: %s", settings.GEOIP_DB_PATH)
    except FileNotFoundError:
        logger.warning("GeoIP database not found at %s — location will show IP only", settings.GEOIP_DB_PATH)
    except Exception as e:
        logger.warning("GeoIP init failed: %s", e)
    return _reader


def resolve(ip: str) -> str | None:
    """Resolve an IP address to 'City, Country'. Returns None if unavailable."""
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return "localhost"
    reader = _get_reader()
    if not reader:
        return None
    try:
        resp = reader.city(ip)
        city = resp.city.name or ""
        country = resp.country.name or ""
        if city and country:
            return f"{city}, {country}"
        return country or city or None
    except Exception:
        return None
