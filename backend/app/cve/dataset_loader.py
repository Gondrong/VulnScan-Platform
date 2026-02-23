import json
from functools import lru_cache

@lru_cache(maxsize=128)
def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def clear_cache():
    load_json.cache_clear()
