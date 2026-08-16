import json
import os
import time

import pytest

from nearest_exit import cache as cache_mod
from nearest_exit.cache import JsonCache


def test_save_and_load_roundtrip(tmp_path):
    c = JsonCache(cache_dir=tmp_path)
    c.save("k", {"a": [1, 2, 3]})
    assert c.fresh("k")
    assert c.load("k") == {"a": [1, 2, 3]}


def test_save_leaves_no_temp_files(tmp_path):
    c = JsonCache(cache_dir=tmp_path)
    c.save("k", {"a": 1})
    assert [p.name for p in tmp_path.iterdir()] == ["k.json"]


def test_save_is_atomic_replace(tmp_path):
    """The destination must never see a partially written file."""
    c = JsonCache(cache_dir=tmp_path)
    c.save("k", {"old": True})
    seen = {}
    real_replace = os.replace

    def spy(src, dst):
        seen["src_content"] = json.loads(open(src).read())
        seen["dst_content"] = json.loads(open(dst).read())
        return real_replace(src, dst)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(cache_mod.os, "replace", spy)
        c.save("k", {"new": True})

    # Full payload staged in the temp file; destination still the old entry.
    assert seen["src_content"] == {"new": True}
    assert seen["dst_content"] == {"old": True}
    assert c.load("k") == {"new": True}


def test_failed_save_keeps_previous_entry_and_cleans_up(tmp_path):
    c = JsonCache(cache_dir=tmp_path)
    c.save("k", {"good": 1})
    with pytest.raises(TypeError):
        c.save("k", {"bad": object()})
    assert c.load("k") == {"good": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["k.json"]


def test_corrupt_entry_is_a_miss_not_an_exception(tmp_path):
    c = JsonCache(cache_dir=tmp_path)
    c.save("k", {"a": 1})
    (tmp_path / "k.json").write_text('{"a": [1, 2')  # truncated write
    assert c.fresh("k") is False
    assert c.load("k") is None


def test_corrupt_entry_recovers_on_next_save(tmp_path):
    c = JsonCache(cache_dir=tmp_path)
    (tmp_path / "k.json").write_text("not json at all")
    assert not c.fresh("k")
    c.save("k", {"a": 2})
    assert c.fresh("k")
    assert c.load("k") == {"a": 2}


def test_missing_entry_is_a_miss(tmp_path):
    c = JsonCache(cache_dir=tmp_path)
    assert c.fresh("nope") is False
    assert c.load("nope") is None


def test_ttl_expiry(tmp_path):
    c = JsonCache(cache_dir=tmp_path, ttl_seconds=60)
    c.save("k", {"a": 1})
    assert c.fresh("k")
    old = time.time() - 3600
    os.utime(tmp_path / "k.json", (old, old))
    assert c.fresh("k") is False
    # Stale but intact entries stay readable for callers that want a fallback.
    assert c.load("k") == {"a": 1}


def test_zero_ttl_is_never_fresh(tmp_path):
    c = JsonCache(cache_dir=tmp_path, ttl_seconds=0)
    c.save("k", {"a": 1})
    assert c.fresh("k") is False


def test_save_invalidates_memoized_payload(tmp_path):
    c = JsonCache(cache_dir=tmp_path)
    c.save("k", {"v": 1})
    assert c.load("k") == {"v": 1}
    c.save("k", {"v": 2})
    assert c.load("k") == {"v": 2}


def test_save_creates_directory(tmp_path):
    c = JsonCache(cache_dir=tmp_path / "deep" / "nested")
    c.save("k", [1])
    assert c.load("k") == [1]


def test_no_cache_keeps_entries_in_memory_but_never_on_disk(tmp_path):
    """`--no-cache` means "do not persist between runs". It must not mean
    "refetch the same provider several times within one run", which is what a
    cache that always misses would cause."""
    cache = JsonCache(cache_dir=tmp_path, ttl_seconds=3600, enabled=False)

    assert cache.fresh("relays") is False
    cache.save("relays", {"a": 1})

    assert cache.fresh("relays") is True
    assert cache.load("relays") == {"a": 1}
    assert list(tmp_path.iterdir()) == []


def test_no_cache_ignores_anything_already_on_disk(tmp_path):
    on_disk = JsonCache(cache_dir=tmp_path, ttl_seconds=3600)
    on_disk.save("relays", {"stale": True})

    cold = JsonCache(cache_dir=tmp_path, ttl_seconds=3600, enabled=False)

    assert cold.fresh("relays") is False
    assert cold.load("relays") is None


def test_in_memory_entries_still_expire(tmp_path):
    cache = JsonCache(cache_dir=tmp_path, ttl_seconds=0, enabled=False)
    cache.save("relays", {"a": 1})

    # TTL 0 means nothing is ever fresh, on disk or off it.
    assert cache.fresh("relays") is False
    # ...but load() ignores the TTL in both modes, so a stale-but-valid entry
    # is still available to callers that choose to fall back to it.
    assert cache.load("relays") == {"a": 1}
