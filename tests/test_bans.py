import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml"))

from bans import BanError, BanList  # noqa: E402

NEVER = ["127.0.0.0/8", "::1/128", "10.250.0.0/24"]


def test_shared_addresses_are_never_banned(tmp_path):
    bans = BanList(tmp_path / "bans.json", NEVER)
    for ip in ("10.250.0.1", "10.250.0.10", "127.0.0.1", "::1"):
        with pytest.raises(BanError):
            bans.add(ip, "manual", "test", None)
    with pytest.raises(BanError):
        bans.add("not-an-ip", "manual", "test", None)


def test_ban_persists_and_expires(tmp_path):
    path = tmp_path / "bans.json"
    bans = BanList(path, NEVER)
    bans.add("192.168.137.25", "waf", "5 requêtes bloquées", 3600)
    bans.add("192.168.137.26", "manual", "permanent", None)
    reloaded = BanList(path, NEVER)
    assert reloaded.get("192.168.137.25")["source"] == "waf"
    assert reloaded.get("192.168.137.26")["until"] is None
    assert reloaded.purge(time.time() + 7200) == ["192.168.137.25"]
    assert reloaded.get("192.168.137.25") is None and reloaded.get("192.168.137.26") is not None


def test_shorter_ban_does_not_replace_longer_one(tmp_path):
    bans = BanList(tmp_path / "bans.json", NEVER)
    long_ban = bans.add("192.168.137.25", "manual", "permanent", None)
    assert bans.add("192.168.137.25", "ml", "trafic anormal", 600) is long_ban
    assert bans.remove("192.168.137.25") and not bans.remove("192.168.137.25")


def test_ipv4_mapped_ipv6_is_normalized(tmp_path):
    bans = BanList(tmp_path / "bans.json", NEVER)
    bans.add("::ffff:192.168.137.25", "manual", "test", None)
    assert bans.get("192.168.137.25") is not None
