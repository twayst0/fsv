import asyncio
import pytest
from fsv.core.http_client import TokenBucket, HTTPStats, _decode


@pytest.mark.asyncio
async def test_token_bucket_rate_limits():
    import time
    tb = TokenBucket(rate_per_sec=20, burst=1)
    t0 = time.monotonic()
    for _ in range(4):
        await tb.acquire()
    # 4 tokens at 20/s with burst 1 ≈ 0.15s minimum
    assert time.monotonic() - t0 >= 0.1


def test_stats_avg_latency():
    s = HTTPStats(requests=6, responses=4, total_time=0.4)
    assert s.as_dict()["avg_latency_ms"] == 100.0


def test_decode_handles_bogus_charset():
    assert _decode(b"hello", "not-a-real-charset") == "hello"
    assert _decode(b"\xff\xfe", "utf-8") == "��"
