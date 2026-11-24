"""
A minimal in-memory stand-in for `redis.asyncio.Redis`, implementing the
subset `RedisCache` uses — with **Redis's own** `MATCH` glob semantics
(including backslash escapes), not `fnmatch`'s.

The previous per-file mocks used `fnmatch`, which treats `\\` literally
and so could never tell an escaped `\\*` from a wildcard. Tests built on
those mocks — plus a route-level fake that merely recorded whatever
fragment string it was handed — let SEC3-6 ship: the control plane's
"invalidate tenant" asserted the wrong fragment and passed.
"""

import re


def redis_glob_to_regex(pattern: str) -> re.Pattern:
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                out.append(re.escape(ch))
            else:
                body = pattern[i + 1 : end]
                negate = body.startswith("^")
                body = ("^" if negate else "") + re.escape(body[1:] if negate else body)
                out.append(f"[{body}]")
                i = end
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("".join(out), re.DOTALL)


class FakeRedis:
    def __init__(self):
        self.store: dict[str, bytes] = {}
        self.scan_counts: list[int | None] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value.encode() if isinstance(value, str) else value

    async def delete(self, *keys):
        return sum(self.store.pop(k, None) is not None for k in keys)

    async def unlink(self, *keys):
        return await self.delete(*keys)

    async def scan_iter(self, match=None, count=None):
        self.scan_counts.append(count)
        regex = redis_glob_to_regex(match) if match is not None else None
        for key in list(self.store):
            if regex is None or regex.fullmatch(key):
                yield key

    async def aclose(self):
        pass
