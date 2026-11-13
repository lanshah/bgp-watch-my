"""Prefix helpers: a small longest-prefix-match index and AS-path utilities."""
from __future__ import annotations

import ipaddress
from typing import Generic, Iterator, TypeVar

T = TypeVar("T")
Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def net(p: str) -> Net:
    return ipaddress.ip_network(p, strict=False)


class PrefixIndex(Generic[T]):
    """Maps prefixes to values and answers 'which stored prefixes cover X?'.

    Stores one dict per (IP version, prefix length) keyed by the network address as an
    integer, so a covering lookup is at most 33 (IPv4) or 129 (IPv6) dict probes.
    """

    def __init__(self) -> None:
        self._t: dict[tuple[int, int], dict[int, T]] = {}
        self._lens: dict[int, list[int]] = {4: [], 6: []}

    def add(self, prefix: str | Net, value: T) -> None:
        n = net(prefix) if isinstance(prefix, str) else prefix
        key = (n.version, n.prefixlen)
        if key not in self._t:
            self._t[key] = {}
            self._lens[n.version] = sorted({*self._lens[n.version], n.prefixlen})
        self._t[key][int(n.network_address)] = value

    def get(self, prefix: str | Net) -> T | None:
        n = net(prefix) if isinstance(prefix, str) else prefix
        return self._t.get((n.version, n.prefixlen), {}).get(int(n.network_address))

    def __contains__(self, prefix: str | Net) -> bool:
        return self.get(prefix) is not None

    def covering(self, prefix: str | Net, include_self: bool = True) -> list[tuple[Net, T]]:
        """All stored prefixes that contain `prefix`, most specific first."""
        n = net(prefix) if isinstance(prefix, str) else prefix
        bits = 32 if n.version == 4 else 128
        addr = int(n.network_address)
        out = []
        for plen in reversed(self._lens[n.version]):
            if plen > n.prefixlen or (plen == n.prefixlen and not include_self):
                continue
            mask = ((1 << bits) - 1) ^ ((1 << (bits - plen)) - 1)
            v = self._t[(n.version, plen)].get(addr & mask)
            if v is not None:
                cls = ipaddress.IPv4Network if n.version == 4 else ipaddress.IPv6Network
                out.append((cls((addr & mask, plen)), v))
        return out

    def items(self) -> Iterator[tuple[Net, T]]:
        for (ver, plen), d in self._t.items():
            cls = ipaddress.IPv4Network if ver == 4 else ipaddress.IPv6Network
            for a, v in d.items():
                yield cls((a, plen)), v

    def __len__(self) -> int:
        return sum(len(d) for d in self._t.values())


def top_level(prefixes: list[str]) -> list[str]:
    """Prefixes not contained in another prefix of the list (the covering set)."""
    idx: PrefixIndex[bool] = PrefixIndex()
    nets = sorted({net(p) for p in prefixes}, key=lambda n: (n.version, n.prefixlen))
    out = []
    for n in nets:
        if not idx.covering(n, include_self=False):
            out.append(str(n))
        idx.add(n, True)
    return out


# ---------------------------------------------------------------- AS paths
def has_as_set(path) -> bool:
    return any(isinstance(h, (list, tuple)) for h in path or [])


def clean_path(path: list) -> list[int]:
    """Collapse prepending (4788 4788 -> 4788). Callers that reason about adjacency must first
    check has_as_set(): an AS_SET hides the real sequence, so neighbours across it are not adjacent."""
    out: list[int] = []
    for hop in path or []:
        if isinstance(hop, (list, tuple)):
            continue
        h = int(hop)
        if not out or out[-1] != h:
            out.append(h)
    return out


def origin_of(path: list) -> int | None:
    """Origin AS for *detection*: the last AS, or the only member of a one-element AS_SET.
    A multi-member AS_SET origin is ambiguous -> None. (RPKI validation is stricter: any
    AS_SET origin is NONE per RFC 6811; see rov_origin.)"""
    if not path:
        return None
    last = path[-1]
    if isinstance(last, (list, tuple)):
        return int(last[0]) if len(last) == 1 else None
    return int(last)


def rov_origin(path: list) -> int | None:
    """Origin AS for RFC 6811 route origin validation: None if the path ends in an AS_SET."""
    if not path or isinstance(path[-1], (list, tuple)):
        return None
    return int(path[-1])


def is_poisoned(cpath: list[int]) -> bool:
    """AS-path poisoning: the origin also appears earlier, non-adjacently (e.g. 3356 4788 174 4788).
    Used legitimately for traffic engineering; adjacency-based checks are unreliable on such paths."""
    return len(cpath) >= 3 and cpath[-1] in cpath[:-2]


def upstream_of(path: list) -> int | None:
    """The AS adjacent to the origin (None if unknowable: AS_SET present or path too short)."""
    if has_as_set(path):
        return None
    p = clean_path(path)
    return p[-2] if len(p) >= 2 else None
