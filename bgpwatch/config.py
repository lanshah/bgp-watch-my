"""Configuration loading (TOML, standard library only)."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "config" / "bgpwatch.toml"

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class NetworkCfg:
    key: str
    name: str
    primary_asn: int
    sibling_asns: list[int]
    holder_keywords: list[str]

    @property
    def all_asns(self) -> list[int]:
        return [self.primary_asn, *self.sibling_asns]


@dataclass
class Config:
    raw: dict
    path: Path
    networks: list[NetworkCfg] = field(default_factory=list)

    # convenience accessors -------------------------------------------------
    @property
    def client_name(self) -> str:
        return self.raw["client"]["name"]

    @property
    def user_agent(self) -> str:
        return self.raw["client"]["user_agent"]

    @property
    def sources(self) -> dict:
        return self.raw["sources"]

    @property
    def detect(self) -> dict:
        return self.raw["detect"]

    @property
    def alerts(self) -> dict:
        return self.raw["alerts"]

    @property
    def web(self) -> dict:
        return self.raw["web"]

    def data_path(self, rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else ROOT / p

    @property
    def db_path(self) -> Path:
        return self.data_path(self.raw["storage"]["db_path"])

    @property
    def recordings_dir(self) -> Path:
        return self.data_path(self.raw["storage"]["recordings_dir"])

    @property
    def data_dir(self) -> Path:
        return ROOT / "data"


def load_config(path: str | os.PathLike | None = None) -> Config:
    p = Path(path) if path else DEFAULT_CONFIG
    with open(p, "rb") as fh:
        raw = tomllib.load(fh)
    nets = [
        NetworkCfg(
            key=n["key"],
            name=n["name"],
            primary_asn=int(n["primary_asn"]),
            sibling_asns=[int(a) for a in n.get("sibling_asns", [])],
            holder_keywords=[k.upper() for k in n.get("holder_keywords", [])],
        )
        for n in raw.get("network", [])
    ]
    return Config(raw=raw, path=p, networks=nets)


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env reader (KEY=VALUE lines). Existing environment variables win."""
    p = path or ROOT / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
