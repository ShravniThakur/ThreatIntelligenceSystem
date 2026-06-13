"""
campaign_store.py — fraud-campaign clustering over ANALYZED APKs.
================================================================

Answers a different question from the DNA component. DNA asks "which known
malware *family* does this resemble?" (against seeded MalwareBazaar labels).
The campaign store asks "which *other APKs we have analyzed* is this one grouped
with?" — i.e. is there a fraud group repackaging the same base app? It uses ONLY
analyzed↔analyzed relationships; malware-family labels are deliberately NOT a
clustering criterion (that's the DNA component's job).

Cold start (by design)
----------------------
The store starts empty of relationships. The FIRST analyzed APK is recorded as a
singleton (no peer to compare to). From the SECOND APK onward, each new APK is
compared pairwise against every previously-analyzed APK; any edge that passes a
threshold links them into the same campaign. A campaign = a connected component of
>= 2 analyzed APKs.

Edge rules (any ONE links two analyzed APKs)
--------------------------------------------
    * structural cosine >= COSINE_EDGE          (structural twins; reuses the
                                                  fingerprint vectors in dna_fingerprints)
    * DEX-TLSH distance <= TLSH_EDGE             (byte-level repackaged clone)
    * identical signing-cert fingerprint        (same actor signed both)
    * a shared non-benign domain                (same C2 / infrastructure)

Domains are filtered through feature_store_pipeline._is_benign_infra so shared
OS/CDN hosts (google, gstatic, …) never link unrelated apps.

Never raises: the orchestrator (:func:`analyze_campaign`) returns a CampaignResult
with ``error`` set on any failure.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import dna_fingerprint as dna   # reuse vector store + cosine/tlsh helpers
import intent_spoof             # reuse extract_cert_fingerprint

try:
    from feature_store_pipeline import _is_benign_infra
except Exception:  # noqa: BLE001 - fall back to a permissive filter if unavailable
    def _is_benign_infra(domain: str) -> bool:  # type: ignore
        return False

DB_PATH = dna.DB_PATH

# Edge thresholds (tunable). Deliberately strict so a campaign means "almost
# certainly the same actor/base", not "vaguely similar".
COSINE_EDGE = 0.92      # structural-twin cosine cut
TLSH_EDGE = 50          # DEX-TLSH distance cut (<= => repackaged clone)


# --------------------------------------------------------------------------- #
# Result dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class CampaignEdge:
    """A direct link from the queried APK to one campaign peer, with the why."""

    other_hash: str
    other_package: str
    reasons: List[str] = field(default_factory=list)
    strength: float = 0.0          # for ordering links (higher = stronger)


@dataclass
class CampaignResult:
    """The campaign membership for one analyzed APK."""

    is_campaign: bool = False              # True when the cluster has >= 2 members
    campaign_id: str = ""                  # stable-ish id derived from members
    size: int = 1                          # members in this APK's cluster
    members: List[Dict[str, str]] = field(default_factory=list)  # [{apk_hash, package_name}]
    links: List[CampaignEdge] = field(default_factory=list)      # direct edges from this APK
    total_analyzed: int = 0                # APKs in the whole store
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Schema + storage (this module owns campaign_apks; vectors live in dna_fingerprints)
# --------------------------------------------------------------------------- #

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS campaign_apks (
    apk_hash         TEXT PRIMARY KEY,
    package_name     TEXT,
    cert_fingerprint TEXT,
    domains          TEXT,          -- JSON list of non-benign domains
    analyzed_at      TEXT NOT NULL
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(_CREATE_TABLE)
    conn.commit()


def record(conn: sqlite3.Connection, apk_hash: str, package_name: str,
           cert_fingerprint: str, domains: List[str]) -> None:
    """Upsert one analyzed APK's campaign signals (package / cert / domains)."""
    conn.execute(
        """
        INSERT OR REPLACE INTO campaign_apks
            (apk_hash, package_name, cert_fingerprint, domains, analyzed_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (apk_hash, package_name or "", (cert_fingerprint or "").lower(),
         json.dumps(sorted(set(domains or []))),
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


# --------------------------------------------------------------------------- #
# Static-report extraction of campaign signals
# --------------------------------------------------------------------------- #


def extract_signals(static_json: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Pull (cert_fingerprint, non-benign domains) from a MobSF static report."""
    static_json = static_json or {}
    cert = static_json.get("certificate_analysis") or {}
    cert_info = cert.get("certificate_info", "") if isinstance(cert, dict) else ""
    fp = intent_spoof.extract_cert_fingerprint(cert_info)

    domains_raw = static_json.get("domains")
    domains: List[str] = []
    if isinstance(domains_raw, dict):
        for d in domains_raw.keys():
            if isinstance(d, str) and d and not _is_benign_infra(d):
                domains.append(d.lower())
    return fp, domains


# --------------------------------------------------------------------------- #
# The clustering pass (brute-force pairwise; connected components)
# --------------------------------------------------------------------------- #


@dataclass
class _Node:
    apk_hash: str
    package: str
    cert: str
    domains: Set[str]
    vector: Any = None        # np.ndarray or None
    dex_tlsh: Optional[str] = None


def _load_nodes(conn: sqlite3.Connection) -> Dict[str, _Node]:
    """Join campaign_apks with the analyzed fingerprints in dna_fingerprints."""
    nodes: Dict[str, _Node] = {}
    for h, pkg, cert, dom_json in conn.execute(
        "SELECT apk_hash, package_name, cert_fingerprint, domains FROM campaign_apks"
    ):
        try:
            doms = set(json.loads(dom_json) if dom_json else [])
        except (ValueError, TypeError):
            doms = set()
        nodes[h] = _Node(apk_hash=h, package=pkg or "", cert=(cert or ""), domains=doms)

    # Attach structural vectors + DEX-TLSH from the analyzed DNA fingerprints.
    try:
        for h, blob, dtlsh in conn.execute(
            "SELECT apk_hash, feature_vector, dex_tlsh FROM dna_fingerprints "
            "WHERE label_source = 'analyzed'"
        ):
            n = nodes.get(h)
            if n is None:
                continue
            if blob is not None and dna._HAVE_NUMPY:
                try:
                    n.vector = dna._deserialize(blob)
                except Exception:  # noqa: BLE001
                    n.vector = None
            n.dex_tlsh = dtlsh
    except sqlite3.Error:
        pass
    return nodes


def _edge_reasons(a: _Node, b: _Node) -> Tuple[List[str], float]:
    """Return (reasons, strength) if a and b should be linked, else ([], 0)."""
    reasons: List[str] = []
    strength = 0.0

    # Same signing certificate — strongest single signal (same actor).
    if a.cert and b.cert and a.cert == b.cert:
        reasons.append("same signing certificate")
        strength = max(strength, 1.0)

    # Shared non-benign domain (same C2 / infrastructure).
    shared = sorted(a.domains & b.domains)
    if shared:
        reasons.append("shared domain: " + ", ".join(shared[:3]))
        strength = max(strength, 0.85)

    # DEX byte-clone (repackage).
    d = dna._tlsh_diff(a.dex_tlsh, b.dex_tlsh)
    if d is not None and d <= TLSH_EDGE:
        reasons.append(f"DEX byte-clone (TLSH {d})")
        strength = max(strength, 1.0 - d / 100.0)

    # Structural twins (cosine over the fingerprint vectors).
    if a.vector is not None and b.vector is not None and dna._HAVE_NUMPY:
        sim = dna._cosine(a.vector, b.vector)
        if sim >= COSINE_EDGE:
            reasons.append(f"structural twin (cosine {sim:.2f})")
            strength = max(strength, float(sim))

    return reasons, strength


def _cluster(nodes: Dict[str, _Node]
             ) -> Tuple[Dict[str, Set[str]], Dict[Tuple[str, str], Tuple[List[str], float]]]:
    """Build the edge set and adjacency over all analyzed APKs (brute-force pairwise)."""
    hashes = list(nodes.keys())
    adjacency: Dict[str, Set[str]] = {h: set() for h in hashes}
    edges: Dict[Tuple[str, str], Tuple[List[str], float]] = {}
    for i in range(len(hashes)):
        for j in range(i + 1, len(hashes)):
            hi, hj = hashes[i], hashes[j]
            reasons, strength = _edge_reasons(nodes[hi], nodes[hj])
            if reasons:
                adjacency[hi].add(hj)
                adjacency[hj].add(hi)
                edges[(hi, hj)] = (reasons, strength)
    return adjacency, edges


def _component(adjacency: Dict[str, Set[str]], start: str) -> Set[str]:
    """Connected component containing ``start`` (BFS)."""
    seen, stack = {start}, [start]
    while stack:
        cur = stack.pop()
        for nb in adjacency.get(cur, ()):
            if nb not in seen:
                seen.add(nb)
                stack.append(nb)
    return seen


def campaign_for(conn: sqlite3.Connection, apk_hash: str) -> CampaignResult:
    """Compute the campaign (cluster) containing ``apk_hash``. Never raises."""
    try:
        nodes = _load_nodes(conn)
        total = len(nodes)
        if apk_hash not in nodes:
            return CampaignResult(total_analyzed=total)

        adjacency, edges = _cluster(nodes)
        comp = _component(adjacency, apk_hash)

        members = [{"apk_hash": h, "package_name": nodes[h].package} for h in sorted(comp)]
        # Direct links from this APK -> peers, with the reasons.
        links: List[CampaignEdge] = []
        for peer in sorted(adjacency.get(apk_hash, set())):
            key = (apk_hash, peer) if (apk_hash, peer) in edges else (peer, apk_hash)
            reasons, strength = edges.get(key, ([], 0.0))
            links.append(CampaignEdge(
                other_hash=peer, other_package=nodes[peer].package,
                reasons=reasons, strength=round(strength, 3)))
        links.sort(key=lambda e: e.strength, reverse=True)

        campaign_id = "campaign-" + min(comp)[:12] if len(comp) >= 2 else ""
        return CampaignResult(
            is_campaign=len(comp) >= 2,
            campaign_id=campaign_id,
            size=len(comp),
            members=members,
            links=links,
            total_analyzed=total,
        )
    except Exception as exc:  # noqa: BLE001
        return CampaignResult(error=f"campaign clustering failed: {exc}")


# --------------------------------------------------------------------------- #
# Orchestrator for the live pipeline (never raises)
# --------------------------------------------------------------------------- #


def analyze_campaign(apk_hash: str, package_name: str, static_json: Dict[str, Any],
                     db_path: str = DB_PATH) -> CampaignResult:
    """Record this APK's campaign signals, then return the campaign it belongs to.

    Records FIRST (so a freshly-analyzed APK is part of the graph), then clusters.
    The first-ever APK comes back as a singleton (is_campaign=False); from the
    second APK onward, edges can form. Degrades to error field, never raises.
    """
    conn = None
    try:
        cert_fp, domains = extract_signals(static_json)
        conn = sqlite3.connect(db_path)
        ensure_schema(conn)
        dna.ensure_schema(conn)   # ensure the dna_fingerprints table exists for the join
        record(conn, apk_hash, package_name, cert_fp, domains)
        return campaign_for(conn, apk_hash)
    except Exception as exc:  # noqa: BLE001 - campaign must never crash the job
        return CampaignResult(error=f"campaign step failed: {exc}")
    finally:
        if conn is not None:
            conn.close()


# --------------------------------------------------------------------------- #
# __main__ — list all campaigns currently in the store
# --------------------------------------------------------------------------- #


def main() -> int:
    conn = sqlite3.connect(DB_PATH)
    ensure_schema(conn)
    nodes = _load_nodes(conn)
    if not nodes:
        print("campaign_apks is empty — analyze some APKs first.")
        return 0
    adjacency, _edges = _cluster(nodes)
    seen: Set[str] = set()
    campaigns = []
    for h in nodes:
        if h in seen:
            continue
        comp = _component(adjacency, h)
        seen |= comp
        if len(comp) >= 2:
            campaigns.append(sorted(comp))
    print(f"{len(nodes)} analyzed APK(s); {len(campaigns)} campaign(s) of >= 2 members:")
    for comp in campaigns:
        print(f"\n  campaign-{min(comp)[:12]}  ({len(comp)} members):")
        for h in comp:
            print(f"    {h[:16]}  {nodes[h].package}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
