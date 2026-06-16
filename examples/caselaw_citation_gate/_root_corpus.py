"""_root_corpus.py -- producer-side trust-root corpus rooter (NETWORK-TOUCHING, run once).

This is the "rooter" box in the credibility-gate seam (see README + the integration
assessment): it turns the reporter cites of patent_redhat_kb shard 01 into a
VERBATIM-rooted court-record corpus by resolving each cite against CourtListener
and capturing the actual opinion text as the misquote yardstick.

WHY THIS EXISTS (the load-bearing fix over caselaw_citation_gate_minimal):
  The _minimal pilot's `holding_text` was a human PARAPHRASE, so its misquote check
  verified one producer's quote against another producer's paraphrase -- the
  circularity flagged in CREDIBILITY_GATE_VKERNEL_INTEGRATION_ASSESSMENT.md ("the
  load-bearing open question"). Here the yardstick is a VERBATIM SPAN of the court's
  own opinion text, fetched from CourtListener and frozen with provenance. The gate
  then proves "the producer's quote appears verbatim in the real opinion," not
  "matches our summary of it."

WHAT IT IS / IS NOT:
  - It IS the corpus-rooter + provenance capture. Run ONCE; its output
    (corpus/rooted_records.json + human_root_queue.json) is committed frozen
    evidence. The verifier (verify.py) NEVER touches the network.
  - It is NOT in the verified path. Re-derivation runs offline over the frozen
    corpus. This tool's trustworthiness is a trust-root concern; the
    provenance fields (cluster_id, opinion_id, absolute_url, retrieved_at) make
    each rooted record auditable back to CourtListener.

RESOLUTION PATHS (two independent authorities + a disambiguation fix):
  The first cut of this rooter accepted ONLY citation-lookup status==200 and routed
  Alice + Bilski to the human queue as "UNRESOLVED_BY_COURTLISTENER". That was too
  strict, and the framing slightly overstated the gap (self-correction, 2026-06-01):

    1. 300-DISAMBIGUATION (CourtListener-internal). A cite can return HTTP 300
       (Multiple Choices) carrying several candidate clusters. When EVERY candidate
       agrees on normalized (case_name, date_filed) it is a DUPLICATE-cluster import
       of one case, not a genuine ambiguity -- safe to accept (pick the cluster whose
       opinion yields the most verbatim text). Alice's U.S. cite (573 U.S. 208) still
       404s, but its S.Ct. PARALLEL cite (134 S. Ct. 2347) returns a 300 whose two
       candidates are both "Alice Corp. v. CLS Bank Int'l" 2014-06-19 -> rooted. Bilski
       likewise. So neither was ever truly unrootable; the acceptance rule was.

    2. CAP / HARVARD INDEPENDENT AUTHORITY (the "alternate authority" the queue note
       asked for). A SECOND, organizationally-independent rooting source: the Caselaw
       Access Project's official bound-reporter digitization (static.case.law, Harvard
       2018 batch, no auth). For every U.S.-Reports authority we also attempt a CAP
       root and attach it as an `additional_roots` entry -- independent corroboration
       that the cite genuinely maps to that case. CAP roots Bilski (vol 561) and Mayo
       (vol 566); it CANNOT root Alice, whose volume 573 is exactly ONE past CAP's
       coverage (max U.S. vol = 572). That coverage edge is itself the trust-root lesson:
       no single authority -- not even the official-reporter digitization -- is
       complete. Alice is therefore single-rooted (CourtListener only), flagged honestly.

GAP HANDLING (the original fix over the daemon's `404 -> REJECT` survives):
  An authority that resolves on NEITHER path is still NOT rejected and NOT fabricated
  into the corpus. It routes to human_root_queue.json with reason UNRESOLVED, to be
  rooted from official reporters / PACER by a human -- the honest "the rooting itself
  is a human trust-root" posture. After this change the §101 queue is empty, but the
  mechanism remains and the CAP coverage edge proves it can be non-empty in general.

RATE LIMITS:
  CourtListener's citation-lookup endpoint is throttled to 50/hour, so ALL cites
  (primary + parallel) go in ONE batched POST. Opinion text fetches use the
  higher-limit opinions endpoint. CAP static files are unthrottled CDN GETs. Raw
  responses cache to _root_cache/ (gitignored) so re-runs do not re-spend the budget.

Usage (token in a gitignored .env beside this file, or COURTLISTENER_TOKEN in env):
    python examples/caselaw_citation_gate/_root_corpus.py
    python examples/caselaw_citation_gate/_root_corpus.py --refresh   # ignore cache
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_CACHE = _HERE / "_root_cache"
_KB_CITES = _HERE / "kb_citations.json"
_CORPUS_OUT = _HERE / "corpus" / "rooted_records.json"
_QUEUE_OUT = _HERE / "human_root_queue.json"

_CL_BASE = "https://www.courtlistener.com"
_LOOKUP_URL = f"{_CL_BASE}/api/rest/v4/citation-lookup/"
_USER_AGENT = "NEXI-VKernel-caselaw-rooter/0.1 (research; contact max@neximedia.ai)"

# Caselaw Access Project (Harvard) -- the independent second authority. Static CDN,
# no auth. Layout: /{reporter_slug}/VolumesMetadata.json, /{slug}/{vol}/CasesMetadata.json
# (per-volume case index), /{slug}/{vol}/cases/{file_name}.json (full case + casebody).
_CAP_BASE = "https://static.case.law"
# Pattern for a U.S.-Reports cite "<vol> U.S. <page>" -> (vol, page). Only this
# reporter is CAP-cross-rooted here; Federal Reporter cross-rooting is the scale path.
_US_CITE = re.compile(r"^\s*(\d+)\s+U\.\s?S\.\s+(\d+)\s*$")


# ---------------------------------------------------------------------------
# Token + low-level HTTP (stdlib only)
# ---------------------------------------------------------------------------


def _load_token() -> str:
    import os  # noqa: PLC0415

    tok = os.environ.get("COURTLISTENER_TOKEN", "").strip()
    if tok:
        return tok
    env = _HERE / ".env"
    if env.is_file():
        for line in env.read_text().splitlines():
            if line.startswith("COURTLISTENER_TOKEN="):
                return line.split("=", 1)[1].strip()
    print("ERROR: no COURTLISTENER_TOKEN in env or .env beside this script.", file=sys.stderr)
    sys.exit(2)


def _get_json(url: str, token: str, retries: int = 3) -> tuple[int, object]:
    req = urllib.request.Request(
        url, method="GET",
        headers={"Authorization": f"Token {token}", "User-Agent": _USER_AGENT},
    )
    return _send(req, retries)


def _get_json_noauth(url: str, retries: int = 3) -> tuple[int, object]:
    """Plain GET (no Authorization header) -- for the public CAP static CDN."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _USER_AGENT})
    return _send(req, retries)


def _post_json(url: str, token: str, form: dict, retries: int = 3) -> tuple[int, object]:
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Authorization": f"Token {token}",
            "User-Agent": _USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    return _send(req, retries)


def _send(req: urllib.request.Request, retries: int) -> tuple[int, object]:
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if e.code == 429 and attempt < retries - 1:
                m = re.search(r"available in (\d+) seconds", body)
                wait = int(m.group(1)) + 2 if m else 60
                print(f"  throttled (429); waiting {wait}s then retrying...", file=sys.stderr)
                time.sleep(wait)
                continue
            try:
                return e.code, json.loads(body)
            except json.JSONDecodeError:
                return e.code, body[:500]
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < retries - 1:
                time.sleep(5)
                continue
            return 0, str(e)
    return 0, "exhausted retries"


# ---------------------------------------------------------------------------
# Opinion text extraction
# ---------------------------------------------------------------------------

_TAG = re.compile(r"<[^>]+>")


def _best_text(op: dict) -> tuple[str, str]:
    """Pick the best available verbatim text field from an opinion resource.

    Returns (text, source_field). Prefers plain_text; falls back through the
    HTML/XML fields with tags stripped. The court's own words either way.
    """
    if op.get("plain_text", "").strip():
        return op["plain_text"], "plain_text"
    for field in ("html_with_citations", "html", "html_lawbox", "html_columbia", "xml_harvard"):
        raw = op.get(field) or ""
        if raw.strip():
            text = _TAG.sub("", raw)
            text = re.sub(r"&[a-z]+;", " ", text)
            return text, field
    return "", "none"


# ---------------------------------------------------------------------------
# CourtListener cluster disambiguation (the 300-multiple-choices fix)
# ---------------------------------------------------------------------------


def _cluster_identity(cluster: dict) -> tuple[str, str]:
    """Normalized (case_name, date_filed) -- the identity two candidate clusters
    must share for a 300 to count as a duplicate-import, not a real ambiguity."""
    name = " ".join(str(cluster.get("case_name") or "").casefold().split())
    return name, str(cluster.get("date_filed") or "")


def _accept_clusters(item: dict) -> tuple[list[dict], str] | None:
    """Decide whether a citation-lookup item is safely resolvable, returning
    (candidate_clusters, resolution_tag) or None.

      status 200 with clusters         -> accept, "citation_lookup_200"
      status 300 (Multiple Choices)    -> accept ONLY if every candidate cluster
        with >=2 unanimous clusters       shares one normalized (case_name,
                                          date_filed) -> "citation_lookup_300_disambiguated"
      anything else                    -> None (route to human queue)

    A 300 whose candidates disagree on identity is a GENUINE ambiguity and is NOT
    auto-resolved -- it stays a gap (honest).
    """
    clusters = item.get("clusters") or []
    if not clusters:
        return None
    status = item.get("status")
    if status == 200:
        return clusters, "citation_lookup_200"
    if status == 300:
        identities = {_cluster_identity(c) for c in clusters}
        if len(identities) == 1:
            return clusters, "citation_lookup_300_disambiguated"
    return None


# ---------------------------------------------------------------------------
# Caselaw Access Project (Harvard) -- the independent second authority
# ---------------------------------------------------------------------------

_cap_volmax_cache: dict[str, int] = {}


def _cap_volume_max(slug: str, refresh: bool = False) -> int | None:
    """Highest digitized volume number for a CAP reporter (e.g. 572 for 'us').
    Cached on disk; used to distinguish 'beyond coverage' from a transient miss."""
    if slug in _cap_volmax_cache:
        return _cap_volmax_cache[slug]
    cache_name = f"cap_{slug}_volumes.json"
    vols = None if refresh else _cache_read(cache_name)
    if vols is None:
        st, vols = _get_json_noauth(f"{_CAP_BASE}/{slug}/VolumesMetadata.json")
        if st != 200 or not isinstance(vols, list):
            return None
        _cache_write(cache_name, vols)
    nums = [int(v["volume_number"]) for v in vols if str(v.get("volume_number", "")).isdigit()]
    if not nums:
        return None
    _cap_volmax_cache[slug] = max(nums)
    return _cap_volmax_cache[slug]


def _cap_text(case: dict) -> tuple[str, int]:
    """Concatenate every opinion's verbatim text from a CAP case record.
    Returns (text, n_opinions)."""
    cb = case.get("casebody") or {}
    ops = cb.get("opinions") or []
    parts = [op.get("text", "") for op in ops if (op.get("text") or "").strip()]
    return "\n\n".join(parts), len(ops)


def _cap_root(slug: str, vol: int, page: int, official_cite: str,
              refresh: bool = False) -> dict | None:
    """Attempt to root one U.S.-Reports authority from the CAP static CDN.

    Returns an `additional_roots` entry (authority='caselaw_access_project') with the
    verbatim opinion text + provenance, or None if CAP does not carry it (e.g. the
    volume is beyond coverage, or no case at that page matches the official cite).
    Identity is checked by matching `official_cite` in the CAP record's citations.
    """
    meta_name = f"cap_{slug}_{vol}_cases.json"
    meta = None if refresh else _cache_read(meta_name)
    if meta is None:
        st, meta = _get_json_noauth(f"{_CAP_BASE}/{slug}/{vol}/CasesMetadata.json")
        if st != 200 or not isinstance(meta, list):
            return None
        _cache_write(meta_name, meta)

    norm_cite = " ".join(official_cite.split())
    entry = None
    for e in meta:
        cites = {" ".join(str(c.get("cite", "")).split()) for c in e.get("citations", [])}
        if norm_cite in cites and str(e.get("first_page")) == str(page):
            entry = e
            break
    if entry is None:
        return None

    file_name = entry["file_name"]
    case_name = f"cap_{slug}_{vol}_{file_name}.json"
    case = None if refresh else _cache_read(case_name)
    if case is None:
        st, case = _get_json_noauth(f"{_CAP_BASE}/{slug}/{vol}/cases/{file_name}.json")
        if st != 200 or not isinstance(case, dict):
            return None
        _cache_write(case_name, case)

    text, n_ops = _cap_text(case)
    if not text.strip():
        return None
    prov = case.get("provenance") or {}
    return {
        "authority": "caselaw_access_project",
        "resolved_via": official_cite,
        "case_name": case.get("name_abbreviation") or entry.get("name_abbreviation"),
        "date_filed": case.get("decision_date"),
        "rooted_text": text,
        "rooted_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "rooted_text_len": len(text),
        "provenance": {
            "source": "caselaw_access_project",
            "cap_case_id": case.get("id"),
            "reporter_slug": slug,
            "volume": vol,
            "first_page": page,
            "case_url": f"{_CAP_BASE}/{slug}/{vol}/cases/{file_name}.json",
            "n_opinions": n_ops,
            "cap_batch": prov.get("batch"),
            "cap_source": prov.get("source"),
        },
    }


def _cap_cross_root(authority: dict, primary_cite: str, refresh: bool) -> tuple[list[dict], str | None]:
    """For one KB authority, attempt CAP roots over its U.S.-Reports cites.

    Returns (additional_roots, cap_status). cap_status is set to
    "beyond_cap_coverage" when a U.S. cite's volume exceeds CAP's coverage (the Alice
    case), None when CAP rooted it or when the authority has no U.S. cite to try.
    """
    roots: list[dict] = []
    status: str | None = None
    tried = [authority["reporter_cite"], *authority.get("parallel_cites", [])]
    for cite in tried:
        m = _US_CITE.match(cite)
        if not m:
            continue
        vol, page = int(m.group(1)), int(m.group(2))
        volmax = _cap_volume_max("us", refresh=refresh)
        if volmax is not None and vol > volmax:
            status = "beyond_cap_coverage"
            print(f"    [CAP]  {authority['id']:<11} {cite:<16} vol {vol} > CAP max {volmax} (beyond coverage)")
            continue
        root = _cap_root("us", vol, page, cite, refresh=refresh)
        if root is not None:
            roots.append(root)
            print(f"    [CAP]  {authority['id']:<11} {cite:<16} -> rooted "
                  f"({root['rooted_text_len']} chars, batch {root['provenance'].get('cap_batch')})")
    return roots, status


# ---------------------------------------------------------------------------
# Rooting
# ---------------------------------------------------------------------------


def _cache_read(name: str):
    p = _CACHE / name
    if p.is_file():
        return json.loads(p.read_text())
    return None


def _cache_write(name: str, obj) -> None:
    _CACHE.mkdir(parents=True, exist_ok=True)
    (_CACHE / name).write_text(json.dumps(obj, indent=2))


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_record(authority: dict, cites: list[str], resolved_via: str,
                 primary_text: str, primary_source: str, primary_provenance: dict,
                 additional_roots: list[dict], cap_status: str | None) -> dict:
    """Assemble one corpus record.

    `reporter_cite` is the KB's CANONICAL primary cite (what producers cite); `cites`
    is every cite the authority is reachable by (primary + parallels), so the verifier
    can match a producer who cites any parallel. `resolved_via` is the cite that
    actually resolved the PRIMARY root. `rooted_text` (the misquote yardstick) is the
    primary authority's verbatim opinion; `additional_roots` lists independent
    corroborating authorities (e.g. CAP) -- present so a fabricated cite would have to
    deceive TWO unrelated digitizations, the trust-root multi-root signal.
    """
    rec = {
        "record_id": authority["id"],
        "reporter_cite": authority["reporter_cite"],
        "cites": cites,
        "resolved_via": resolved_via,
        "case_name": authority["case_name"],
        "date_filed": primary_provenance.get("date_filed"),
        "year": authority.get("year"),
        "rooted_text": primary_text,
        "rooted_text_sha256": hashlib.sha256(primary_text.encode("utf-8")).hexdigest(),
        "rooted_text_len": len(primary_text),
        "provenance": primary_provenance,
        "root_count": 1 + len(additional_roots),
        "additional_roots": additional_roots,
    }
    if cap_status:
        rec["cap_status"] = cap_status
    return rec


def root_corpus(refresh: bool = False) -> int:
    token = _load_token()
    kb = json.loads(_KB_CITES.read_text())
    authorities = kb["authorities"]

    # --- 1. ONE batched citation-lookup for every cite we will try ---------
    all_cites: list[str] = []
    for a in authorities:
        all_cites.append(a["reporter_cite"])
        all_cites.extend(a.get("parallel_cites", []))
    text_blob = "; ".join(all_cites)

    lookup = None if refresh else _cache_read("lookup.json")
    if lookup is None:
        print(f"citation-lookup: 1 batched POST for {len(all_cites)} cites ...")
        status, lookup = _post_json(_LOOKUP_URL, token, {"text": text_blob})
        if status != 200:
            print(f"ERROR: citation-lookup returned {status}: {lookup}", file=sys.stderr)
            return 1
        _cache_write("lookup.json", lookup)
    else:
        print("citation-lookup: using cached _root_cache/lookup.json")

    # Index lookup results by normalized cite string.
    by_cite: dict[str, dict] = {}
    for item in lookup:
        for norm in item.get("normalized_citations", []) or [item.get("citation")]:
            by_cite[norm] = item
        by_cite[item.get("citation")] = item

    retrieved_at = _now_iso()
    rooted: list[dict] = []
    queue: list[dict] = []

    # --- 2. Per authority: resolve (200 or disambiguated 300), fetch opinion text,
    #        then attempt an independent CAP cross-root -----------------------
    for a in authorities:
        tried = [a["reporter_cite"], *a.get("parallel_cites", [])]
        candidates: list[dict] = []
        hit_cite = None
        resolution = None
        for cite in tried:
            accepted = _accept_clusters(by_cite.get(cite, {}))
            if accepted is not None:
                candidates, resolution = accepted
                hit_cite = cite
                break

        op_text, text_field, op_id, cluster_id, cluster_url = "", "none", None, None, ""
        cluster_date = None
        if candidates:
            # Iterate candidate clusters (a disambiguated 300 has >1) and their
            # sub-opinions until one yields usable verbatim text.
            for cluster in candidates:
                cluster_id = cluster.get("id")
                cluster_url = f"{_CL_BASE}{cluster.get('absolute_url', '')}"
                cluster_date = cluster.get("date_filed")
                for op_ref in (cluster.get("sub_opinions") or []):
                    op_url = op_ref if isinstance(op_ref, str) else op_ref.get("resource_uri")
                    full = op_url if op_url.startswith("http") else f"{_CL_BASE}{op_url}"
                    cache_name = f"opinion_{re.sub(r'[^0-9]', '', full.rstrip('/').split('/')[-1])}.json"
                    op = None if refresh else _cache_read(cache_name)
                    if op is None:
                        st, op = _get_json(full, token)
                        if st != 200:
                            print(f"    opinion fetch {full} -> {st}", file=sys.stderr)
                            continue
                        _cache_write(cache_name, op)
                    op_id = op.get("id")
                    op_text, text_field = _best_text(op)
                    if op_text.strip():
                        break
                if op_text.strip():
                    break

        # Independent CAP cross-root (runs regardless of CL outcome, for U.S. cites).
        cap_roots, cap_status = _cap_cross_root(a, a["reporter_cite"], refresh)

        if not op_text.strip():
            # No CourtListener text. If CAP rooted it, promote CAP to primary;
            # else route to the human queue (never auto-reject).
            if cap_roots:
                primary = cap_roots[0]
                others = cap_roots[1:]
                rooted.append(_make_record(a, tried, primary["resolved_via"],
                                           primary["rooted_text"], primary["provenance"]["source"],
                                           primary["provenance"], others, cap_status))
                print(f"  [ROOTED] {a['id']:<11} {primary['resolved_via']:<16} "
                      f"CAP-primary text={primary['rooted_text_len']:>7} chars")
                continue
            statuses = {c: (by_cite.get(c, {}).get("status")) for c in tried}
            queue.append({
                "id": a["id"], "case_name": a["case_name"], "cites_tried": tried,
                "courtlistener_status": statuses, "cap_status": cap_status,
                "reason": "UNRESOLVED",
                "disposition": "route_to_human_root",
                "note": "Resolved on neither CourtListener (200 or unanimous-300) nor "
                        "CAP. Root from official reporter / PACER by a human; do NOT "
                        "auto-reject.",
            })
            print(f"  [QUEUE]  {a['id']:<11} {a['reporter_cite']:<16} -> {statuses} cap={cap_status}")
            continue

        cl_prov = {
            "source": "courtlistener",
            "resolution": resolution,
            "cluster_id": cluster_id,
            "opinion_id": op_id,
            "cluster_url": cluster_url,
            "text_source_field": text_field,
            "date_filed": cluster_date,
            "retrieved_at": retrieved_at,
        }
        rooted.append(_make_record(a, tried, hit_cite, op_text, "courtlistener",
                                   cl_prov, cap_roots, cap_status))
        extra = (f" +{len(cap_roots)} CAP root" if cap_roots else
                 (f" (CAP {cap_status})" if cap_status else ""))
        print(f"  [ROOTED] {a['id']:<11} {hit_cite:<16} cluster={cluster_id} "
              f"text={len(op_text):>7} chars ({text_field}; {resolution}){extra}")

    # --- 3. Write committed evidence ---------------------------------------
    rooted.sort(key=lambda r: r["record_id"])
    queue.sort(key=lambda q: q["id"])
    _CORPUS_OUT.parent.mkdir(parents=True, exist_ok=True)
    _CORPUS_OUT.write_text(json.dumps(rooted, indent=2, ensure_ascii=False) + "\n")
    _QUEUE_OUT.write_text(json.dumps(queue, indent=2, ensure_ascii=False) + "\n")

    multi = sum(1 for r in rooted if r.get("root_count", 1) > 1)
    beyond = sum(1 for r in rooted if r.get("cap_status") == "beyond_cap_coverage")
    print(f"\nrooted {len(rooted)} / {len(authorities)} authorities "
          f"({len(queue)} -> human-root queue)")
    print(f"  multi-rooted (>=2 independent authorities): {multi}")
    print(f"  CAP coverage-edge (U.S. vol beyond CAP):    {beyond}")
    print(f"  corpus: {_CORPUS_OUT}")
    print(f"  queue : {_QUEUE_OUT}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Root the §101 KB corpus from CourtListener (200 + disambiguated "
                    "300) with an independent CAP/Harvard cross-root.")
    ap.add_argument("--refresh", action="store_true", help="ignore _root_cache and re-fetch")
    args = ap.parse_args()
    return root_corpus(refresh=args.refresh)


if __name__ == "__main__":
    sys.exit(main())
