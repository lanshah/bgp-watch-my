"""Plain-English explanations of incidents: why it fired, what it may mean, what to check."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

MYT = timezone(timedelta(hours=8), "MYT")


def _t(ts: float | None) -> str:
    """Malaysia time first (the operators' clock), UTC in brackets (BGP tooling's clock)."""
    if not ts:
        return "-"
    return (datetime.fromtimestamp(ts, MYT).strftime("%Y-%m-%d %H:%M:%S MYT")
            + datetime.fromtimestamp(ts, timezone.utc).strftime(" (%H:%M UTC)"))


def _asns(xs) -> str:
    xs = list(xs or [])
    return ", ".join(f"AS{x}" for x in xs[:12]) + (" ..." if len(xs) > 12 else "") if xs else "none"


def _path(p) -> str:
    return " ".join(str(h) if not isinstance(h, (list, tuple)) else "{" + ",".join(map(str, h)) + "}" for h in p or [])


def explain(inc: dict, network_name: str) -> dict:
    """Returns {"summary", "why", "meaning", "check", "limits"} as plain text."""
    k = inc["kind"]
    ev = inc.get("evidence", {})
    first = ev.get("first", {})
    pfx = inc.get("prefixes", [])
    n_pfx = len(pfx)
    peers = inc.get("peers", 0)
    total_peers = ev.get("ris_peers_total") or 0
    reach = f"{peers} RIS peer{'s' if peers != 1 else ''}" + (f" (of ~{total_peers} seeing this space)" if total_peers else "")
    actor = inc.get("actor_asn")
    rpki = first.get("rpki", {})
    pfx_txt = pfx[0] if n_pfx == 1 else f"{n_pfx} prefixes (e.g. {', '.join(pfx[:3])})"
    low_vis = peers < 3
    lv_note = (" Only a few RIS peers saw it, so it may be a single network's local view rather than a "
               "global event; severity is reduced until more peers confirm it.") if low_vis else ""

    private = actor is not None and (64512 <= actor <= 65534 or 4200000000 <= actor <= 4294967294 or actor == 23456)
    if private:
        lv_note += (f" AS{actor} is a private-use or placeholder ASN (RFC 6996 / AS_TRANS), which usually means an "
                    "internal route leaked by mistake rather than a deliberate hijack.")
    if k == "origin_change":
        exp = first.get("expected_origins", [])
        summary = f"{network_name}: {pfx_txt} announced by AS{actor} instead of {_asns(exp)}"
        why = (f"In the baseline, {pfx[0] if pfx else 'this prefix'} was originated only by {_asns(exp)}. "
               f"Starting {_t(inc['first_seen'])}, {reach} received it with origin AS{actor} "
               f"(example AS path: {_path(first.get('path'))}). Two different origins for one prefix is a "
               f"Multiple-Origin AS (MOAS) conflict. RPKI says: {rpki.get('text', 'n/a')}{lv_note}")
        other = first.get("other_watched_network")
        meaning = ("Possible prefix hijack or a misconfiguration (fat-finger) at AS%s. Traffic from networks that "
                   "prefer the new route goes to AS%s instead of %s." % (actor, actor, network_name))
        if other:
            meaning += f" AS{actor} belongs to another watched Malaysian network ({other}), so a planned transfer or shared customer is plausible."
        if rpki.get("state") == "valid":
            meaning += " A ROA authorises this origin, which points to a planned change (for example DDoS scrubbing or a migration)."
        check = ("Ask the prefix owner whether AS%s is authorised; look the prefix up in RIPEstat/bgp.tools; "
                 "check IRR route objects; if unauthorised, contact AS%s's NOC (PeeringDB) and announce "
                 "more-specifics only as a last resort." % (actor, actor))
    elif k == "more_specific_foreign":
        cov = first.get("covering_prefix")
        summary = f"{network_name}: AS{actor} announced more-specific {pfx_txt} inside {cov or 'watched space'}"
        why = (f"{pfx[0] if pfx else 'A prefix'} is inside {cov}, which belongs to {network_name} "
               f"(origins {_asns(first.get('covering_origins'))}). AS{actor} is not one of {network_name}'s ASNs and "
               f"was not seen announcing this prefix in the baseline. {reach} carried it, first at {_t(inc['first_seen'])} "
               f"(example AS path: {_path(first.get('path'))}). RPKI says: {rpki.get('text', 'n/a')}{lv_note}")
        meaning = ("BGP prefers the most specific route, so a sub-prefix hijack captures traffic even from networks "
                   "that still see the legitimate covering route. This is the most dangerous hijack type. "
                   "It can also be a customer with its own ASN announcing space delegated to it.")
        if rpki.get("state") == "valid":
            meaning += " A ROA authorises this origin and length, so a legitimate customer announcement is likely."
        check = ("Confirm with the address owner whether the space is delegated to AS%s; check the ROA and IRR; "
                 "compare with RIPEstat routing history." % actor)
    elif k == "more_specific_own":
        summary = f"{network_name}: new more-specific {pfx_txt} from its own AS{actor}"
        why = (f"{network_name}'s own AS{actor} started announcing {pfx_txt}, which were not in the baseline. "
               f"Seen by {reach}.")
        meaning = "Usually traffic engineering or de-aggregation (for example during DDoS mitigation). Informational."
        check = "No action unless unexpected; watch the RPKI state (a ROA maxLength that is too short makes these invalid)."
    elif k == "rpki_invalid":
        summary = f"{network_name}: own route {pfx_txt} is RPKI-invalid ({first.get('rpki', {}).get('reason')})"
        why = f"{rpki.get('text', '')} Seen by {reach} since {_t(inc['first_seen'])}."
        meaning = ("Networks that enforce Route Origin Validation (many large transit providers do) drop RPKI-invalid "
                   "routes, so this prefix may be unreachable from part of the Internet even though the "
                   "announcement itself is legitimate.")
        check = "Fix the ROA (origin AS or maxLength) in the RIR portal (APNIC MyAPNIC) or stop announcing the invalid more-specific."
    elif k == "route_leak":
        pat = first.get("pattern")
        if pat == "clique-sandwich":
            why = (f"In the AS path {_path(first.get('path'))}, AS{actor} sits between AS{first.get('left')} and "
                   f"AS{first.get('right')}, which are both members of the transit-free clique (CAIDA AS Rank). "
                   f"Clique members peer with each other directly and buy no transit, so a route travelling "
                   f"clique -> AS{actor} -> clique breaks the valley-free rule: AS{actor} re-announced a route learned "
                   f"from one provider/peer to another.")
        else:
            why = (f"CAIDA AS Rank infers AS{actor} to be a customer of the origin, yet in the AS path "
                   f"{_path(first.get('path'))} the route reaches the rest of the Internet through AS{actor}. "
                   f"A customer should only announce its own and its customers' routes upstream, not its provider's.")
        summary = f"{network_name}: possible route leak by AS{actor} affecting {pfx_txt}"
        why += f" Seen by {reach} since {_t(inc['first_seen'])}.{lv_note}"
        meaning = ("Traffic to %s may take a long detour through AS%s, adding latency or congestion, or be dropped. "
                   "Leaks are usually accidents (missing export filters)." % (network_name, actor))
        check = "Check latency/traceroutes towards the prefixes; contact AS%s's NOC; ask upstreams to filter." % actor
    elif k == "new_upstream":
        summary = f"{network_name}: AS{first.get('origin')} seen through new upstream AS{actor}"
        why = (f"In the baseline, AS{first.get('origin')} was reached through {_asns(first.get('baseline_upstreams'))}. "
               f"Now {reach} see it through AS{actor} (path {_path(first.get('path'))}), an adjacency that is neither in "
               f"the baseline nor in CAIDA's inferred relationships.{lv_note}")
        meaning = ("A new transit or peering link (often planned), a leak, or a forged-origin hijack where the "
                   "attacker prepends the real origin AS to its own announcement.")
        check = "Ask whether a new provider/peering was turned up; if not, treat it as a possible forged-path hijack."
    elif k == "unexpected_origination":
        owners = first.get("roa_asns") or []
        summary = f"{network_name}: AS{actor} originates {pfx_txt}, outside its known address space"
        why = (f"{network_name}'s AS{actor} was not announcing {pfx_txt} in the last two weeks of RIS data, but "
               f"{reach} now receive it from AS{actor} (path {_path(first.get('path'))}). RPKI says: "
               f"{rpki.get('text', 'n/a')}{lv_note}")
        meaning = ("If the ROA belongs to another network (%s), %s may be originating someone else's prefix: "
                   "a fat-fingered static route redistributed into BGP, or a leak of a customer's more-specific. "
                   "This is the reverse view of a hijack, with the watched network as the possible culprit."
                   % (_asns(owners), network_name))
        if rpki.get("state") == "not-found":
            meaning = ("A new prefix with no ROA. Often a new customer or a newly allocated block, but worth checking "
                       "that it really belongs to %s." % network_name)
        check = "Check the prefix's registry (whois/RIPEstat) and whether a new customer or allocation explains it."
    elif k == "path_anomaly":
        summary = f"{network_name}: unusually long AS path for {pfx_txt}"
        why = (f"The AS path {_path(first.get('path'))} has {first.get('path_len')} distinct ASes; the longest path in the "
               f"baseline for this prefix had {first.get('baseline_max_len')}.")
        meaning = "Could be a detour after a link failure, a route leak, or heavy prepending."
        check = "Compare with traceroutes; usually informational unless it persists."
    elif k == "visibility_drop":
        worst = ev.get("worst", {})
        summary = f"{network_name}: {pfx_txt} lost RIS visibility (worst {worst.get('ratio', 0):.0%})"
        why = (f"Each watched prefix is compared with the RIS peers that carried it in the baseline. "
               f"{worst.get('prefix', '')} dropped to {worst.get('seen')}/{worst.get('baseline')} peers "
               f"({worst.get('ratio', 0):.0%}), below the {first.get('warn', 0.6):.0%} threshold, and stayed there for "
               f"more than {first.get('hold_s', 180)} s (normal BGP convergence takes 1-3 minutes, so shorter dips are ignored). "
               f"Peers whose own BGP session to RIS went down are not counted against the prefix.")
        meaning = ("The prefix was withdrawn or a major upstream stopped carrying it: users on those prefixes may be "
                   "unreachable from part of the Internet. A drop for many prefixes of one network at once usually "
                   "means an outage or an upstream link failure.")
        check = "Check the network's upstream sessions and recent changes; test reachability (ping/traceroute) from outside; check other monitors (bgp.tools, Cloudflare Radar)."
    else:
        summary, why, meaning, check = inc.get("title", k), "", "", ""
    limits = ("BGP Watch only sees what RIPE RIS peers see (a few hundred networks), so local events can be missed "
              "and partial views can mislead. Baselines come from RIPEstat snapshots that are a few hours old. "
              "Route-leak checks rely on CAIDA's inferred relationships, which can be wrong or out of date. "
              "Treat alerts as leads to investigate, not proof.")
    return {"summary": summary, "why": why, "meaning": meaning, "check": check, "limits": limits}
