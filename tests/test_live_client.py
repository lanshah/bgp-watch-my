"""RIS Live client against a local fake server: subscription format, recording, reconnect."""
import asyncio
import gzip
import json

import websockets

from bgpwatch.live import Recorder, run_live

MSG = {"type": "ris_message", "data": {"timestamp": 1.0, "peer": "192.0.2.1", "peer_asn": "65100", "id": "1",
                                       "host": "rrc90.synthetic", "type": "UPDATE", "path": [65100, 64500],
                                       "announcements": [{"next_hop": "192.0.2.1", "prefixes": ["198.18.0.0/22"]}]}}


def test_subscribe_record_and_reconnect(tmp_path):
    seen_subs, connections = [], []

    async def handler(ws):
        connections.append(1)
        for _ in range(2):
            seen_subs.append(json.loads(await ws.recv()))
        await ws.send(json.dumps({"type": "ris_subscribe_ok", "data": {}}))
        msg = json.loads(json.dumps(MSG))
        msg["data"]["id"] = str(len(connections))
        await ws.send(json.dumps(msg))
        await ws.send(json.dumps(msg))       # duplicate (matched two subscriptions) -> dropped
        await ws.send("not json at all")      # malformed frame -> counted, stream continues
        if len(connections) == 1:
            await ws.close()          # force one reconnect
            return
        await asyncio.sleep(5)

    async def main():
        async with websockets.serve(handler, "127.0.0.1", 0) as srv:
            port = srv.sockets[0].getsockname()[1]
            got = []
            rec = Recorder(tmp_path)
            stats = await run_live(f"ws://127.0.0.1:{port}/v1/ws/", "test-client", ["198.18.0.0/15"], got.append,
                                   lambda now: None, rec, duration_s=3, tick_s=0.5, log=lambda *_: None)
            return got, stats, rec

    got, stats, rec = asyncio.run(main())
    assert stats["connects"] == 2 and stats["disconnects"] >= 1
    assert stats["duplicates"] == 2 and stats["bad_messages"] == 2
    assert len(got) == 2 and got[0]["data"]["id"] == "1"
    upd = seen_subs[0]
    assert upd["type"] == "ris_subscribe" and upd["data"]["prefix"] == ["198.18.0.0/15"]
    assert upd["data"]["moreSpecific"] is True and upd["data"]["type"] == "UPDATE"
    assert seen_subs[1]["data"] == {"type": "RIS_PEER_STATE"}
    lines = [l for f in rec.files for l in gzip.open(f, "rt", encoding="utf-8")]
    assert len(lines) == 2 and json.loads(lines[0])["data"]["id"] == "1"
