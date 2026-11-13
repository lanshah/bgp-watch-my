# 2-minute demo video script

Record with **Win + Alt + R** (Xbox Game Bar) or OBS. Use the offline replay so the demo works
on any day: real hijacks are rare, and you should never wait for one on camera.

**Before recording**

1. Run `start-demo.bat` once and let it finish, so you know the timing. The dashboard opens at
   http://127.0.0.1:8060.
2. Close other tabs, zoom the browser to 110 %, and hide the taskbar if you can.
3. Restart `start-demo.bat`. The replay runs at 120× speed: the 8-hour synthetic timeline
   takes about 4 minutes, so the first incidents appear within ~10 seconds.

| Time | On screen | Say (roughly) |
|---|---|---|
| 0:00–0:15 | README top, then the dashboard Overview | "This is BGP Watch Malaysia. It watches the BGP routes of TM, Maxis, CelcomDigi, TIME, U Mobile and MYREN in real time, using RIPE's RIS Live feed, and tells a NOC engineer when a prefix is hijacked, leaked or disappears." |
| 0:15–0:30 | Point at the yellow SYNTHETIC banner and the network cards | "For the demo I'm replaying a labelled synthetic incident set, with fictional networks and reserved test numbers, so it works offline. Live mode uses the real networks." |
| 0:30–0:55 | An incident appears; click it. Show "Why this fired" and the AS path with the red suspect AS | "Here a fictional AS announced our prefix. The tool explains why in plain English: the prefix normally comes from one AS, 25 RIS peers now see a different origin, and RPKI says the ROA doesn't authorise it. That's a hijack, critical." |
| 0:55–1:15 | Alert log tab: notification log | "Alert fatigue matters in a NOC. Hundreds of raw findings became about a dozen incidents, each paged once. A route flapping 12 times is one incident, not 12 pages." |
| 1:15–1:30 | Visibility-drop incident with the chart | "This one is an outage. The prefix dropped to zero visibility for 15 minutes. Dips shorter than normal BGP convergence are ignored." |
| 1:30–1:45 | Terminal: `python -m bgpwatch evaluate` output, or `docs/ACCURACY.md` | "Every detector is tested against labelled scenarios, including benign look-alikes. On the synthetic set it detected all expected events with zero false alerts, and CI re-runs this check on every commit." |
| 1:45–2:00 | Live dashboard (`start-live.bat`) with the green LIVE badge, or the live screenshot from the README | "In live mode it streams real updates for about 940 Malaysian prefixes. Every ASN and prefix list is verified from RIPEstat and PeeringDB, never typed from memory. Code and results are on my GitHub." |

**Tips**

* Say "RIS peers", "origin AS" and "RPKI". Those are the words an interviewer will listen for.
* If asked "has it caught a real hijack?", answer honestly: the README lists what the live runs
  actually saw, and the synthetic set is labelled as synthetic.
