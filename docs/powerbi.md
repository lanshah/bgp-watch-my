# Building a Power BI "BGP NOC" report from BGP Watch data

BGP Watch exports tidy CSV files (UTF-8 with BOM, so Excel and Power BI read them cleanly). This
guide builds a one-page report: KPI cards, a network health trend, an incident matrix and the
alert log. It follows the same pattern as the NetPulse SLA report.

> **Status:** the CSV files and column names below were checked against `python -m bgpwatch
> export-csv` output. I wrote the Power BI click path for current Power BI Desktop but did not
> click through it myself; menu names can differ slightly between versions.

## 1. Create the CSV files

Open **Command Prompt** in the project folder and run one of:

```bat
.venv\Scripts\python.exe -m bgpwatch export-csv --db data\demo.db
```

(after `start-demo.bat`: the labelled synthetic incident set, which has plenty of incidents to chart), or

```bat
.venv\Scripts\python.exe -m bgpwatch export-csv
```

(your live database, after the monitor has run for a while). The Alert log tab of the dashboard
also has **Export … CSV** buttons.

Files created in `exports\`:

| File | One row per | Key columns |
|---|---|---|
| `incidents.csv` | incident | `incident_id`, `source`, `network`, `kind`, `severity`, `status`, `first_seen_utc`, `resolved_utc`, `duration_min`, `actor_asn`, `peers`, `prefix_count`, `title`, `summary` |
| `notifications.csv` | notification | `incident_id`, `time_utc`, `channel`, `severity`, `reason`, `delivered` |
| `network_health.csv` | network per minute | `time_utc`, `network`, `prefixes`, `healthy_prefixes`, `avg_visibility_pct` |
| `prefix_visibility.csv` | watched prefix | `network`, `prefix`, `peers_seeing`, `baseline_peers`, `visibility_pct` |
| `updates.csv` | BGP update | `time_utc`, `network`, `prefix`, `type`, `origin_asn`, `ris_peer`, `collector`, `flagged` |

All times are UTC. Malaysia time is UTC+8 (a calculated column below).

## 2. Load the files

1. **Power BI Desktop** → **Blank report** → **Home** → **Get data** → **Text/CSV**.
2. Load `incidents.csv`, `notifications.csv`, `network_health.csv` and `prefix_visibility.csv`.
3. In the **Data** pane, set the `*_utc` columns to **Date/Time**.
4. Add a Malaysia-time column to `incidents` (**Table tools** → **New column**):

```DAX
first_seen_myt = incidents[first_seen_utc] + TIME ( 8, 0, 0 )
```

## 3. Relationships

Create a small `networks` dimension: **Home** → **Enter data**, one column `network` with
the keys `TM`, `MAXIS`, `CELCOMDIGI`, `TIME`, `UMOBILE`, `MYREN` (or `SYN-A`, `SYN-B`, `SYN-C` for
the demo data). In **Model view**, drag `networks[network]` onto the `network` column of each
of the other tables (**1 → \***). Then drag `incidents[incident_id]` onto
`notifications[incident_id]` (**1 → \***).

## 4. Measures (DAX)

Select `incidents` → **Home** → **New measure**, one at a time:

```DAX
Incidents = COUNTROWS ( incidents )
```

```DAX
Open incidents = CALCULATE ( [Incidents], incidents[status] = "open" )
```

```DAX
Critical + high = CALCULATE ( [Incidents], incidents[severity] IN { "critical", "high" } )
```

```DAX
Median duration (min) = MEDIAN ( incidents[duration_min] )
```

```DAX
Pages per incident = DIVIDE ( COUNTROWS ( notifications ), [Incidents] )
```

On `network_health`:

```DAX
Avg visibility % = AVERAGE ( network_health[avg_visibility_pct] )
```

`Pages per incident` is the alert-fatigue KPI: BGP Watch folds repeated findings into one
incident, so it should stay close to 1.

## 5. Visuals (one page)

1. **Cards**: `Incidents`, `Open incidents`, `Critical + high`, `Pages per incident`.
2. **Line chart**: X = `network_health[time_utc]`, Y = `Avg visibility %`, Legend = `network`.
3. **Matrix**: Rows = `networks[network]`, Columns = `incidents[kind]`, Values = `Incidents`.
   Conditional formatting → background colour scale.
4. **Table** (alert log): `first_seen_myt`, `severity`, `network`, `kind`, `summary`, `duration_min`,
   sorted by `first_seen_myt` descending.
5. **Slicers**: `networks[network]`, `incidents[severity]`, `incidents[source]` (live / synthetic / replay).

Keep `source` visible: never mix synthetic demo incidents with live ones in a chart without the slicer.

## 6. Refresh

Re-run `export-csv` and press **Home** → **Refresh**. To automate it, schedule the export with
Windows Task Scheduler (Action: `...\.venv\Scripts\python.exe`, arguments `-m bgpwatch export-csv`,
start in: the project folder).
