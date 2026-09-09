# Historical statistics

NetSentinel builds bounded historical rollups when an authenticated flow batch or a detection alert is persisted. Dashboard graph requests never aggregate the raw `network_flows` or `security_alerts` tables.

## Resolutions

| Dashboard range | Stored resolution | Returned points | Retention |
| --- | ---: | ---: | ---: |
| Last 5 minutes | 1 minute | 5 | 15 minutes |
| Last hour | 5 minutes | 12 | 2 hours |
| Last 24 hours | 1 hour | 24 | 2 days |
| Last 7 days | 6 hours | 28 | 8 days |

Each ingestion updates all four resolutions in the same database transaction as the accepted flow batch. Expired buckets are removed during writes, keeping the global rollup table to roughly 119 rows regardless of raw-flow volume. Per-host rollups use the same bounded retention policy and indexed `(host_ip, granularity, bucket_start)` lookups.

`GET /api/stats/history?range=1h` selects only the relevant indexed bucket range and fills absent intervals with zeros in application memory. Every supported request therefore returns between 5 and 28 points.

## Metric semantics

- `bytes_uploaded` counts bytes where the source is a recognized local-network address.
- `bytes_downloaded` counts bytes where the destination is a recognized local-network address.
- Local-to-local traffic contributes to both directional counters because both endpoints participated.
- `flow_count` counts completed directional flows by their `last_seen` time.
- `active_hosts` counts distinct local hosts observed in each bucket. A compact per-host bucket row prevents a busy host from being counted repeatedly.
- `alerts` counts newly created defensive alerts by their alert timestamp.

Historical rollups begin accumulating after this feature is installed; existing raw records are intentionally not scanned automatically at startup. A future PostgreSQL migration can retain the same unique constraints and indexes. Row locks serialize updates to existing buckets when multiple workers ingest concurrently.
