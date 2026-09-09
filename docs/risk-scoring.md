# Alert risk scoring

NetSentinel assigns every generated alert an explainable integer risk score from 0 to 100. The score is a triage aid, not a claim that activity is malicious. Version `1.1` records every component under `evidence.risk_score_breakdown` so operators can see exactly why a score was assigned.

## Severity bands

| Score | Severity |
| --- | --- |
| 0–19 | INFO |
| 20–39 | LOW |
| 40–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

Severity is always derived from the final score; detection rules do not choose their own severity.

## Components

The total is the sum of bounded components, capped at 100:

1. **Rule base (5–35 points).** A new host starts at 5 because it is informational. A configured unusual port or unusually long domain starts at 20. A bandwidth spike or repeated failed DNS lookup starts at 25. A connection spike or high DNS query rate starts at 30 because each measures frequency against a configured threshold. A possible port scan starts at 35 because it combines activity across many ports. These weights express increasing metadata specificity, not certainty of malicious intent.
2. **Rule correlation (0–18 points).** Each additional distinct rule triggered for the same source during one analysis run adds 6 points, up to three additional rules. Correlated independent signals receive more weight than repeated instances of one rule.
3. **Connection frequency (0–15 points).** `15 × min(1, observed connections ÷ (2 × configured minimum))`, rounded to the nearest integer. Meeting the configured threshold earns roughly half the component; twice the threshold earns the cap.
4. **Unique ports (0–15 points).** The same bounded ratio is applied to distinct destination ports and the configured port-scan threshold.
5. **Bandwidth volume (0–15 points).** The same bounded ratio is applied to transfer bytes and the configured inbound or outbound threshold.
6. **DNS signals (0–40 points).** Query rate and repeated failures each use the same bounded ratio for up to 15 points. Domain length uses that ratio for up to 10 points. These factors are zero for non-DNS alerts unless another DNS rule correlated for the same source in the same analysis run.
7. **Traffic direction (0–4 points).** Inbound threshold events add 4 points because they target a local asset. Outbound threshold events add 2 points because large outbound traffic may warrant review but is often routine. Direction is deliberately a small modifier and never triggers an alert by itself.
8. **Previous alert history (0–8 points).** Each prior alert for the source adds 2 points, capped after four alerts. This gives recurring observations limited additional weight without allowing history alone to dominate the score.

Missing factors contribute zero. Components use the same configured thresholds that triggered the rules, so changing a detection threshold also changes the corresponding score normalization. The evidence records the component points, distinct-rule count, previous-alert count, total, and methodology version.

## Existing development data

When an older SQLite database is opened, legacy severity labels are normalized to uppercase and given the midpoint of their matching score band: INFO 10, LOW 30, MEDIUM 50, HIGH 70, and CRITICAL 90. Legacy workflow states map to `RESOLVED` when already resolved, `ACKNOWLEDGED` when previously acknowledged, and `NEW` otherwise.
