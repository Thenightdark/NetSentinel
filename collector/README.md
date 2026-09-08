# Collector

This package is reserved for passive observation of local network metadata. The starter only reads interface byte and packet counters through `psutil`.

Scapy is declared for future, explicitly enabled passive packet-header inspection. Do not add packet injection, credential interception, payload harvesting, spoofing, man-in-the-middle behavior, or exploit logic. Capture only on networks and devices you are authorized to monitor, and minimize retained data.

Run the safe metadata snapshot with:

```bash
python -m collector.service
```

