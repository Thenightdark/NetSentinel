# Safety boundaries

NetSentinel is for defensive monitoring on systems and networks you own or are explicitly authorized to observe.

Allowed direction:

- passive interface, connection, flow, and packet-header metadata;
- defensive alerting and anomaly detection;
- transparent retention controls and auditable configuration;
- least-privilege operation.

Out of scope:

- packet injection or traffic manipulation;
- credential or secret interception;
- man-in-the-middle functionality;
- exploitation, persistence, evasion, or lateral movement;
- covert collection from third-party systems.

The collector starts with OS-provided counters only. Any future Scapy capture must be opt-in, documented, authorization-aware, and bounded to necessary metadata.

