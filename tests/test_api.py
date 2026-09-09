from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.database.base import Base
from backend.database.session import get_db
from backend.config import get_settings
from backend.main import app
from backend.models import Host, NetworkFlow, SecurityAlert, User
from backend.services.auth import hash_password
from backend.services.statistics import record_flow_statistics


@pytest.fixture
def database() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(database: Session, monkeypatch) -> TestClient:
    def override_database():
        yield database

    app.dependency_overrides[get_db] = override_database
    monkeypatch.setattr(get_settings(), "auth_secret", SecretStr("test-dashboard-auth-secret-that-is-long"))
    monkeypatch.setattr("backend.websocket.routes.SessionLocal", lambda: database)
    database.add(
        User(
            username="analyst",
            password_hash=hash_password("correct-horse-battery-staple"),
            role="admin",
            is_active=True,
        )
    )
    database.commit()
    with TestClient(app) as test_client:
        login = test_client.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "correct-horse-battery-staple"},
        )
        assert login.status_code == 200
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def stub_hostname_lookup(monkeypatch) -> None:
    names = {
        "192.168.1.10": "workstation.local",
        "10.0.0.20": "gateway.local",
        "10.0.0.30": "dns.local",
    }
    monkeypatch.setattr(
        "backend.services.hosts.resolve_hostname", lambda address: names.get(address)
    )


@pytest.fixture
def seeded_database(database: Session) -> Session:
    now = datetime.now(timezone.utc)
    records = [
            Host(ip_address="192.168.1.10", hostname="workstation", first_seen=now, last_seen=now),
            Host(ip_address="198.51.100.20", hostname=None, first_seen=now, last_seen=now),
            NetworkFlow(
                source_ip="192.168.1.10", destination_ip="198.51.100.20",
                source_port=51000, destination_port=443, protocol="TCP",
                bytes=1500, packet_count=12,
                first_seen=now - timedelta(minutes=5), last_seen=now,
            ),
            NetworkFlow(
                source_ip="192.168.1.10", destination_ip="203.0.113.53",
                source_port=53000, destination_port=53, protocol="UDP",
                bytes=240, packet_count=2,
                first_seen=now - timedelta(hours=3), last_seen=now - timedelta(hours=3),
            ),
            SecurityAlert(
                timestamp=now, severity="HIGH", risk_score=70, alert_type="port_scan",
                source_ip="192.0.2.50", destination_ip="192.168.1.10",
                description="Multiple destination ports observed", status="NEW",
            ),
        ]
    database.add_all(records)
    record_flow_statistics(
        database, [item for item in records if isinstance(item, NetworkFlow)]
    )
    database.commit()
    return database


@pytest.fixture
def ingest_api_key(monkeypatch) -> str:
    key = "test-ingestion-key"
    monkeypatch.setattr(get_settings(), "ingest_api_key", SecretStr(key))
    return key


def ingest_payload() -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "batch_id": "fd560318-c737-4a87-a11e-213acf655810",
        "flows": [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.0.20",
                "source_port": 51000,
                "destination_port": 443,
                "protocol": "tcp",
                "process_id": 42,
                "process_name": "chrome.exe",
                "executable_name": "chrome.exe",
                "bytes": 2048,
                "packet_count": 16,
                "first_seen": (now - timedelta(seconds=5)).isoformat(),
                "last_seen": now.isoformat(),
            }
        ],
    }


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok", "service": "backend", "database": "connected"
    }


def test_flows_support_filtering_and_pagination(
    client: TestClient, seeded_database: Session
) -> None:
    response = client.get("/api/flows", params={"protocol": "tcp", "limit": 1})
    body = response.json()
    assert response.status_code == 200
    assert body["total"] == 1
    assert body["limit"] == 1
    assert body["items"][0]["packet_count"] == 12


def test_recent_flows_exclude_old_records(
    client: TestClient, seeded_database: Session
) -> None:
    response = client.get("/api/flows/recent", params={"minutes": 60})
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["protocol"] == "TCP"


def test_hosts_can_be_searched(client: TestClient, seeded_database: Session) -> None:
    response = client.get("/api/hosts", params={"search": "work"})
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["ip_address"] == "192.168.1.10"


def test_host_detail_includes_destination_and_protocol_statistics(
    client: TestClient, seeded_database: Session
) -> None:
    host_id = client.get("/api/hosts", params={"search": "workstation"}).json()["items"][0]["id"]

    response = client.get(f"/api/hosts/{host_id}")
    body = response.json()

    assert response.status_code == 200
    assert body["is_active"] is True
    assert body["top_destinations"][0] == {
        "ip_address": "198.51.100.20", "bytes": 1500, "connections": 1
    }
    assert body["most_used_protocols"][0] == {
        "protocol": "TCP", "bytes": 1500, "connections": 1
    }
    assert body["risk_score"] == 70
    assert body["top_destination_ports"][0] == {
        "port": 443, "bytes": 1500, "connections": 1
    }
    assert len(body["activity_over_time"]) == 24
    assert sum(point["bytes"] for point in body["activity_over_time"]) == 1740
    assert sum(point["connections"] for point in body["activity_over_time"]) == 2
    assert [flow["destination_port"] for flow in body["recent_flows"]] == [443, 53]
    assert body["recent_alerts"][0]["risk_score"] == 70


def test_missing_host_detail_returns_404(client: TestClient) -> None:
    assert client.get("/api/hosts/99999").status_code == 404


def test_hosts_can_be_filtered_by_activity(
    client: TestClient, database: Session
) -> None:
    now = datetime.now(timezone.utc)
    database.add_all(
        [
            Host(ip_address="10.0.0.1", first_seen=now, last_seen=now),
            Host(
                ip_address="10.0.0.2",
                first_seen=now - timedelta(hours=1),
                last_seen=now - timedelta(hours=1),
            ),
        ]
    )
    database.commit()

    active = client.get("/api/hosts", params={"active": True}).json()
    inactive = client.get("/api/hosts", params={"active": False}).json()

    assert [item["ip_address"] for item in active["items"]] == ["10.0.0.1"]
    assert [item["ip_address"] for item in inactive["items"]] == ["10.0.0.2"]


def test_alerts_can_be_filtered(client: TestClient, seeded_database: Session) -> None:
    response = client.get("/api/alerts", params={"severity": "HIGH", "status": "NEW"})
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["alert_type"] == "port_scan"


def test_stats_summary_aggregates_database(
    client: TestClient, seeded_database: Session
) -> None:
    response = client.get("/api/stats/summary")
    assert response.status_code == 200
    assert response.json() == {
        "hosts": 2,
        "flows": 2,
        "alerts": 1,
        "open_alerts": 1,
        "total_bytes": 1740,
        "total_packets": 14,
        "protocols": [
            {"protocol": "TCP", "flow_count": 1},
            {"protocol": "UDP", "flow_count": 1},
        ],
    }


def test_invalid_pagination_is_rejected(client: TestClient) -> None:
    response = client.get("/api/flows", params={"limit": 500})
    assert response.status_code == 422


def test_ingestion_requires_api_key(client: TestClient, ingest_api_key: str) -> None:
    response = client.post("/api/ingest/flows", json=ingest_payload())
    assert response.status_code == 401


def test_ingestion_validates_persists_and_deduplicates_batch(
    client: TestClient, database: Session, ingest_api_key: str
) -> None:
    payload = ingest_payload()
    headers = {"X-API-Key": ingest_api_key}

    first = client.post("/api/ingest/flows", json=payload, headers=headers)
    duplicate = client.post("/api/ingest/flows", json=payload, headers=headers)

    assert first.status_code == 202
    assert first.json() == {"accepted": 1, "duplicate": False}
    assert duplicate.status_code == 202
    assert duplicate.json() == {"accepted": 1, "duplicate": True}

    summary = client.get("/api/stats/summary").json()
    assert summary["flows"] == 1
    assert summary["hosts"] == 2
    assert summary["total_bytes"] == 2048

    stored_flow = client.get("/api/flows").json()["items"][0]
    assert stored_flow["process_id"] == 42
    assert stored_flow["process_name"] == "chrome.exe"
    assert stored_flow["executable_name"] == "chrome.exe"

    hosts = client.get("/api/hosts").json()["items"]
    assert {host["ip_address"] for host in hosts} == {"192.168.1.10", "10.0.0.20"}
    assert all(host["total_bytes"] == 2048 for host in hosts)
    assert all(host["total_connections"] == 1 for host in hosts)
    assert {host["hostname"] for host in hosts} == {"workstation.local", "gateway.local"}

    alerts = client.get("/api/alerts", params={"alert_type": "new_host"}).json()
    assert alerts["total"] == 2
    assert {alert["severity"] for alert in alerts["items"]} == {"INFO"}
    assert all(0 <= alert["risk_score"] <= 100 for alert in alerts["items"])
    assert {
        alert["evidence"]["discovery_method"] for alert in alerts["items"]
    } == {"passive_flow_observation"}


def test_ingestion_does_not_track_public_addresses_as_local_hosts(
    client: TestClient, ingest_api_key: str
) -> None:
    payload = ingest_payload()
    payload["batch_id"] = "4cf1091b-f0a4-4ed1-98c4-c25d1ec692bc"
    payload["flows"][0]["source_ip"] = "8.8.8.8"
    payload["flows"][0]["destination_ip"] = "1.1.1.1"

    response = client.post(
        "/api/ingest/flows",
        json=payload,
        headers={"X-API-Key": ingest_api_key},
    )

    assert response.status_code == 202
    assert client.get("/api/hosts").json()["total"] == 0


def test_ingestion_rejects_invalid_flow_times(
    client: TestClient, ingest_api_key: str
) -> None:
    payload = ingest_payload()
    payload["flows"][0]["first_seen"], payload["flows"][0]["last_seen"] = (
        payload["flows"][0]["last_seen"],
        payload["flows"][0]["first_seen"],
    )
    response = client.post(
        "/api/ingest/flows", json=payload, headers={"X-API-Key": ingest_api_key}
    )
    assert response.status_code == 422


def test_alert_status_can_be_updated(
    client: TestClient, seeded_database: Session
) -> None:
    alert_id = client.get("/api/alerts").json()["items"][0]["id"]

    acknowledged = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "ACKNOWLEDGED"}
    )
    resolved = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "RESOLVED"}
    )

    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "ACKNOWLEDGED"
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "RESOLVED"
    assert client.get("/api/stats/summary").json()["open_alerts"] == 0


def test_alert_status_update_validates_state_and_missing_alert(
    client: TestClient,
) -> None:
    invalid = client.patch("/api/alerts/1/status", json={"status": "OPEN"})
    missing = client.patch("/api/alerts/999/status", json={"status": "NEW"})

    assert invalid.status_code == 422
    assert missing.status_code == 404


def test_live_websocket_connects_and_responds_to_ping(client: TestClient) -> None:
    with client.websocket_connect("/ws/live") as websocket:
        ready = websocket.receive_json()
        websocket.send_text("ping")
        heartbeat = websocket.receive_json()

    assert ready["type"] == "connection.ready"
    assert heartbeat["type"] == "connection.heartbeat"
    assert heartbeat["message"] == "pong"


def test_dashboard_authentication_and_collector_key_are_separate(
    client: TestClient, database: Session, ingest_api_key: str
) -> None:
    stored_user = database.scalar(select(User).where(User.username == "analyst"))
    assert stored_user is not None
    assert stored_user.password_hash != "correct-horse-battery-staple"
    assert stored_user.password_hash.startswith("$argon2")

    original_token = client.cookies.get("netsentinel_session")
    assert original_token is not None
    logged_out = client.post("/api/auth/logout")
    assert logged_out.status_code == 200
    for protected_path in (
        "/api/flows",
        "/api/hosts",
        "/api/alerts",
        "/api/dns",
        "/api/stats/summary",
    ):
        assert client.get(protected_path).status_code == 401
    client.cookies.set("netsentinel_session", original_token)
    assert client.get("/api/flows").status_code == 401
    client.cookies.clear()
    assert client.get("/api/health").status_code == 200

    payload = ingest_payload()
    payload["batch_id"] = "10a2ba58-f9df-4889-b0ad-7499376c3314"
    ingested = client.post(
        "/api/ingest/flows",
        json=payload,
        headers={"X-API-Key": ingest_api_key},
    )
    assert ingested.status_code == 202
    assert client.get("/api/flows", headers={"X-API-Key": ingest_api_key}).status_code == 401

    rejected = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "wrong-password"}
    )
    accepted = client.post(
        "/api/auth/login",
        json={"username": "ANALYST", "password": "correct-horse-battery-staple"},
    )
    assert rejected.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json()["user"]["role"] == "admin"
    assert "HttpOnly" in accepted.headers["set-cookie"]
    assert client.get("/api/auth/me").json()["username"] == "analyst"


def test_live_websocket_requires_dashboard_session(client: TestClient) -> None:
    client.cookies.clear()
    with pytest.raises(WebSocketDisconnect) as rejected:
        with client.websocket_connect("/ws/live"):
            pass
    assert rejected.value.code == 1008


def test_ingested_flows_emit_throttled_live_update(
    client: TestClient, ingest_api_key: str
) -> None:
    first_payload = ingest_payload()
    second_payload = ingest_payload()
    second_payload["batch_id"] = "580dcdd3-bbee-4d3a-a093-c9d1d41f162c"
    second_payload["flows"][0]["protocol"] = "udp"
    headers = {"X-API-Key": ingest_api_key}

    with client.websocket_connect("/ws/live") as websocket:
        assert websocket.receive_json()["type"] == "connection.ready"
        assert client.post("/api/ingest/flows", json=first_payload, headers=headers).status_code == 202
        assert client.post("/api/ingest/flows", json=second_payload, headers=headers).status_code == 202
        update = websocket.receive_json()

    assert update["type"] == "live.update"
    assert update["summary"]["active_connections"] == 2
    assert update["summary"]["total_flows"] == 2
    assert update["summary"]["throughput_bps"] > 0
    assert {item["protocol"] for item in update["summary"]["protocols"]} == {"TCP", "UDP"}
    assert {item["protocol"] for item in update["completed_flows"]} == {"TCP", "UDP"}
    assert len(update["recent_flows"]) == 2
