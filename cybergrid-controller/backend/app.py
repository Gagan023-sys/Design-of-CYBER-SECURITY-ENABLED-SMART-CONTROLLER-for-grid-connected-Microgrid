"""
Flask application entrypoint for the CyberGrid controller.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
import random

from flask import Flask, jsonify, request, g
from flask_cors import CORS

from . import auth
from .ids import IntrusionDetectionSystem, TelemetrySample
from .models import (
    MicrogridComponent,
    PatchStatus,
    SecurityEvent,
    TelemetryRecord,
    User,
    init_db,
    SessionLocal,
)
from .patcher import PatchManager, PatchRequest
from .utils import RepeatingTimer, SchedulerJob, load_json, logger

ROOT = Path(__file__).resolve().parent.parent
TEST_DATA_PATH = ROOT / "test_data" / "fake_microgrid_nodes.json"
FRONTEND_DIR = ROOT / "frontend"


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=str(FRONTEND_DIR),
        static_url_path="",
    )
    app.config["JSON_SORT_KEYS"] = False
    app.config["SECRET_KEY"] = os.getenv("CYBERGRID_FLASK_SECRET", "super-secret")
    CORS(app, resources={r"/*": {"origins": "*"}})

    init_db()

    ids = IntrusionDetectionSystem()
    patch_manager = PatchManager()

    scheduler = RepeatingTimer()

    def ingest_fake_data() -> None:
        if not TEST_DATA_PATH.exists():
            logger.warning("Telemetry data file missing: %s", TEST_DATA_PATH)
            return

        def jitter_numeric(key: str, value: float) -> float:
            if key == "voltage":
                return round(max(0.0, value + random.uniform(-14, 18)), 2)
            if key == "frequency":
                return round(value + random.uniform(-1.2, 1.2), 3)
            if key in {"power_kw", "soc"}:
                return round(max(0.0, value + random.uniform(-22, 28)), 2)
            span = max(1.0, abs(value) * 0.08)
            return round(value + random.uniform(-span, span), 2)

        def jitter_payload(payload: dict) -> dict:
            jittered: dict = {}
            for key, value in payload.items():
                if isinstance(value, (int, float)):
                    if key == "failed_logins":
                        jittered[key] = max(0, int(round(value + random.randint(-2, 3))))
                    else:
                        jittered[key] = jitter_numeric(key, float(value))
                else:
                    jittered[key] = value
            if random.random() < 0.12:
                jittered["status"] = "offline"
                jittered["voltage"] = 0.0
                jittered["frequency"] = 0.0
            else:
                jittered["status"] = jittered.get("status", "online")
            if "failed_logins" not in jittered:
                jittered["failed_logins"] = max(0, random.randint(0, 4))
            return jittered

        raw_records = load_json(TEST_DATA_PATH)
        samples: list[TelemetrySample] = []
        for entry in raw_records:
            telemetry = entry.get("telemetry", {})
            payload = jitter_payload(telemetry)
            samples.append(TelemetrySample(component=entry["name"], payload=payload))
        ids.update_baseline(samples)
        ids.ingest_and_store(samples)
        alerts = ids.analyze(samples)
        if alerts:
            logger.warning("IDS alerts detected: %s", alerts)

    scheduler.register(SchedulerJob(interval_seconds=6, target=ingest_fake_data, name="ingest_fake_data"))
    scheduler.start()

    @app.route("/", methods=["GET"])
    def root():
        return app.send_static_file("index.html")

    def record_event(category: str, details: str, severity: str = "info", context: dict | None = None) -> None:
        actor = getattr(g, "current_user", None)
        with SessionLocal() as session:
            event = SecurityEvent(
                severity=severity,
                category=category,
                details=details,
                context=context or {},
                actor_id=actor.id if actor else None,
            )
            session.add(event)
            session.commit()

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    @app.post("/auth/login")
    def login():
        payload = request.get_json(force=True)
        username = payload.get("username", "")
        password = payload.get("password", "")

        user = auth.authenticate_user(username, password)
        if not user:
            return jsonify({"detail": "Invalid credentials"}), 401

        access = auth.create_access_token(username)
        refresh = auth.create_refresh_token(username)
        return jsonify({"access_token": access, "refresh_token": refresh})

    @app.post("/auth/refresh")
    def refresh_token():
        payload = request.get_json(force=True)
        refresh = payload.get("refresh_token")
        if not refresh:
            return jsonify({"detail": "Missing refresh_token"}), 400

        data = auth.decode_token(refresh)
        if not data or data.get("type") != "refresh":
            return jsonify({"detail": "Invalid refresh token"}), 401

        username = data.get("sub")
        if not username:
            return jsonify({"detail": "Invalid subject"}), 401

        return jsonify({"access_token": auth.create_access_token(username)})

    @app.get("/auth/me")
    @auth.token_required
    def current_user_profile():
        user = g.current_user
        return jsonify(
            {
                "username": user.username,
                "role": user.role,
                "is_active": user.is_active,
            }
        )

    @app.get("/admin/users")
    @auth.role_required({"admin"})
    def list_users_endpoint():
        return jsonify({"items": auth.list_users(), "roles": sorted(auth.VALID_ROLES)})

    @app.post("/admin/users")
    @auth.role_required({"admin"})
    def create_user_endpoint():
        payload = request.get_json(force=True)
        username = payload.get("username")
        password = payload.get("password")
        role = payload.get("role", "operator")
        if not username or not password:
            return jsonify({"detail": "username and password required"}), 400
        try:
            user = auth.create_user(username=username, password=password, role=role)
        except ValueError as exc:
            return jsonify({"detail": str(exc)}), 400
        record_event(
            category="user_management",
            details=f"Created user {user.username} with role {user.role}",
            severity="low",
        )
        return jsonify({"username": user.username, "role": user.role}), 201

    @app.patch("/admin/users/<username>")
    @auth.role_required({"admin"})
    def update_user_endpoint(username: str):
        payload = request.get_json(force=True)
        role = payload.get("role")
        is_active = payload.get("is_active")
        if role is None and is_active is None:
            return jsonify({"detail": "Provide role or is_active to update"}), 400
        try:
            if role is not None:
                auth.update_user_role(username, role)
                record_event(
                    category="user_management",
                    details=f"Updated role for {username} to {role}",
                    severity="info",
                )
            if is_active is not None:
                auth.set_user_status(username, bool(is_active))
                state = "activated" if is_active else "deactivated"
                record_event(
                    category="user_management",
                    details=f"{state.capitalize()} account {username}",
                    severity="info",
                )
        except ValueError as exc:
            return jsonify({"detail": str(exc)}), 400
        return jsonify({"detail": "User updated"})

    @app.get("/telemetry")
    @auth.token_required
    def get_telemetry():
        limit = int(request.args.get("limit", "50"))
        with SessionLocal() as session:
            records = (
                session.query(TelemetryRecord)
                .order_by(TelemetryRecord.created_at.desc())
                .limit(limit)
                .all()
            )
            payload = [
                {
                    "id": record.id,
                    "component": record.component.name if record.component else None,
                    "payload": record.payload,
                    "created_at": record.created_at.isoformat(),
                }
                for record in records
            ]
        return jsonify({"items": list(reversed(payload))})

    @app.get("/components")
    @auth.token_required
    def list_components():
        with SessionLocal() as session:
            components = session.query(MicrogridComponent).all()
            payload = []
            for component in components:
                latest_patch = (
                    session.query(PatchStatus)
                    .filter_by(component_id=component.id)
                    .order_by(PatchStatus.created_at.desc())
                    .first()
                )
                payload.append(
                    {
                        "name": component.name,
                        "type": component.component_type,
                        "firmware_version": component.firmware_version,
                        "ip_address": component.ip_address,
                        "criticality": component.criticality,
                        "latest_patch": latest_patch.version if latest_patch else None,
                        "patch_status": latest_patch.status if latest_patch else None,
                    }
                )
        return jsonify({"items": payload})

    @app.get("/alerts")
    @auth.token_required
    def list_alerts():
        severity = request.args.get("severity")
        category = request.args.get("category")
        limit = min(200, int(request.args.get("limit", "100")))
        with SessionLocal() as session:
            query = session.query(SecurityEvent).order_by(SecurityEvent.created_at.desc())
            if severity:
                query = query.filter_by(severity=severity)
            if category:
                query = query.filter_by(category=category)
            events = query.limit(limit).all()
            payload = [
                {
                    "id": event.id,
                    "severity": event.severity,
                    "category": event.category,
                    "details": event.details,
                    "context": event.context,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ]
        return jsonify({"items": payload})

    @app.get("/admin/activity/summary")
    @auth.token_required
    def activity_summary():
        with SessionLocal() as session:
            user_count = session.query(User).count()
            telemetry_count = session.query(TelemetryRecord).count()
            alert_count = session.query(SecurityEvent).count()
            component_count = session.query(MicrogridComponent).count()
            recent_alerts = (
                session.query(SecurityEvent)
                .order_by(SecurityEvent.created_at.desc())
                .limit(5)
                .all()
            )
            alerts_payload = [
                {
                    "severity": event.severity,
                    "category": event.category,
                    "details": event.details,
                    "created_at": event.created_at.isoformat(),
                }
                for event in recent_alerts
            ]
        return jsonify(
            {
                "users": user_count,
                "components": component_count,
                "telemetry_records": telemetry_count,
                "alerts": alert_count,
                "recent_alerts": alerts_payload,
            }
        )

    @app.post("/control/dispatch")
    @auth.role_required({"operator", "admin"})
    def dispatch_control():
        payload = request.get_json(force=True)
        component = payload.get("component")
        action = payload.get("action")
        value = payload.get("value")

        if not component or not action:
            return jsonify({"detail": "Missing component or action"}), 400

        requester = getattr(g, "current_user", None)
        with SessionLocal() as session:
            event = SecurityEvent(
                severity="info",
                category="control_action",
                details=f"{action} -> {component}",
                context={"value": value},
                actor_id=requester.id if requester else None,
            )
            session.add(event)
            session.commit()
        return jsonify({"detail": "Command accepted"})

    @app.post("/patch/deploy")
    @auth.role_required({"admin", "analyst"})
    def deploy_patch():
        data = request.get_json(force=True)
        component_name = data.get("component_name")
        version = data.get("version")
        payload_b64 = data.get("payload", "")
        requester = getattr(g, "current_user", None)

        if not component_name or not version:
            return jsonify({"detail": "Missing component_name or version"}), 400

        try:
            payload_bytes = base64.b64decode(payload_b64) if payload_b64 else b""
        except ValueError:
            return jsonify({"detail": "Invalid payload encoding"}), 400

        request_obj = PatchRequest(
            component_name=component_name,
            version=version,
            payload=payload_bytes or os.urandom(32),
            requested_by=requester.username if requester else "system",
        )
        status = patch_manager.schedule_patch(request_obj)
        patch_manager.apply_patches([status])

        return jsonify(
            {
                "id": status.id,
                "status": status.status,
                "notes": status.notes,
                "component": component_name,
                "version": version,
            }
        )

    @app.post("/ids/reload-baseline")
    @auth.role_required({"admin"})
    def reload_baseline():
        ids.baseline.clear()
        ingest_fake_data()
        return jsonify({"detail": "Baseline refreshed"})

    @app.post("/simulations/attack")
    @auth.role_required({"admin", "analyst"})
    def simulate_attack():
        payload = request.get_json(force=True)
        attack_type = payload.get("attack_type", "generic")
        component = payload.get("component")
        alert = ids.simulate_attack(attack_type=attack_type, component=component)
        record_event(
            category="attack_simulation",
            details=f"Simulated {attack_type} attack on {alert['component']}",
            severity=alert.get("severity", "medium"),
            context=alert,
        )
        return jsonify({"detail": "Simulation triggered", "alert": alert})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

