"""
Simplified intrusion detection system combining rule-based
and statistical checks over microgrid telemetry.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Tuple

from .models import SecurityEvent, SessionLocal, TelemetryRecord
from .utils import load_json, logger


DEFAULT_THRESHOLD = 4.0  # standard deviations from baseline


@dataclass
class TelemetrySample:
    component: str
    payload: dict


class IntrusionDetectionSystem:
    """
    Lightweight IDS that relies on thresholds and heuristics.
    """

    def __init__(
        self,
        baseline_path: Path | None = None,
        deviation_threshold: float = DEFAULT_THRESHOLD,
        cooldown_seconds: int = 120,
    ) -> None:
        self.deviation_threshold = deviation_threshold
        self.baseline = {}
        self.cooldown_seconds = cooldown_seconds
        self._recent_alerts: dict[str, float] = {}
        if baseline_path and baseline_path.exists():
            self.baseline = load_json(baseline_path)
            logger.info("Loaded IDS baseline from %s", baseline_path)

    def update_baseline(self, samples: Iterable[TelemetrySample]) -> None:
        """
        Build or refresh baseline metrics using the provided samples.
        """
        for sample in samples:
            component_metrics = self.baseline.setdefault(sample.component, {})
            for key, value in sample.payload.items():
                if not isinstance(value, (int, float)):
                    continue
                history: list[float] = component_metrics.setdefault(key, [])
                history.append(float(value))
                # Keep rolling window of last 100 values
                if len(history) > 100:
                    component_metrics[key] = history[-100:]

    def analyze(self, samples: Iterable[TelemetrySample]) -> list[dict]:
        """
        Evaluate telemetry for anomalies, persisting events if discovered.
        """
        alerts: list[dict] = []
        for sample in samples:
            rules = self._rule_checks(sample)
            statistics_alerts = self._statistical_checks(sample)
            for alert in rules + statistics_alerts:
                key = f"{sample.component}:{alert[0]}"
                if not self._should_emit_alert(key):
                    continue
                alert_record = {
                    "component": sample.component,
                    "reason": alert[0],
                    "severity": alert[1],
                    "metric": alert[2],
                    "value": alert[3],
                }
                alerts.append(alert_record)
                self._persist_alert(alert_record)
        return alerts

    def _should_emit_alert(self, key: str) -> bool:
        now = time.monotonic()
        last_seen = self._recent_alerts.get(key, 0.0)
        if now - last_seen < self.cooldown_seconds:
            return False
        self._recent_alerts[key] = now
        # Garbage collect stale keys occasionally
        stale_keys = [k for k, ts in self._recent_alerts.items() if now - ts > self.cooldown_seconds * 5]
        for stale in stale_keys:
            self._recent_alerts.pop(stale, None)
        return True

    def _rule_checks(self, sample: TelemetrySample) -> list[Tuple[str, str, str, float]]:
        alerts: list[Tuple[str, str, str, float]] = []
        status = sample.payload.get("status")
        if status == "offline":
            alerts.append(("Device offline", "high", "status", 0))
        voltage = sample.payload.get("voltage")
        if isinstance(voltage, (int, float)) and (voltage < 200 or voltage > 260):
            alerts.append(("Voltage out of bounds", "medium", "voltage", float(voltage)))
        frequency = sample.payload.get("frequency")
        if isinstance(frequency, (int, float)) and abs(frequency - 60.0) > 1.5:
            alerts.append(("Frequency deviation", "medium", "frequency", float(frequency)))

        failed_logins = sample.payload.get("failed_logins")
        if isinstance(failed_logins, (int, float)) and failed_logins > 5:
            alerts.append(("Excessive failed logins", "high", "failed_logins", float(failed_logins)))

        return alerts

    def _statistical_checks(self, sample: TelemetrySample) -> list[Tuple[str, str, str, float]]:
        stats_alerts: list[Tuple[str, str, str, float]] = []
        baseline_metrics = self.baseline.get(sample.component, {})
        for metric, baseline_values in baseline_metrics.items():
            current_value = sample.payload.get(metric)
            if not isinstance(current_value, (int, float)):
                continue
            if len(baseline_values) < 5:
                continue
            mean = statistics.fmean(baseline_values)
            stdev = statistics.pstdev(baseline_values)
            if stdev == 0:
                continue
            z_score = abs((float(current_value) - mean) / stdev)
            if z_score >= self.deviation_threshold:
                stats_alerts.append(
                    (f"{metric} deviation z={z_score:.2f}", "medium", metric, float(current_value))
                )
        return stats_alerts

    def _persist_alert(self, alert: dict) -> None:
        with SessionLocal() as session:
            event = SecurityEvent(
                severity=alert.get("severity", "low"),
                category="ids_alert",
                details=f"{alert.get('reason')} on {alert.get('component')}",
                context=alert,
            )
            session.add(event)
            session.commit()

    def simulate_attack(self, attack_type: str, component: str | None = None) -> dict:
        component_name = component or "microgrid-core"
        attack_catalog = {
            "dos": {
                "severity": "critical",
                "description": "Detected high-rate traffic saturating control interface",
                "mitigation": "Rate limiting applied, offending IPs blocked",
            },
            "spoof": {
                "severity": "high",
                "description": "Detected spoofed telemetry with inconsistent signatures",
                "mitigation": "Telemetry quarantined, device certificates revalidated",
            },
            "malware": {
                "severity": "critical",
                "description": "Firmware integrity violation detected during scan",
                "mitigation": "Patch manager rolled back update and isolated node",
            },
        }
        scenario = attack_catalog.get(
            attack_type,
            {
                "severity": "medium",
                "description": "Generic anomalous behavior detected",
                "mitigation": "IPS applied standard containment",
            },
        )
        alert = {
            "component": component_name,
            "reason": f"Simulated {attack_type} attack",
            "severity": scenario["severity"],
            "metric": attack_type,
            "value": 1,
            "description": scenario["description"],
            "mitigation": scenario["mitigation"],
        }
        self._persist_alert(alert)
        return alert

    def ingest_and_store(self, samples: Iterable[TelemetrySample]) -> None:
        """
        Persist telemetry snapshots to the database for forensics.
        """
        with SessionLocal() as session:
            for sample in samples:
                record = TelemetryRecord(
                    component=self._get_or_create_component(session, sample.component),
                    payload=sample.payload,
                    severity="normal",
                )
                session.add(record)
            session.commit()

    def _get_or_create_component(self, session, component_name: str):
        from .models import MicrogridComponent

        component = session.query(MicrogridComponent).filter_by(name=component_name).one_or_none()
        if component:
            return component
        component = MicrogridComponent(
            name=component_name,
            component_type="unknown",
            firmware_version="0.0.0",
            ip_address="0.0.0.0",
            criticality="low",
        )
        session.add(component)
        session.flush()
        return component


