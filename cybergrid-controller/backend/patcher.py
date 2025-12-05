"""
Patch management simulation for microgrid components.
"""

from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass
from typing import Iterable

from .models import PatchStatus, SessionLocal
from .utils import logger


@dataclass
class PatchRequest:
    component_name: str
    version: str
    payload: bytes
    requested_by: str

    def checksum(self) -> str:
        digest = hashlib.sha256(self.payload).hexdigest()
        return digest


class PatchManager:
    def __init__(self, failure_rate: float = 0.1) -> None:
        self.failure_rate = failure_rate

    def schedule_patch(self, request: PatchRequest) -> PatchStatus:
        logger.info("Scheduling patch %s for %s", request.version, request.component_name)
        with SessionLocal() as session:
            status = PatchStatus(
                component=self._get_component(session, request.component_name),
                version=request.version,
                status="pending",
                requested_by=request.requested_by,
                notes=f"Checksum {request.checksum()}",
            )
            session.add(status)
            session.commit()
            session.refresh(status)
            return status

    def apply_patches(self, statuses: Iterable[PatchStatus]) -> None:
        with SessionLocal() as session:
            for status in statuses:
                tracked = session.merge(status)
                tracked.status = "in_progress"
                session.commit()
                time.sleep(0.1)
                if random.random() < self.failure_rate:
                    tracked.status = "failed"
                    tracked.notes = (tracked.notes or "") + " Automated validation failed."
                else:
                    tracked.status = "success"
                    tracked.notes = (tracked.notes or "") + " Patch applied successfully."
                session.commit()

    def _get_component(self, session, component_name: str):
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


