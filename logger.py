from flask import request
from models import db, AuditLog

def audit_log(user, action, details=None):
    try:
        entry = AuditLog(
            user=user or "system",
            action=action,
            details=details,
            ip=request.remote_addr if request else None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        # Avoid breaking app if logging fails
        print("Audit logging failed:", e)
