import random, time
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from logger import audit_log

bp = Blueprint("telemetry", __name__, url_prefix="/telemetry")

# Generate simulated readings for one node
def generate_reading(node_id: str):
    voltage = round(random.gauss(230, 5), 2)   # around 230V ± 5
    current = round(random.gauss(10, 2), 2)    # around 10A ± 2
    frequency = round(random.gauss(50, 0.5), 2) # around 50Hz ± 0.5
    load_kw = round(voltage * current / 1000.0, 2)

    return {
        "node_id": node_id,
        "voltage": voltage,
        "current": current,
        "frequency": frequency,
        "load_kw": load_kw,
        "ts": int(time.time())
    }

# API endpoint
@bp.get("/data")
@jwt_required()
def get_data():
    claims = get_jwt()
    role = claims.get("role")

    if role not in ("operator", "auditor", "admin"):
        return jsonify({"msg": "insufficient role"}), 403

    readings = [generate_reading(f"n{i}") for i in range(11)]  # 10 nodes
    audit_log(claims.get("sub"), "fetch_telemetry", f"{len(readings)} nodes")

    return jsonify({"readings": readings})
