"""
Sentinel-X Platform - REST API
Network traffic monitoring and security analysis platform.
"""

import os
import atexit
from flask import Flask, render_template, jsonify, request, send_file
from datetime import datetime
import json
import csv
from io import BytesIO, StringIO

from services import get_traffic_service, shutdown_service
from config import Config

# Initialize App
app = Flask(__name__)

# Get the traffic service (lazy initialization)
service = None


def get_service():
    """Get or initialize the traffic service."""
    global service
    if service is None:
        service = get_traffic_service()
    return service


# Register cleanup on exit
atexit.register(shutdown_service)


# --- Page Routes ---


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/monitor")
def monitor():
    return render_template("monitor.html")


@app.route("/processor")
def processor():
    return render_template("processor.html")


@app.route("/about")
def about():
    return render_template("about.html")


# --- API Routes ---


@app.route("/api/control", methods=["POST"])
def control_traffic():
    """Control the traffic generator (start/stop/clear)."""
    action = request.json.get("action")
    svc = get_service()

    if action == "start":
        result = svc.start_traffic()
        return jsonify(result)
    elif action == "stop":
        result = svc.stop_traffic()
        return jsonify(result), 202
    elif action == "clear":
        result = svc.clear_packets()
        return jsonify(result), 202

    return jsonify({"error": "Invalid action"}), 400


@app.route("/api/packets")
def get_packets():
    """Get all stored packets."""
    limit = request.args.get("limit", 500, type=int)
    packets = get_service().get_packets(limit=limit)
    return jsonify(packets)


@app.route("/api/packets/<int:packet_id>")
def get_packet(packet_id):
    """Get a specific packet by ID."""
    packet = get_service().get_packet_by_id(packet_id)
    if packet:
        return jsonify(packet)
    return jsonify({"error": "Packet not found"}), 404


@app.route("/api/status")
def get_status():
    """Get current engine status."""
    return jsonify(get_service().get_status())


@app.route("/api/statistics")
def get_statistics():
    """Get packet statistics."""
    return jsonify(get_service().get_statistics())


# --- IP Range Processor API ---


@app.route("/api/process_ip_range", methods=["POST"])
def process_ip_range():
    """Process and analyze an IP range."""
    data = request.json
    start_ip = data.get("start_ip")
    end_ip = data.get("end_ip")

    if not start_ip or not end_ip:
        return jsonify({"error": "Start IP and End IP are required."}), 400

    status, packets = get_service().process_ip_range(start_ip, end_ip)

    if status.get("error"):
        return jsonify(status), 400

    return jsonify(
        {
            "status": "success",
            "message": status.get("message"),
            "results": packets,
            "count": len(packets),
            "total_generated": status.get("total_generated", len(packets)),
            "filtered_count": status.get("filtered_count", len(packets)),
        }
    )


# --- Export APIs ---


@app.route("/api/export_packets", methods=["GET"])
def export_packets():
    """Export packets as JSON file."""
    packets = get_service().get_packets()
    if not packets:
        return jsonify({"message": "No packets in buffer to export."}), 404

    data_to_export = json.dumps(packets, indent=4)
    buffer = BytesIO()
    buffer.write(data_to_export.encode("utf-8"))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'sentinel-export-{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
        mimetype="application/json",
    )


@app.route("/api/export_packets_csv", methods=["GET"])
def export_packets_csv():
    """Export packets as CSV file."""
    packets = get_service().get_packets()
    if not packets:
        return jsonify({"message": "No packets in buffer to export."}), 404

    fieldnames = [
        "id",
        "timestamp",
        "source",
        "destination",
        "protocol",
        "port",
        "length",
        "severity",
        "type",
        "is_successful",
        "rule_hit",
        "ml_score",
        "info",
    ]

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(packets)

    buffer = BytesIO(output.getvalue().encode("utf-8"))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'sentinel-export-{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
        mimetype="text/csv",
    )


# --- Health Check ---


@app.route("/api/health")
def health_check():
    """API health check endpoint."""
    svc = get_service()
    return jsonify(
        {
            "status": "healthy",
            "engine_running": svc.engine.is_running,
            "packet_count": svc.get_packet_count(),
        }
    )


# --- Main Entry Point ---

if __name__ == "__main__":
    # SSL Context for HTTPS (optional)
    cert_path = "certs/cert.pem"
    key_path = "certs/key.pem"
    context = None

    if os.path.exists(cert_path) and os.path.exists(key_path):
        context = (cert_path, key_path)
        print("[+] SSL certificates found. Running with HTTPS.")
    else:
        print("[!] SSL certificates not found. Running without HTTPS (HTTP only).")
        print("[!] To enable HTTPS, run: python gen_certs.py")

    # Initialize service and start traffic generator
    svc = get_service()
    svc.start_traffic()

    print("\n[+] Sentinel-X Platform Running...")
    print(f"[+] Traffic Generator running: {svc.engine.is_running}")

    try:
        if context:
            app.run(
                host=Config.FLASK_HOST,
                port=Config.FLASK_PORT,
                ssl_context=context,
                debug=Config.DEBUG,
            )
        else:
            app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT, debug=Config.DEBUG)
    except Exception as e:
        print(f"Error starting server: {e}")
        shutdown_service()
