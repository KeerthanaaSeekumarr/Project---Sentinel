import os
import ssl
from flask import Flask, render_template, jsonify, request, send_file
from traffic_engine import TrafficEngine
from datetime import datetime
import json
import csv
from io import BytesIO, StringIO

# Initialize App
app = Flask(__name__)
engine = TrafficEngine()

# --- Routes ---


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


@app.route("/api/control", methods=["POST"])
def control_traffic():
    action = request.json.get("action")
    if action == "start":
        engine.start_generator()
        return jsonify({"status": "started", "message": "Traffic Generator Active"})
    elif action == "stop":
        engine.stop_generator()
        return (
            jsonify({"status": "stopped", "message": "Traffic Generator Halted"}),
            202,
        )
    elif action == "clear":
        engine.clear_packets()
        return jsonify({"status": "cleared", "message": "Buffer Cleared"}), 202
    return jsonify({"error": "Invalid action"}), 400


@app.route("/api/packets")
def get_packets():
    return jsonify(engine.get_packets())


# --- IP Range Processor API ---
@app.route("/api/process_ip_range", methods=["POST"])
def process_ip_range():
    data = request.json
    start_ip = data.get("start_ip")
    end_ip = data.get("end_ip")

    if not start_ip or not end_ip:
        return jsonify({"error": "Start IP and End IP are required."}), 400

    # Call the new method on the TrafficEngine
    status, packets = engine.generate_simulated_ipdr_data(start_ip, end_ip)

    if status.get("error"):
        return jsonify(status), 400

    # Add the results to the main buffer to see them on the Monitor page
    with engine.lock:
        for packet in packets:
            engine.packet_buffer.append(packet)
        # Prune older packets if buffer is too large
        if len(engine.packet_buffer) > 500:
            engine.packet_buffer = engine.packet_buffer[-500:]

    return jsonify(
        {
            "status": "success",
            "message": status.get("message"),
            "results": packets,
            "count": len(packets),
            "total_generated": status.get("total_generated", len(packets)),
            "filtered_count": status.get("filtered_count", len(packets))
        }
    )


# --- Export JSON API ---
@app.route("/api/export_packets", methods=["GET"])
def export_packets():
    packets = engine.get_packets()
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


# --- NEW FEATURE: Export CSV API ---
@app.route("/api/export_packets_csv", methods=["GET"])
def export_packets_csv():
    packets = engine.get_packets()
    if not packets:
        return jsonify({"message": "No packets in buffer to export."}), 404

    # Define the fields for the CSV header (must match keys in the packet dictionary)
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

    # Use StringIO to build the CSV in memory
    output = StringIO()
    writer = csv.DictWriter(
        output, fieldnames=fieldnames, extrasaction="ignore"
    )  # ignore extra fields if any

    writer.writeheader()
    writer.writerows(packets)

    # Create an in-memory buffer for the file
    buffer = BytesIO(output.getvalue().encode("utf-8"))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'sentinel-export-{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
        mimetype="text/csv",
    )


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

    # Start the traffic engine automatically on server start
    engine.start_generator()

    print("\n[+] Sentinel-X Platform Running...")
    print(f"[+] Traffic Generator running: {engine.thread.is_alive()}")

    try:
        if context:
            app.run(host="0.0.0.0", port=5000, ssl_context=context)
        else:
            app.run(host="0.0.0.0", port=5000)
    except Exception as e:
        print(f"Error starting server: {e}")
        engine.stop_generator()
