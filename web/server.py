#!/usr/bin/env python3
"""Serve a local NetSentry dashboard and run the existing PCAP analyzer."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
PAGE = Path(__file__).with_name("index.html")
MAX_CAPTURE_SIZE = 100 * 1024 * 1024
ANALYSIS_TIMEOUT_SECONDS = 300


def find_executable():
    candidates = (
        ROOT / "build" / "netsentry.exe",
        ROOT / "build" / "Release" / "netsentry.exe",
        ROOT / "build" / "netsentry",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "NetSentry executable not found. Build the project first; "
        "expected build/netsentry.exe."
    )


def runtime_environment():
    environment = os.environ.copy()
    runtime_paths = []
    cache = ROOT / "build" / "CMakeCache.txt"
    if cache.is_file():
        compiler_match = re.search(
            r"^CMAKE_CXX_COMPILER(?::[^=]+)?=(.+)$",
            cache.read_text(encoding="utf-8", errors="replace"),
            re.MULTILINE,
        )
        if compiler_match:
            compiler = Path(compiler_match.group(1).strip())
            if compiler.is_file():
                runtime_paths.append(str(compiler.parent))
    runtime_paths.append(str(find_executable().parent))
    environment["PATH"] = os.pathsep.join(
        runtime_paths + [environment.get("PATH", "")]
    )
    return environment


def option_values(query, name):
    values = []
    for value in query.get(name, []):
        values.extend(item.strip() for item in value.split(",") if item.strip())
    if len(values) > 20:
        raise ValueError(f"At most 20 {name} filters are supported.")
    return values


def threshold(query, name, default):
    values = query.get(name, [str(default)])
    if len(values) != 1:
        raise ValueError(f"Provide exactly one {name.replace('_', ' ')} value.")
    try:
        value = int(values[0])
    except ValueError as error:
        raise ValueError(f"{name.replace('_', ' ')} must be a non-negative integer.") from error
    if value < 0 or value > 2**63 - 1:
        raise ValueError(f"{name.replace('_', ' ')} must be between 0 and {2**63 - 1}.")
    return value


def analyze(capture, query):
    executable = find_executable()
    scan_threshold = threshold(query, "scan_threshold", 20)
    syn_threshold = threshold(query, "syn_threshold", 100)
    command = [
        str(executable),
        "--input",
        "capture.pcap",
        "--output",
        "report",
        "--threads",
        "2",
        "--scan-threshold",
        str(scan_threshold),
        "--syn-threshold",
        str(syn_threshold),
    ]
    for name in ("ip", "port", "domain"):
        for value in option_values(query, name):
            command.extend(("--" + name, value))

    with tempfile.TemporaryDirectory(prefix="netsentry-") as directory:
        workdir = Path(directory)
        (workdir / "capture.pcap").write_bytes(capture)
        try:
            result = subprocess.run(
                command,
                cwd=workdir,
                env=runtime_environment(),
                capture_output=True,
                text=True,
                timeout=ANALYSIS_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"Analysis exceeded the {ANALYSIS_TIMEOUT_SECONDS}-second time limit."
            ) from error
        if result.returncode:
            message = result.stderr.strip() or "The analyzer exited unexpectedly."
            raise ValueError(message)
        with (workdir / "report.json").open(encoding="utf-8") as report_file:
            report = json.load(report_file)
    return report


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "NetSentryLocal/1.0"

    def send_bytes(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_bytes(status, "application/json; charset=utf-8", body)

    def do_GET(self):
        if urlsplit(self.path).path not in ("/", "/index.html"):
            self.send_error(404)
            return
        try:
            page = PAGE.read_bytes()
        except OSError as error:
            self.send_json(500, {"error": f"Could not read the dashboard: {error}"})
            return
        self.send_bytes(200, "text/html; charset=utf-8", page)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/analyze":
            self.send_json(404, {"error": "Not found."})
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_json(400, {"error": "A valid Content-Length header is required."})
            return
        if content_length <= 0:
            self.send_json(400, {"error": "Choose a non-empty PCAP file."})
            return
        if content_length > MAX_CAPTURE_SIZE:
            self.send_json(
                413,
                {"error": "Capture exceeds the 100 MiB upload limit."},
            )
            return
        capture = self.rfile.read(content_length)
        if len(capture) != content_length:
            self.send_json(400, {"error": "The capture upload was incomplete."})
            return
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        try:
            report = analyze(capture, query)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        except (OSError, json.JSONDecodeError) as error:
            self.send_json(500, {"error": f"Could not run the analyzer: {error}"})
            return
        except RuntimeError as error:
            self.send_json(504, {"error": str(error)})
            return
        self.send_json(200, {"report": report})

    def log_message(self, format_string, *args):
        print("%s - %s" % (self.address_string(), format_string % args))


def main():
    find_executable()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), RequestHandler)
    server.daemon_threads = True
    print("NetSentry dashboard: http://127.0.0.1:8000")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NetSentry dashboard.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
