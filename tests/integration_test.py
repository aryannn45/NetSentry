#!/usr/bin/env python3
"""Exercise the sample-PCAP generator, CLI, and both report formats."""

import json
import os
import subprocess
import sys


def main():
    executable, generator, build_dir = sys.argv[1:]
    capture = os.path.join(build_dir, "netsentry-integration.pcap")
    prefix = os.path.join(build_dir, "netsentry-integration-report")
    subprocess.run([sys.executable, generator, capture], check=True)
    subprocess.run(
        [
            executable,
            "--input",
            capture,
            "--output",
            prefix,
            "--threads",
            "2",
            "--scan-threshold",
            "3",
        ],
        check=True,
    )
    with open(prefix + ".json", encoding="utf-8") as report_file:
        report = json.load(report_file)
    summary = report["summary"]
    assert summary["packets"] == 5, summary
    assert summary["tcp_packets"] == 4, summary
    assert summary["udp_packets"] == 1, summary
    assert summary["connections"] == 5, summary
    assert report["domains"]["www.example.com"] >= 2, report["domains"]
    assert any(alert["type"] == "port_scan" for alert in report["alerts"]), report["alerts"]
    with open(prefix + ".csv", encoding="utf-8") as report_file:
        csv_report = report_file.read()
    assert "summary,packets,5" in csv_report, csv_report

    invalid_capture = os.path.join(build_dir, "netsentry-invalid.pcap")
    with open(invalid_capture, "wb") as invalid_file:
        invalid_file.write(b"not a PCAP")
    result = subprocess.run(
        [executable, "--input", invalid_capture, "--format", "json", "--output", prefix],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2, result
    assert "NetSentry error:" in result.stderr, result.stderr
    os.remove(invalid_capture)
    print("NetSentry CLI integration test passed")


if __name__ == "__main__":
    main()
