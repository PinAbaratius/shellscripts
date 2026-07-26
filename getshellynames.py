#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_CSV = "Shelly_4PM_Master_gemappt.csv"
TIMEOUT = 2.0


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    if len(compact) != 12:
        return (value or "").upper()
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def get_json(ip: str, path: str) -> dict[str, Any]:
    url = f"http://{ip}{path}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Shelly-4PM-Checker/1.0"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        payload = response.read().decode("utf-8", errors="replace")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ValueError(f"Ungültige JSON-Antwort von {url}")
        return value


def load_devices(csv_path: Path) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=";")

        for row in reader:
            ip = (row.get("IP") or "").strip()
            if not ip:
                continue

            device = grouped.setdefault(
                ip,
                {
                    "ip": ip,
                    "mac": (row.get("MAC") or "").strip(),
                    "model": (row.get("model") or "").strip(),
                    "device_id": (row.get("device_id") or "").strip(),
                    "shelly_id": (row.get("Shelly_ID") or "").strip(),
                    "desired_device_name": (row.get("desired_device_name") or "").strip(),
                    "channels": {},
                },
            )

            channel_text = (row.get("channel") or "").strip()
            if not channel_text:
                continue

            channel = int(channel_text)
            device["channels"][channel] = {
                "desired_name": (row.get("desired_channel_name") or "").strip(),
                "target_type": (row.get("target_type") or "").strip(),
                "cable": (row.get("cable") or "").strip(),
            }

    return grouped


def nested(mapping: dict[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def check_device(device: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    ip = device["ip"]

    try:
        info = get_json(ip, "/rpc/Shelly.GetDeviceInfo")
        config = get_json(ip, "/rpc/Shelly.GetConfig")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"NICHT ERREICHBAR: {exc}"], warnings

    actual_mac = normalize_mac(str(info.get("mac") or ""))
    expected_mac = normalize_mac(device["mac"])
    if expected_mac and actual_mac != expected_mac:
        errors.append(f"MAC erwartet {expected_mac}, erhalten {actual_mac}")

    actual_device_id = str(info.get("id") or "")
    if device["device_id"] and actual_device_id != device["device_id"]:
        errors.append(
            f"device_id erwartet {device['device_id']}, erhalten {actual_device_id}"
        )

    actual_model = str(info.get("model") or "")
    if device["model"] and actual_model != device["model"]:
        errors.append(f"Modell erwartet {device['model']}, erhalten {actual_model}")

    actual_device_name = str(
        nested(config, "sys", "device", "name") or ""
    )
    desired_device_name = device["desired_device_name"]
    if desired_device_name and actual_device_name != desired_device_name:
        warnings.append(
            f"Gerätename aktuell '{actual_device_name or '(leer)'}', "
            f"gewünscht '{desired_device_name}'"
        )

    for channel in range(4):
        key = f"switch:{channel}"
        switch_config = config.get(key)

        if not isinstance(switch_config, dict):
            errors.append(f"{key} fehlt")
            continue

        expected = device["channels"].get(channel, {})
        desired_name = expected.get("desired_name", "")
        actual_name = str(switch_config.get("name") or "")

        if desired_name and actual_name != desired_name:
            warnings.append(
                f"Kanal {channel}: aktuell '{actual_name or '(leer)'}', "
                f"gewünscht '{desired_name}'"
            )

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prüft Shelly Pro 4PM gegen die gemappte CSV."
    )
    parser.add_argument(
        "csv",
        nargs="?",
        default=DEFAULT_CSV,
        help=f"CSV-Datei, Standard: {DEFAULT_CSV}",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"CSV nicht gefunden: {csv_path}", file=sys.stderr)
        return 2

    devices = load_devices(csv_path)
    if not devices:
        print("Keine Geräte mit IP in der CSV gefunden.", file=sys.stderr)
        return 2

    total_errors = 0
    total_warnings = 0

    for ip in sorted(devices, key=lambda value: tuple(map(int, value.split(".")))):
        device = devices[ip]
        errors, warnings = check_device(device)

        if errors:
            status = "FEHLER"
        elif warnings:
            status = "ABWEICHUNGEN"
        else:
            status = "OK"

        print(
            f"\n[{status}] {ip}  "
            f"Shelly-ID {device['shelly_id']}  "
            f"{device['device_id']}"
        )

        for item in errors:
            print(f"  FEHLER: {item}")
        for item in warnings:
            print(f"  HINWEIS: {item}")

        if not errors and not warnings:
            print("  IP, MAC, Geräte-ID, Modell und Namen stimmen.")

        total_errors += len(errors)
        total_warnings += len(warnings)

    print(
        f"\nErgebnis: {len(devices)} Geräte geprüft, "
        f"{total_errors} Fehler, {total_warnings} Namensabweichungen."
    )
    return 1 if total_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
