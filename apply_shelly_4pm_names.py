#!/usr/bin/env python3
"""
Shelly Pro 4PM: Geräte- und Kanalnamen aus einer CSV prüfen und setzen.

Standard = Trockenlauf:
    python3 apply_shelly_4pm_names.py Shelly_4PM_Master_gemappt.csv

Tatsächlich anwenden:
    python3 apply_shelly_4pm_names.py Shelly_4PM_Master_gemappt.csv --apply

Eigenschaften:
- schaltet keine Ausgänge
- prüft vor Änderungen IP, MAC, Geräte-ID und Modell
- sichert Shelly.GetConfig vor Änderungen als JSON
- setzt nur abweichende Namen
- liest danach erneut ein und verifiziert
- bricht bei widersprüchlichen CSV-Daten oder Geräteidentität ab
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_CSV = "Shelly_4PM_Master_gemappt.csv"
DEFAULT_TIMEOUT = 3.0
EXPECTED_MODEL = "SPSW-204PE16EU"


class ShellyError(RuntimeError):
    pass


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    if len(compact) != 12:
        return (value or "").strip().upper()
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def rpc_get(ip: str, method: str, timeout: float) -> dict[str, Any]:
    url = f"http://{ip}/rpc/{method}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Shelly-4PM-Namer/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ShellyError(f"{url} nicht erreichbar: {exc}") from exc

    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ShellyError(f"Ungültige JSON-Antwort von {url}: {payload[:200]}") from exc

    if not isinstance(value, dict):
        raise ShellyError(f"Unerwartete Antwort von {url}")
    if "code" in value and "message" in value:
        raise ShellyError(f"{method}: {value['code']} – {value['message']}")
    return value


def rpc_post(
    ip: str,
    method: str,
    params: dict[str, Any],
    timeout: float,
    request_id: int,
) -> dict[str, Any]:
    url = f"http://{ip}/rpc"
    body = json.dumps(
        {
            "id": request_id,
            "method": method,
            "params": params,
        },
        ensure_ascii=False,
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Shelly-4PM-Namer/1.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ShellyError(f"{method} auf {ip} fehlgeschlagen: {exc}") from exc

    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ShellyError(
            f"Ungültige JSON-Antwort von {method} auf {ip}: {payload[:200]}"
        ) from exc

    if not isinstance(value, dict):
        raise ShellyError(f"Unerwartete Antwort von {method} auf {ip}")

    if "error" in value:
        error = value["error"]
        raise ShellyError(
            f"{method} auf {ip}: {error.get('code')} – {error.get('message')}"
        )

    if "code" in value and "message" in value:
        raise ShellyError(f"{method} auf {ip}: {value['code']} – {value['message']}")

    params_response = value.get("result", value.get("params", value))
    return params_response if isinstance(params_response, dict) else {"result": params_response}


def load_devices(csv_path: Path) -> dict[str, dict[str, Any]]:
    devices: dict[str, dict[str, Any]] = {}

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=";")
        required = {
            "IP",
            "MAC",
            "model",
            "device_id",
            "Shelly_ID",
            "desired_device_name",
            "channel",
            "desired_channel_name",
        }
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ShellyError(
                "In der CSV fehlen Spalten: " + ", ".join(sorted(missing))
            )

        for line_number, row in enumerate(reader, start=2):
            ip = (row.get("IP") or "").strip()
            if not ip:
                continue

            try:
                channel = int((row.get("channel") or "").strip())
            except ValueError as exc:
                raise ShellyError(
                    f"Zeile {line_number}: ungültiger Kanal '{row.get('channel')}'"
                ) from exc

            if channel not in range(4):
                raise ShellyError(
                    f"Zeile {line_number}: Kanal {channel} ist bei Pro 4PM ungültig"
                )

            identity = {
                "mac": normalize_mac(row.get("MAC") or ""),
                "model": (row.get("model") or "").strip(),
                "device_id": (row.get("device_id") or "").strip(),
                "shelly_id": (row.get("Shelly_ID") or "").strip(),
                "desired_device_name": (row.get("desired_device_name") or "").strip(),
            }

            if ip not in devices:
                devices[ip] = {
                    **identity,
                    "ip": ip,
                    "channels": {},
                    "source_lines": [],
                }
            else:
                existing = devices[ip]
                for key, expected in identity.items():
                    if existing[key] != expected:
                        raise ShellyError(
                            f"Zeile {line_number}: widersprüchliche Angabe für {ip}, "
                            f"Feld {key}: '{existing[key]}' / '{expected}'"
                        )

            desired_channel_name = (row.get("desired_channel_name") or "").strip()
            if channel in devices[ip]["channels"]:
                raise ShellyError(
                    f"Zeile {line_number}: Kanal {channel} für {ip} doppelt"
                )

            devices[ip]["channels"][channel] = desired_channel_name
            devices[ip]["source_lines"].append(line_number)

    for ip, device in devices.items():
        missing_channels = set(range(4)).difference(device["channels"])
        if missing_channels:
            raise ShellyError(
                f"{ip}: Kanäle fehlen in der CSV: {sorted(missing_channels)}"
            )
        if not device["desired_device_name"]:
            raise ShellyError(f"{ip}: gewünschter Gerätename ist leer")
        for channel, name in device["channels"].items():
            if not name:
                raise ShellyError(f"{ip}: gewünschter Name für Kanal {channel} ist leer")

    if not devices:
        raise ShellyError("Keine Geräte mit IP in der CSV gefunden")

    return devices


def nested(mapping: dict[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def validate_identity(device: dict[str, Any], info: dict[str, Any]) -> None:
    errors: list[str] = []

    actual_mac = normalize_mac(str(info.get("mac") or ""))
    if device["mac"] and actual_mac != device["mac"]:
        errors.append(f"MAC erwartet {device['mac']}, erhalten {actual_mac}")

    actual_device_id = str(info.get("id") or "")
    if device["device_id"] and actual_device_id != device["device_id"]:
        errors.append(
            f"Geräte-ID erwartet {device['device_id']}, erhalten {actual_device_id}"
        )

    actual_model = str(info.get("model") or "")
    expected_model = device["model"] or EXPECTED_MODEL
    if expected_model and actual_model != expected_model:
        errors.append(f"Modell erwartet {expected_model}, erhalten {actual_model}")

    if errors:
        raise ShellyError("; ".join(errors))


def build_changes(
    device: dict[str, Any],
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []

    current_device_name = str(nested(config, "sys", "device", "name") or "")
    desired_device_name = device["desired_device_name"]
    if current_device_name != desired_device_name:
        changes.append(
            {
                "kind": "device",
                "current": current_device_name,
                "desired": desired_device_name,
            }
        )

    for channel in range(4):
        key = f"switch:{channel}"
        switch_config = config.get(key)
        if not isinstance(switch_config, dict):
            raise ShellyError(f"Komponente {key} fehlt")

        current_name = str(switch_config.get("name") or "")
        desired_name = device["channels"][channel]
        if current_name != desired_name:
            changes.append(
                {
                    "kind": "channel",
                    "channel": channel,
                    "current": current_name,
                    "desired": desired_name,
                }
            )

    return changes


def verify_names(
    device: dict[str, Any],
    config: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    actual_device_name = str(nested(config, "sys", "device", "name") or "")
    if actual_device_name != device["desired_device_name"]:
        errors.append(
            f"Gerätename ist '{actual_device_name}', "
            f"erwartet '{device['desired_device_name']}'"
        )

    for channel in range(4):
        actual_channel_name = str(
            nested(config, f"switch:{channel}", "name") or ""
        )
        expected_channel_name = device["channels"][channel]
        if actual_channel_name != expected_channel_name:
            errors.append(
                f"Kanal {channel} ist '{actual_channel_name}', "
                f"erwartet '{expected_channel_name}'"
            )

    return errors


def save_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Setzt Shelly-Pro-4PM-Geräte- und Kanalnamen aus der CSV."
    )
    parser.add_argument(
        "csv",
        nargs="?",
        default=DEFAULT_CSV,
        help=f"CSV-Datei; Standard: {DEFAULT_CSV}",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Änderungen tatsächlich schreiben. Ohne diese Option nur Trockenlauf.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP-Timeout in Sekunden; Standard: {DEFAULT_TIMEOUT}",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"CSV nicht gefunden: {csv_path}", file=sys.stderr)
        return 2

    try:
        devices = load_devices(csv_path)
    except ShellyError as exc:
        print(f"CSV-FEHLER: {exc}", file=sys.stderr)
        return 2

    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = Path(f"shelly-name-backup-{timestamp}")
    log: dict[str, Any] = {
        "timestamp": timestamp,
        "mode": "apply" if args.apply else "dry-run",
        "csv": str(csv_path.resolve()),
        "devices": [],
    }

    print("MODUS:", "ANWENDEN" if args.apply else "TROCKENLAUF")
    print("Es werden ausschließlich Geräte- und Kanalnamen bearbeitet.")
    print()

    error_count = 0
    changed_device_count = 0
    changed_field_count = 0

    for request_id_base, ip in enumerate(
        sorted(devices, key=lambda address: tuple(map(int, address.split(".")))),
        start=1,
    ):
        device = devices[ip]
        print(
            f"[{ip}] Shelly-ID {device['shelly_id']} – "
            f"{device['device_id']}"
        )

        device_log: dict[str, Any] = {
            "ip": ip,
            "shelly_id": device["shelly_id"],
            "device_id": device["device_id"],
            "status": "",
            "changes": [],
            "errors": [],
        }

        try:
            info = rpc_get(ip, "Shelly.GetDeviceInfo", args.timeout)
            validate_identity(device, info)
            config_before = rpc_get(ip, "Shelly.GetConfig", args.timeout)
            changes = build_changes(device, config_before)
            device_log["changes"] = changes

            if not changes:
                print("  OK: Namen stimmen bereits.")
                device_log["status"] = "already-correct"
                log["devices"].append(device_log)
                continue

            for change in changes:
                old = change["current"] or "(leer)"
                if change["kind"] == "device":
                    print(f"  Gerät: '{old}' → '{change['desired']}'")
                else:
                    print(
                        f"  Kanal {change['channel']}: "
                        f"'{old}' → '{change['desired']}'"
                    )

            changed_device_count += 1
            changed_field_count += len(changes)

            if not args.apply:
                device_log["status"] = "dry-run-change"
                log["devices"].append(device_log)
                continue

            backup_dir.mkdir(parents=True, exist_ok=True)
            safe_device_id = re.sub(r"[^A-Za-z0-9_.-]", "_", device["device_id"])
            save_json(backup_dir / f"{ip}_{safe_device_id}_before.json", config_before)

            request_counter = request_id_base * 100

            for change in changes:
                request_counter += 1
                if change["kind"] == "device":
                    rpc_post(
                        ip,
                        "Sys.SetConfig",
                        {
                            "config": {
                                "device": {
                                    "name": change["desired"],
                                }
                            }
                        },
                        args.timeout,
                        request_counter,
                    )
                else:
                    rpc_post(
                        ip,
                        "Switch.SetConfig",
                        {
                            "id": change["channel"],
                            "config": {
                                "name": change["desired"],
                            },
                        },
                        args.timeout,
                        request_counter,
                    )

            config_after = rpc_get(ip, "Shelly.GetConfig", args.timeout)
            save_json(backup_dir / f"{ip}_{safe_device_id}_after.json", config_after)

            verify_errors = verify_names(device, config_after)
            if verify_errors:
                raise ShellyError(
                    "Verifikation fehlgeschlagen: " + "; ".join(verify_errors)
                )

            print("  ANGEWENDET UND VERIFIZIERT.")
            device_log["status"] = "applied-and-verified"

        except ShellyError as exc:
            error_count += 1
            message = str(exc)
            print(f"  FEHLER: {message}")
            device_log["status"] = "error"
            device_log["errors"].append(message)

        log["devices"].append(device_log)

    log["summary"] = {
        "devices_total": len(devices),
        "devices_with_changes": changed_device_count,
        "fields_with_changes": changed_field_count,
        "errors": error_count,
    }

    log_path = Path(f"shelly-name-run-{timestamp}.json")
    save_json(log_path, log)

    print()
    print(
        f"Ergebnis: {len(devices)} Geräte, "
        f"{changed_device_count} mit Änderungen, "
        f"{changed_field_count} Namensfelder, "
        f"{error_count} Fehler."
    )
    print(f"Protokoll: {log_path.resolve()}")

    if args.apply and backup_dir.exists():
        print(f"Sicherungen: {backup_dir.resolve()}")

    if not args.apply and changed_field_count:
        print()
        print("Zum Anwenden denselben Befehl mit --apply ausführen.")

    return 1 if error_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
