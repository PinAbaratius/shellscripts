#!/usr/bin/env python3
"""
Setzt für alle als Steckdose dokumentierten Switch-Kanäle aus der TSV:
    initial_state = "on"

Erkannt werden Kanalnamen mit dem Muster -SDxx-, z. B.:
    WZ-20-0-SD01-B-EZ-LS-NB

Trockenlauf:
    python3 set_shelly_socket_power_on.py Shelly_Gesamtmapping_final_bestaetigt.tsv

Anwenden:
    python3 set_shelly_socket_power_on.py Shelly_Gesamtmapping_final_bestaetigt.tsv --apply

Sicherheit:
- Identitätsprüfung über IP, MAC, Modell und technische device_id
- shelly_id wird nicht geprüft
- ausschließlich Switch.SetConfig wird verwendet
- aktuelle Ausgänge werden nicht geschaltet
- Zustand wird vor und nach der Änderung geprüft
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_TSV = "Shelly_Gesamtmapping_final_bestaetigt.tsv"
DEFAULT_TIMEOUT = 4.0
SOCKET_PATTERN = re.compile(r"(?:^|-)SD\d{2}(?:-|$)", re.IGNORECASE)

EXPECTED_HEADERS = [
    "ip",
    "mac",
    "model",
    "device_id",
    "shelly_id",
    "current_device_name",
    "desired_device_name",
    "channel_0_type",
    "current_channel_0_name",
    "desired_channel_0_name",
    "channel_1_type",
    "current_channel_1_name",
    "desired_channel_1_name",
    "channel_2_type",
    "current_channel_2_name",
    "desired_channel_2_name",
    "channel_3_type",
    "current_channel_3_name",
    "desired_channel_3_name",
    "firmware",
    "status_hinweis",
]


class ShellyError(RuntimeError):
    pass


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    if len(compact) != 12:
        return (value or "").strip().upper()
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def rpc_get(
    ip: str,
    method: str,
    params: dict[str, Any] | None,
    timeout: float,
) -> dict[str, Any]:
    url = f"http://{ip}/rpc/{method}"
    if params:
        query = urllib.parse.urlencode(
            {
                key: json.dumps(value, separators=(",", ":"))
                if isinstance(value, (dict, list, bool))
                else value
                for key, value in params.items()
            }
        )
        url = f"{url}?{query}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Shelly-Socket-Power-On/1.0"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ShellyError(f"{method} nicht erreichbar: {exc}") from exc

    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ShellyError(
            f"{method}: ungültige JSON-Antwort: {text[:200]}"
        ) from exc

    if not isinstance(value, dict):
        raise ShellyError(f"{method}: unerwartete Antwort")

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
    payload = json.dumps(
        {
            "id": request_id,
            "method": method,
            "params": params,
        },
        ensure_ascii=False,
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Shelly-Socket-Power-On/1.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ShellyError(f"{method} fehlgeschlagen: {exc}") from exc

    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ShellyError(
            f"{method}: ungültige JSON-Antwort: {text[:200]}"
        ) from exc

    if not isinstance(value, dict):
        raise ShellyError(f"{method}: unerwartete Antwort")

    if "error" in value:
        error = value["error"]
        raise ShellyError(
            f"{method}: {error.get('code')} – {error.get('message')}"
        )

    if "code" in value and "message" in value:
        raise ShellyError(f"{method}: {value['code']} – {value['message']}")

    result = value.get("result", value.get("params", value))
    return result if isinstance(result, dict) else {}


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        headers = reader.fieldnames or []

        if headers != EXPECTED_HEADERS:
            raise ShellyError(
                "TSV-Spalten stimmen nicht mit dem erwarteten Format überein."
            )

        rows = list(reader)

    if not rows:
        raise ShellyError("TSV enthält keine Geräte.")

    seen_ips: set[str] = set()

    for line_number, row in enumerate(rows, start=2):
        ip = row["ip"].strip()

        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ShellyError(
                f"Zeile {line_number}: ungültige IP '{ip}'"
            ) from exc

        if ip in seen_ips:
            raise ShellyError(f"Zeile {line_number}: doppelte IP {ip}")

        seen_ips.add(ip)

    return rows


def socket_channels(row: dict[str, str]) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []

    for channel in range(4):
        channel_type = row[f"channel_{channel}_type"].strip().lower()
        channel_name = row[f"desired_channel_{channel}_name"].strip()

        if channel_type == "switch" and SOCKET_PATTERN.search(channel_name):
            result.append((channel, channel_name))

    return result


def validate_identity(row: dict[str, str], info: dict[str, Any]) -> None:
    errors: list[str] = []

    expected_mac = normalize_mac(row["mac"])
    actual_mac = normalize_mac(str(info.get("mac") or ""))
    if actual_mac != expected_mac:
        errors.append(f"MAC erwartet {expected_mac}, erhalten {actual_mac}")

    expected_model = row["model"].strip()
    actual_model = str(info.get("model") or "")
    if actual_model != expected_model:
        errors.append(
            f"Modell erwartet {expected_model}, erhalten {actual_model}"
        )

    expected_device_id = row["device_id"].strip()
    actual_device_id = str(info.get("id") or "")
    if actual_device_id != expected_device_id:
        errors.append(
            f"device_id erwartet {expected_device_id}, erhalten {actual_device_id}"
        )

    if errors:
        raise ShellyError("; ".join(errors))


def save_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Setzt initial_state=on für alle als SD dokumentierten "
            "Steckdosenkanäle."
        )
    )
    parser.add_argument(
        "tsv",
        nargs="?",
        default=DEFAULT_TSV,
        help=f"TSV-Datei; Standard: {DEFAULT_TSV}",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Änderungen tatsächlich anwenden.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP-Timeout; Standard: {DEFAULT_TIMEOUT} Sekunden",
    )
    args = parser.parse_args()

    source = Path(args.tsv)
    if not source.exists():
        print(f"TSV nicht gefunden: {source}", file=sys.stderr)
        return 2

    try:
        rows = load_rows(source)
    except ShellyError as exc:
        print(f"DATEIFEHLER: {exc}", file=sys.stderr)
        return 2

    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = Path(f"shelly-socket-poweron-backup-{timestamp}")
    log_path = Path(f"shelly-socket-poweron-run-{timestamp}.json")

    log: dict[str, Any] = {
        "timestamp": timestamp,
        "mode": "apply" if args.apply else "dry-run",
        "source": str(source.resolve()),
        "target": 'Switch.initial_state = "on"',
        "devices": [],
    }

    print("MODUS:", "ANWENDEN" if args.apply else "TROCKENLAUF")
    print("Ziel: alle als SD dokumentierten Steckdosen starten nach Stromausfall EIN.")
    print("Identitätsprüfung: IP, MAC, Modell und technische device_id.")
    print("Die aktuellen Ausgangszustände werden nicht geschaltet.")
    print()

    devices_targeted = 0
    channels_total = 0
    channels_already_on = 0
    channels_changes_needed = 0
    channels_applied = 0
    devices_skipped = 0
    restart_required_count = 0
    errors = 0
    request_id = 3000

    for row in rows:
        targets = socket_channels(row)
        if not targets:
            continue

        devices_targeted += 1
        channels_total += len(targets)

        ip = row["ip"].strip()
        name = row["desired_device_name"].strip()
        print(f"[{ip}] {name}")

        entry: dict[str, Any] = {
            "ip": ip,
            "device_id": row["device_id"].strip(),
            "channels": [],
            "errors": [],
        }

        if not all(
            row[field].strip()
            for field in ("ip", "mac", "model", "device_id")
        ):
            devices_skipped += 1
            print("  ÜBERSPRUNGEN: technische Identitätsdaten unvollständig")
            entry["status"] = "skipped-incomplete"
            log["devices"].append(entry)
            continue

        try:
            info = rpc_get(ip, "Shelly.GetDeviceInfo", None, args.timeout)
            validate_identity(row, info)
        except ShellyError as exc:
            errors += 1
            message = str(exc)
            print(f"  FEHLER: {message}")
            entry["status"] = "identity-error"
            entry["errors"].append(message)
            log["devices"].append(entry)
            continue

        device_had_error = False

        for channel, channel_name in targets:
            channel_entry: dict[str, Any] = {
                "channel": channel,
                "name": channel_name,
                "before": None,
                "after": None,
                "status": "",
                "restart_required": False,
                "errors": [],
            }

            try:
                before = rpc_get(
                    ip,
                    "Switch.GetConfig",
                    {"id": channel},
                    args.timeout,
                )
                channel_entry["before"] = before

                current = str(before.get("initial_state") or "")
                if current == "on":
                    channels_already_on += 1
                    channel_entry["status"] = "already-on"
                    print(
                        f"  switch:{channel} {channel_name}: "
                        "OK, initial_state ist bereits 'on'."
                    )
                    entry["channels"].append(channel_entry)
                    continue

                channels_changes_needed += 1
                print(
                    f"  switch:{channel} {channel_name}: "
                    f"'{current or '(leer)'}' → 'on'"
                )

                if not args.apply:
                    channel_entry["status"] = "dry-run-change"
                    entry["channels"].append(channel_entry)
                    continue

                backup_dir.mkdir(parents=True, exist_ok=True)
                safe_id = re.sub(
                    r"[^A-Za-z0-9_.-]",
                    "_",
                    row["device_id"].strip(),
                )
                save_json(
                    backup_dir
                    / f"{ip}_{safe_id}_switch-{channel}_before.json",
                    before,
                )

                request_id += 1
                result = rpc_post(
                    ip,
                    "Switch.SetConfig",
                    {
                        "id": channel,
                        "config": {"initial_state": "on"},
                    },
                    args.timeout,
                    request_id,
                )

                restart_required = bool(
                    result.get("restart_required", False)
                )
                channel_entry["restart_required"] = restart_required
                if restart_required:
                    restart_required_count += 1

                after = rpc_get(
                    ip,
                    "Switch.GetConfig",
                    {"id": channel},
                    args.timeout,
                )
                channel_entry["after"] = after

                save_json(
                    backup_dir
                    / f"{ip}_{safe_id}_switch-{channel}_after.json",
                    after,
                )

                if str(after.get("initial_state") or "") != "on":
                    raise ShellyError(
                        "Verifikation fehlgeschlagen: "
                        f"initial_state={after.get('initial_state')!r}"
                    )

                channels_applied += 1
                channel_entry["status"] = "applied-and-verified"

                if restart_required:
                    print(
                        "    ANGEWENDET UND VERIFIZIERT; "
                        "Gerät meldet Neustart erforderlich."
                    )
                else:
                    print("    ANGEWENDET UND VERIFIZIERT.")

            except ShellyError as exc:
                errors += 1
                device_had_error = True
                message = str(exc)
                print(f"    FEHLER: {message}")
                channel_entry["status"] = "error"
                channel_entry["errors"].append(message)

            entry["channels"].append(channel_entry)

        entry["status"] = "error" if device_had_error else "processed"
        log["devices"].append(entry)

    log["summary"] = {
        "devices_total_in_tsv": len(rows),
        "devices_with_socket_channels": devices_targeted,
        "socket_channels_total": channels_total,
        "already_initial_state_on": channels_already_on,
        "changes_needed": channels_changes_needed,
        "applied_and_verified": channels_applied,
        "devices_skipped": devices_skipped,
        "restart_required": restart_required_count,
        "errors": errors,
    }
    save_json(log_path, log)

    print()
    print(
        f"Ergebnis: {devices_targeted} Geräte mit Steckdosen, "
        f"{channels_total} Steckdosenkanäle, "
        f"{channels_already_on} bereits auf 'on', "
        f"{channels_changes_needed} mit Änderungsbedarf, "
        f"{channels_applied} angewendet, "
        f"{devices_skipped} Geräte übersprungen, "
        f"{restart_required_count} mit Neustarthinweis, "
        f"{errors} Fehler."
    )
    print(f"Protokoll: {log_path.resolve()}")

    if args.apply and backup_dir.exists():
        print(f"Sicherungen: {backup_dir.resolve()}")

    if not args.apply and channels_changes_needed:
        print()
        print("Zum Anwenden denselben Befehl zusätzlich mit --apply starten.")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
