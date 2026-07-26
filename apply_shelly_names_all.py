#!/usr/bin/env python3
"""
Wendet die gewünschten Shelly-Geräte- und Kanalnamen aus dem finalen TSV an.

Wichtig:
- shelly_id wird NICHT zur Identitätsprüfung verwendet.
- Geprüft werden ausschließlich IP, MAC, Modell und technische device_id.
- Es werden nur Namen geändert, keine Ausgänge geschaltet.
- Geräte mit unvollständigen technischen Daten werden übersprungen.
- Vorher-/Nachher-Konfigurationen werden als JSON gesichert.
- Nach dem Anwenden wird jede Änderung erneut vom Gerät gelesen und verifiziert.
- Bei Cover-Komponenten wird abgebrochen, wenn ein Cover gerade fährt/kalibriert.

Trockenlauf:
    python3 apply_shelly_names_all.py Shelly_Gesamtmapping_final_bestaetigt.tsv

Anwenden:
    python3 apply_shelly_names_all.py Shelly_Gesamtmapping_final_bestaetigt.tsv --apply
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

COMPONENT_METHODS = {
    "switch": ("Switch.GetConfig", "Switch.SetConfig"),
    "light": ("Light.GetConfig", "Light.SetConfig"),
    "cover": ("Cover.GetConfig", "Cover.SetConfig"),
}

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


def rpc_get(ip: str, method: str, timeout: float, **params: Any) -> dict[str, Any]:
    if params:
        query = urllib.parse.urlencode(params)
        url = f"http://{ip}/rpc/{method}?{query}"
    else:
        url = f"http://{ip}/rpc/{method}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Shelly-Name-Manager/2.0"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ShellyError(f"{method} auf {ip} nicht erreichbar: {exc}") from exc

    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ShellyError(
            f"{method} auf {ip}: ungültige JSON-Antwort: {payload[:200]}"
        ) from exc

    if not isinstance(value, dict):
        raise ShellyError(f"{method} auf {ip}: unerwartete Antwort")

    if "code" in value and "message" in value:
        raise ShellyError(f"{method} auf {ip}: {value['code']} – {value['message']}")

    return value


def rpc_post(
    ip: str,
    method: str,
    params: dict[str, Any],
    timeout: float,
    request_id: int,
) -> dict[str, Any] | None:
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
            "User-Agent": "Shelly-Name-Manager/2.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ShellyError(f"{method} auf {ip} fehlgeschlagen: {exc}") from exc

    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ShellyError(
            f"{method} auf {ip}: ungültige JSON-Antwort: {text[:200]}"
        ) from exc

    if not isinstance(value, dict):
        raise ShellyError(f"{method} auf {ip}: unerwartete Antwort")

    if "error" in value:
        error = value["error"]
        raise ShellyError(
            f"{method} auf {ip}: {error.get('code')} – {error.get('message')}"
        )

    if "code" in value and "message" in value:
        raise ShellyError(f"{method} auf {ip}: {value['code']} – {value['message']}")

    result = value.get("result", value.get("params"))
    return result if isinstance(result, dict) else None


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        headers = reader.fieldnames or []
        if headers != EXPECTED_HEADERS:
            raise ShellyError(
                "TSV-Spalten stimmen nicht mit dem finalen Format überein.\n"
                f"Erwartet: {EXPECTED_HEADERS}\n"
                f"Erhalten: {headers}"
            )
        rows = list(reader)

    if not rows:
        raise ShellyError("TSV enthält keine Gerätezeilen.")

    seen_ips: set[str] = set()
    for line_number, row in enumerate(rows, start=2):
        ip = row["ip"].strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ShellyError(f"Zeile {line_number}: ungültige IP '{ip}'.") from exc

        if ip in seen_ips:
            raise ShellyError(f"Zeile {line_number}: doppelte IP {ip}.")
        seen_ips.add(ip)

        if not row["desired_device_name"].strip():
            raise ShellyError(
                f"Zeile {line_number} / {ip}: gewünschter Gerätename fehlt."
            )

        for channel in range(4):
            component_type = row[f"channel_{channel}_type"].strip().lower()
            desired_name = row[f"desired_channel_{channel}_name"].strip()

            if component_type and component_type not in COMPONENT_METHODS:
                raise ShellyError(
                    f"Zeile {line_number} / {ip}: unbekannter Kanaltyp "
                    f"'{component_type}' bei Kanal {channel}."
                )

            if component_type and not desired_name:
                raise ShellyError(
                    f"Zeile {line_number} / {ip}: Sollname für Kanal "
                    f"{channel} fehlt."
                )

    return rows


def technical_data_complete(row: dict[str, str]) -> bool:
    return all(
        row[field].strip()
        for field in ("ip", "mac", "model", "device_id")
    ) and any(
        row[f"channel_{channel}_type"].strip()
        for channel in range(4)
    )


def validate_identity(row: dict[str, str], info: dict[str, Any]) -> None:
    errors: list[str] = []

    expected_mac = normalize_mac(row["mac"])
    actual_mac = normalize_mac(str(info.get("mac") or ""))
    if actual_mac != expected_mac:
        errors.append(f"MAC erwartet {expected_mac}, erhalten {actual_mac}")

    expected_device_id = row["device_id"].strip()
    actual_device_id = str(info.get("id") or "")
    if actual_device_id != expected_device_id:
        errors.append(
            f"device_id erwartet {expected_device_id}, erhalten {actual_device_id}"
        )

    expected_model = row["model"].strip()
    actual_model = str(info.get("model") or "")
    if actual_model != expected_model:
        errors.append(f"Modell erwartet {expected_model}, erhalten {actual_model}")

    if errors:
        raise ShellyError("; ".join(errors))


def get_current_names(
    row: dict[str, str],
    config: dict[str, Any],
) -> tuple[str, dict[int, str]]:
    sys_config = config.get("sys")
    if not isinstance(sys_config, dict):
        raise ShellyError("Komponente sys fehlt in Shelly.GetConfig.")

    device = sys_config.get("device")
    if not isinstance(device, dict):
        raise ShellyError("sys.device fehlt in Shelly.GetConfig.")

    device_name = str(device.get("name") or "")
    channel_names: dict[int, str] = {}

    for channel in range(4):
        component_type = row[f"channel_{channel}_type"].strip().lower()
        if not component_type:
            continue

        key = f"{component_type}:{channel}"
        component_config = config.get(key)
        if not isinstance(component_config, dict):
            raise ShellyError(f"Komponente {key} fehlt in Shelly.GetConfig.")

        channel_names[channel] = str(component_config.get("name") or "")

    return device_name, channel_names


def ensure_covers_idle(row: dict[str, str], timeout: float) -> None:
    ip = row["ip"].strip()

    for channel in range(4):
        if row[f"channel_{channel}_type"].strip().lower() != "cover":
            continue

        status = rpc_get(ip, "Cover.GetStatus", timeout, id=channel)
        state = str(status.get("state") or "").lower()
        calibrating = bool(status.get("calibrating", False))

        if state in {"opening", "closing"} or calibrating:
            raise ShellyError(
                f"cover:{channel} bewegt sich oder kalibriert. "
                "Cover stoppen und erneut starten."
            )


def build_changes(
    row: dict[str, str],
    current_device_name: str,
    current_channel_names: dict[int, str],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []

    desired_device_name = row["desired_device_name"].strip()
    if current_device_name != desired_device_name:
        changes.append(
            {
                "kind": "device",
                "current": current_device_name,
                "desired": desired_device_name,
            }
        )

    for channel, current_name in current_channel_names.items():
        component_type = row[f"channel_{channel}_type"].strip().lower()
        desired_name = row[f"desired_channel_{channel}_name"].strip()

        if current_name != desired_name:
            changes.append(
                {
                    "kind": "component",
                    "component_type": component_type,
                    "channel": channel,
                    "current": current_name,
                    "desired": desired_name,
                }
            )

    return changes


def verify_names(
    row: dict[str, str],
    config: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    current_device_name, current_channels = get_current_names(row, config)

    desired_device_name = row["desired_device_name"].strip()
    if current_device_name != desired_device_name:
        errors.append(
            f"Gerätename ist '{current_device_name}', "
            f"erwartet '{desired_device_name}'"
        )

    for channel, current_name in current_channels.items():
        desired_name = row[f"desired_channel_{channel}_name"].strip()
        if current_name != desired_name:
            component_type = row[f"channel_{channel}_type"].strip().lower()
            errors.append(
                f"{component_type}:{channel} ist '{current_name}', "
                f"erwartet '{desired_name}'"
            )

    return errors


def save_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_result_tsv(
    source_path: Path,
    rows: list[dict[str, str]],
    timestamp: str,
) -> Path:
    output = source_path.with_name(
        f"{source_path.stem}_nach_lauf_{timestamp}.tsv"
    )

    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=EXPECTED_HEADERS,
            delimiter="\t",
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Setzt Shelly-Geräte- und Kanalnamen aus dem finalen Gesamtmapping. "
            "shelly_id wird bewusst nicht validiert."
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
        help="Änderungen schreiben. Ohne diese Option nur Trockenlauf.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP-Timeout in Sekunden; Standard: {DEFAULT_TIMEOUT}",
    )
    args = parser.parse_args()

    source_path = Path(args.tsv)
    if not source_path.exists():
        print(f"TSV nicht gefunden: {source_path}", file=sys.stderr)
        return 2

    try:
        rows = load_rows(source_path)
    except ShellyError as exc:
        print(f"DATEIFEHLER: {exc}", file=sys.stderr)
        return 2

    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = Path(f"shelly-name-backup-all-{timestamp}")
    log_path = Path(f"shelly-name-run-all-{timestamp}.json")

    run_log: dict[str, Any] = {
        "timestamp": timestamp,
        "mode": "apply" if args.apply else "dry-run",
        "source": str(source_path.resolve()),
        "identity_check": "IP + MAC + model + device_id; shelly_id ignored",
        "devices": [],
    }

    print("MODUS:", "ANWENDEN" if args.apply else "TROCKENLAUF")
    print("Identitätsprüfung: IP, MAC, Modell und technische device_id.")
    print("shelly_id wird nicht geprüft.")
    print("Es werden ausschließlich Namen geändert; keine Ausgänge geschaltet.")
    print()

    changed_devices = 0
    changed_fields = 0
    applied_devices = 0
    skipped_devices = 0
    error_count = 0
    request_id = 1000

    for row in rows:
        ip = row["ip"].strip()
        shelly_id = row["shelly_id"].strip() or "-"
        print(f"[{ip}] Dokumentations-ID {shelly_id} – {row['desired_device_name']}")

        entry: dict[str, Any] = {
            "ip": ip,
            "shelly_id_documentation_only": shelly_id,
            "device_id": row["device_id"].strip(),
            "status": "",
            "changes": [],
            "errors": [],
        }

        if not technical_data_complete(row):
            skipped_devices += 1
            reason = (
                "übersprungen: technische Daten oder Kanaltypen unvollständig"
            )
            print(f"  ÜBERSPRUNGEN: {reason}")
            row["status_hinweis"] = (
                f"{row['status_hinweis'].strip()} Lauf {timestamp}: {reason}."
            ).strip()
            entry["status"] = "skipped-incomplete"
            entry["errors"].append(reason)
            run_log["devices"].append(entry)
            continue

        try:
            info = rpc_get(ip, "Shelly.GetDeviceInfo", args.timeout)
            validate_identity(row, info)

            config_before = rpc_get(ip, "Shelly.GetConfig", args.timeout)
            current_device_name, current_channel_names = get_current_names(
                row,
                config_before,
            )

            row["current_device_name"] = current_device_name
            for channel, current_name in current_channel_names.items():
                row[f"current_channel_{channel}_name"] = current_name

            changes = build_changes(
                row,
                current_device_name,
                current_channel_names,
            )
            entry["changes"] = changes

            if not changes:
                print("  OK: Namen stimmen bereits.")
                row["status_hinweis"] = (
                    f"Lauf {timestamp}: Namen bereits korrekt verifiziert."
                )
                entry["status"] = "already-correct"
                run_log["devices"].append(entry)
                continue

            changed_devices += 1
            changed_fields += len(changes)

            for change in changes:
                current = change["current"] or "(leer)"
                if change["kind"] == "device":
                    print(f"  Gerät: '{current}' → '{change['desired']}'")
                else:
                    print(
                        f"  {change['component_type']}:{change['channel']}: "
                        f"'{current}' → '{change['desired']}'"
                    )

            if not args.apply:
                row["status_hinweis"] = (
                    f"Trockenlauf {timestamp}: {len(changes)} Namensänderungen vorgesehen."
                )
                entry["status"] = "dry-run-change"
                run_log["devices"].append(entry)
                continue

            ensure_covers_idle(row, args.timeout)

            backup_dir.mkdir(parents=True, exist_ok=True)
            safe_id = re.sub(
                r"[^A-Za-z0-9_.-]",
                "_",
                row["device_id"].strip(),
            )
            save_json(
                backup_dir / f"{ip}_{safe_id}_device_info.json",
                info,
            )
            save_json(
                backup_dir / f"{ip}_{safe_id}_before.json",
                config_before,
            )

            for change in changes:
                request_id += 1

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
                        request_id,
                    )
                    continue

                component_type = change["component_type"]
                _, set_method = COMPONENT_METHODS[component_type]
                rpc_post(
                    ip,
                    set_method,
                    {
                        "id": change["channel"],
                        "config": {
                            "name": change["desired"],
                        },
                    },
                    args.timeout,
                    request_id,
                )

            config_after = rpc_get(ip, "Shelly.GetConfig", args.timeout)
            save_json(
                backup_dir / f"{ip}_{safe_id}_after.json",
                config_after,
            )

            verification_errors = verify_names(row, config_after)
            if verification_errors:
                raise ShellyError(
                    "Verifikation fehlgeschlagen: "
                    + "; ".join(verification_errors)
                )

            new_device_name, new_channel_names = get_current_names(
                row,
                config_after,
            )
            row["current_device_name"] = new_device_name
            for channel, current_name in new_channel_names.items():
                row[f"current_channel_{channel}_name"] = current_name

            row["status_hinweis"] = (
                f"Angewendet und verifiziert am {timestamp}; "
                "shelly_id nur Dokumentation."
            )
            print("  ANGEWENDET UND VERIFIZIERT.")
            applied_devices += 1
            entry["status"] = "applied-and-verified"

        except ShellyError as exc:
            error_count += 1
            message = str(exc)
            print(f"  FEHLER: {message}")
            row["status_hinweis"] = (
                f"Lauf {timestamp}: FEHLER – {message}"
            )
            entry["status"] = "error"
            entry["errors"].append(message)

        run_log["devices"].append(entry)

    result_path = write_result_tsv(source_path, rows, timestamp)

    run_log["summary"] = {
        "devices_total": len(rows),
        "devices_with_changes": changed_devices,
        "fields_with_changes": changed_fields,
        "devices_applied": applied_devices,
        "devices_skipped": skipped_devices,
        "errors": error_count,
        "result_tsv": str(result_path.resolve()),
    }
    save_json(log_path, run_log)

    print()
    print(
        f"Ergebnis: {len(rows)} Geräte, "
        f"{changed_devices} mit Änderungen, "
        f"{changed_fields} Namensfelder, "
        f"{applied_devices} angewendet, "
        f"{skipped_devices} übersprungen, "
        f"{error_count} Fehler."
    )
    print(f"Ergebnis-TSV: {result_path.resolve()}")
    print(f"Protokoll: {log_path.resolve()}")

    if args.apply and backup_dir.exists():
        print(f"Sicherungen: {backup_dir.resolve()}")

    if not args.apply and changed_fields:
        print()
        print("Zum Anwenden denselben Befehl zusätzlich mit --apply starten.")

    return 1 if error_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
