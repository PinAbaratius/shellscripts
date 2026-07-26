#!/usr/bin/env python3
"""
Deaktiviert Bluetooth/BLE auf allen technisch vollständig erfassten Shellys
aus Shelly_Gesamtmapping_final_bestaetigt.tsv.

Trockenlauf:
    python3 disable_shelly_bt.py Shelly_Gesamtmapping_final_bestaetigt.tsv

Anwenden:
    python3 disable_shelly_bt.py Shelly_Gesamtmapping_final_bestaetigt.tsv --apply

Sicherheit:
- Identitätsprüfung über IP, MAC, Modell und technische device_id
- shelly_id wird nicht zur Prüfung verwendet
- keine Ausgänge werden geschaltet
- unvollständige Geräte wie .128 werden übersprungen
- BLE.GetConfig wird vor und nach der Änderung geprüft
- unterstützt die tatsächlich vom Gerät gelieferten Felder:
  enable, rpc.enable, observer.enable und keep_running
- kein automatischer Neustart
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


def rpc_get(ip: str, method: str, timeout: float) -> dict[str, Any]:
    url = f"http://{ip}/rpc/{method}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Shelly-BLE-Disabler/1.0"},
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
            "User-Agent": "Shelly-BLE-Disabler/1.0",
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


def technical_data_complete(row: dict[str, str]) -> bool:
    return all(
        row[field].strip()
        for field in ("ip", "mac", "model", "device_id")
    )


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


def desired_ble_patch(config: dict[str, Any]) -> dict[str, Any]:
    patch: dict[str, Any] = {}

    if "enable" in config:
        patch["enable"] = False

    rpc = config.get("rpc")
    if isinstance(rpc, dict) and "enable" in rpc:
        patch["rpc"] = {"enable": False}

    observer = config.get("observer")
    if isinstance(observer, dict) and "enable" in observer:
        patch["observer"] = {"enable": False}

    if "keep_running" in config:
        patch["keep_running"] = False

    return patch


def ble_is_disabled(config: dict[str, Any]) -> tuple[bool, list[str]]:
    active: list[str] = []

    if config.get("enable") is True:
        active.append("enable=true")

    rpc = config.get("rpc")
    if isinstance(rpc, dict) and rpc.get("enable") is True:
        active.append("rpc.enable=true")

    observer = config.get("observer")
    if isinstance(observer, dict) and observer.get("enable") is True:
        active.append("observer.enable=true")

    if config.get("keep_running") is True:
        active.append("keep_running=true")

    return not active, active


def save_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deaktiviert Bluetooth/BLE auf allen Shellys der TSV."
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
        help="BLE tatsächlich deaktivieren. Ohne Option nur Trockenlauf.",
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
    backup_dir = Path(f"shelly-ble-backup-{timestamp}")
    log_path = Path(f"shelly-ble-run-{timestamp}.json")

    log: dict[str, Any] = {
        "timestamp": timestamp,
        "mode": "apply" if args.apply else "dry-run",
        "source": str(source.resolve()),
        "devices": [],
    }

    print("MODUS:", "ANWENDEN" if args.apply else "TROCKENLAUF")
    print("Identitätsprüfung: IP, MAC, Modell und technische device_id.")
    print("Es wird ausschließlich Bluetooth/BLE deaktiviert.")
    print("Kein automatischer Neustart.")
    print()

    already_disabled = 0
    changes_needed = 0
    applied = 0
    skipped = 0
    errors = 0
    restart_required_count = 0
    request_id = 2000

    for row in rows:
        ip = row["ip"].strip()
        name = row["desired_device_name"].strip()
        print(f"[{ip}] {name}")

        entry: dict[str, Any] = {
            "ip": ip,
            "device_id": row["device_id"].strip(),
            "status": "",
            "before": None,
            "patch": None,
            "after": None,
            "restart_required": False,
            "errors": [],
        }

        if not technical_data_complete(row):
            skipped += 1
            print("  ÜBERSPRUNGEN: technische Identitätsdaten unvollständig")
            entry["status"] = "skipped-incomplete"
            log["devices"].append(entry)
            continue

        try:
            info = rpc_get(ip, "Shelly.GetDeviceInfo", args.timeout)
            validate_identity(row, info)

            before = rpc_get(ip, "BLE.GetConfig", args.timeout)
            entry["before"] = before

            disabled, active = ble_is_disabled(before)
            if disabled:
                already_disabled += 1
                print("  OK: Bluetooth/BLE ist bereits deaktiviert.")
                entry["status"] = "already-disabled"
                log["devices"].append(entry)
                continue

            patch = desired_ble_patch(before)
            entry["patch"] = patch

            if not patch:
                raise ShellyError(
                    "BLE.GetConfig enthält keine unterstützten Schalter."
                )

            changes_needed += 1
            print("  Aktiv:", ", ".join(active))
            print(
                "  Geplant:",
                json.dumps(patch, ensure_ascii=False, separators=(",", ":")),
            )

            if not args.apply:
                entry["status"] = "dry-run-change"
                log["devices"].append(entry)
                continue

            backup_dir.mkdir(parents=True, exist_ok=True)
            safe_id = re.sub(
                r"[^A-Za-z0-9_.-]",
                "_",
                row["device_id"].strip(),
            )
            save_json(
                backup_dir / f"{ip}_{safe_id}_ble_before.json",
                before,
            )

            request_id += 1
            result = rpc_post(
                ip,
                "BLE.SetConfig",
                {"config": patch},
                args.timeout,
                request_id,
            )

            restart_required = bool(result.get("restart_required", False))
            entry["restart_required"] = restart_required
            if restart_required:
                restart_required_count += 1

            after = rpc_get(ip, "BLE.GetConfig", args.timeout)
            entry["after"] = after
            save_json(
                backup_dir / f"{ip}_{safe_id}_ble_after.json",
                after,
            )

            disabled_after, still_active = ble_is_disabled(after)
            if not disabled_after:
                raise ShellyError(
                    "Verifikation fehlgeschlagen; weiterhin aktiv: "
                    + ", ".join(still_active)
                )

            applied += 1
            entry["status"] = "disabled-and-verified"

            if restart_required:
                print(
                    "  DEAKTIVIERT UND VERIFIZIERT; "
                    "Gerät meldet zusätzlich Neustart erforderlich."
                )
            else:
                print("  DEAKTIVIERT UND VERIFIZIERT.")

        except ShellyError as exc:
            errors += 1
            message = str(exc)
            print(f"  FEHLER: {message}")
            entry["status"] = "error"
            entry["errors"].append(message)

        log["devices"].append(entry)

    log["summary"] = {
        "devices_total": len(rows),
        "already_disabled": already_disabled,
        "changes_needed": changes_needed,
        "applied": applied,
        "skipped": skipped,
        "restart_required": restart_required_count,
        "errors": errors,
    }
    save_json(log_path, log)

    print()
    print(
        f"Ergebnis: {len(rows)} Geräte, "
        f"{already_disabled} bereits aus, "
        f"{changes_needed} mit Änderungsbedarf, "
        f"{applied} deaktiviert, "
        f"{skipped} übersprungen, "
        f"{restart_required_count} mit Neustarthinweis, "
        f"{errors} Fehler."
    )
    print(f"Protokoll: {log_path.resolve()}")

    if args.apply and backup_dir.exists():
        print(f"Sicherungen: {backup_dir.resolve()}")

    if not args.apply and changes_needed:
        print()
        print("Zum Anwenden denselben Befehl zusätzlich mit --apply starten.")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
