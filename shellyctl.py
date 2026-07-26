#!/usr/bin/env python3
"""
shellyctl.py – universelles Verwaltungswerkzeug für Shelly Gen2-Geräte.

Trockenlauf ist bei allen schreibenden Aktionen der Standard.
Nur --apply führt Änderungen tatsächlich aus.

Die festen Aktionen decken häufige Verwaltungsaufgaben ab. Über die Aktion
"rpc" kann jede RPC-Methode genutzt werden, die das jeweilige Gen2-Gerät über
Shelly.ListMethods anbietet.

Beispiele
=========
Aktionen anzeigen:
    python3 shellyctl.py actions

Bestand und Audit:
    python3 shellyctl.py inventory
    python3 shellyctl.py audit
    python3 shellyctl.py methods --target 192.168.178.138
    python3 shellyctl.py backup

Feste Aktionen – zunächst Trockenlauf:
    python3 shellyctl.py bt-off
    python3 shellyctl.py cloud-off
    python3 shellyctl.py socket-boot-on
    python3 shellyctl.py firmware-update-stable

Anwenden:
    python3 shellyctl.py bt-off --apply
    python3 shellyctl.py socket-boot-on --apply
    python3 shellyctl.py firmware-update-stable --apply

Freie RPC-Aufrufe:
    python3 shellyctl.py rpc \
      --target 192.168.178.138 \
      --method Switch.GetConfig \
      --params '{"id":0}'

    python3 shellyctl.py rpc \
      --target 192.168.178.138 \
      --method Switch.Set \
      --params '{"id":0,"on":true}'
    # Nur Anzeige, weil --apply fehlt.

    python3 shellyctl.py rpc \
      --target 192.168.178.138 \
      --method Switch.Set \
      --params '{"id":0,"on":true}' \
      --apply

Ein Aufruf pro dokumentiertem Kanal:
    python3 shellyctl.py rpc \
      --target sockets \
      --method Switch.GetStatus \
      --channels all

Parameter-Platzhalter im freien RPC-Modus:
    {ip}
    {device_id}
    {device_name}
    {channel}
    {channel_name}

Authentifizierung:
    export SHELLY_PASSWORD='dein-passwort'
    python3 shellyctl.py audit

Alternativ:
    python3 shellyctl.py audit --password 'dein-passwort'

Hinweis: Ein Passwort als Kommandozeilenparameter kann in der Shell-Historie
sichtbar sein. Die Umgebungsvariable SHELLY_PASSWORD ist vorzuziehen.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import getpass
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


PROGRAM_VERSION = "1.1.1-update-stable"
DEFAULT_TSV = "Shelly_Gesamtmapping_final_bestaetigt.tsv"
DEFAULT_TIMEOUT = 5.0
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

READ_ACTIONS = {
    "inventory",
    "methods",
    "status",
    "config",
    "audit",
    "backup",
    "firmware-check",
}

CONFIG_ACTIONS = {
    "bt-off",
    "bt-on",
    "cloud-off",
    "cloud-on",
    "mqtt-off",
    "mqtt-on",
}

BOOT_ACTION_VALUES = {
    "socket-boot-on": "on",
    "socket-boot-off": "off",
    "socket-boot-restore": "restore_last",
    "socket-boot-match-input": "match_input",
    "switch-boot-on": "on",
    "switch-boot-off": "off",
    "switch-boot-restore": "restore_last",
    "switch-boot-match-input": "match_input",
}

WRITE_ACTIONS = {
    *CONFIG_ACTIONS,
    *BOOT_ACTION_VALUES,
    "firmware-update-stable",
    "reboot",
}

ALL_ACTIONS = {
    "actions",
    *READ_ACTIONS,
    *WRITE_ACTIONS,
    "rpc",
}

READ_METHOD_PREFIXES = (
    "Get",
    "List",
    "Check",
    "Query",
    "Read",
    "Detect",
)

DANGEROUS_METHODS = {
    "Shelly.FactoryReset",
    "Shelly.ResetWiFiConfig",
    "Shelly.SetAuth",
    "Shelly.SetProfile",
    "Shelly.Update",
}

DANGEROUS_FRAGMENTS = (
    "FactoryReset",
    "ResetWiFi",
    "SetAuth",
    "SetProfile",
    ".Delete",
    "DeleteAll",
    "ResetCounters",
    "PutTLS",
    "PutHTTPServer",
)


class ShellyCtlError(RuntimeError):
    pass


class AuthenticationRequired(ShellyCtlError):
    pass


def timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    if len(compact) != 12:
        return (value or "").strip().upper()
    return ":".join(
        compact[index:index + 2]
        for index in range(0, 12, 2)
    )


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def parse_params(
    raw: str | None,
    params_file: str | None,
) -> dict[str, Any]:
    if raw and params_file:
        raise ShellyCtlError(
            "--params und --params-file nicht gleichzeitig verwenden."
        )

    if params_file:
        try:
            text = Path(params_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise ShellyCtlError(
                f"Parameterdatei nicht lesbar: {exc}"
            ) from exc
    else:
        text = raw or "{}"

    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ShellyCtlError(
            f"RPC-Parameter sind kein gültiges JSON: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise ShellyCtlError(
            "RPC-Parameter müssen ein JSON-Objekt sein."
        )

    return value


def replace_markers(value: Any, markers: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {
            key: replace_markers(item, markers)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [replace_markers(item, markers) for item in value]
    if isinstance(value, str):
        result = value
        for marker, replacement in markers.items():
            result = result.replace(marker, replacement)
        return result
    return value


def load_tsv(path: Path) -> list[dict[str, str]]:
    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ShellyCtlError(f"TSV nicht lesbar: {exc}") from exc

    with handle:
        reader = csv.DictReader(handle, delimiter="\t")
        headers = reader.fieldnames or []

        if headers != EXPECTED_HEADERS:
            raise ShellyCtlError(
                "TSV-Spalten stimmen nicht mit dem erwarteten "
                "21-Spalten-Format überein."
            )

        rows = list(reader)

    if not rows:
        raise ShellyCtlError("TSV enthält keine Geräte.")

    seen_ips: set[str] = set()

    for line_number, row in enumerate(rows, start=2):
        ip = row["ip"].strip()

        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ShellyCtlError(
                f"Zeile {line_number}: ungültige IP {ip!r}"
            ) from exc

        if ip in seen_ips:
            raise ShellyCtlError(
                f"Zeile {line_number}: doppelte IP {ip}"
            )

        seen_ips.add(ip)

    return rows


def complete_identity(row: dict[str, str]) -> bool:
    return all(
        row[field].strip()
        for field in ("ip", "mac", "model", "device_id")
    )


def channel_records(
    row: dict[str, str],
    component_type: str | None = None,
    sockets_only: bool = False,
) -> list[tuple[int, str, str]]:
    records: list[tuple[int, str, str]] = []

    for channel in range(4):
        current_type = row[f"channel_{channel}_type"].strip().lower()
        current_name = row[
            f"desired_channel_{channel}_name"
        ].strip()

        if not current_type:
            continue
        if component_type and current_type != component_type.lower():
            continue
        if sockets_only and not (
            current_type == "switch"
            and SOCKET_PATTERN.search(current_name)
        ):
            continue

        records.append((channel, current_type, current_name))

    return records


def row_has_component(
    row: dict[str, str],
    component_type: str,
) -> bool:
    return bool(channel_records(row, component_type))


def row_has_sockets(row: dict[str, str]) -> bool:
    return bool(
        channel_records(
            row,
            component_type="switch",
            sockets_only=True,
        )
    )


def select_rows(
    rows: list[dict[str, str]],
    target: str,
) -> list[dict[str, str]]:
    normalized = target.strip().lower()

    if normalized == "all":
        return rows

    if normalized == "sockets":
        return [row for row in rows if row_has_sockets(row)]

    if normalized == "switches":
        return [
            row for row in rows
            if row_has_component(row, "switch")
        ]

    if normalized == "lights":
        return [
            row for row in rows
            if row_has_component(row, "light")
        ]

    if normalized == "covers":
        return [
            row for row in rows
            if row_has_component(row, "cover")
        ]

    tokens = {
        token.strip()
        for token in target.split(",")
        if token.strip()
    }

    selected: list[dict[str, str]] = []

    for row in rows:
        candidates = {
            row["ip"].strip(),
            row["device_id"].strip(),
            row["shelly_id"].strip(),
            row["desired_device_name"].strip(),
            row["current_device_name"].strip(),
        }

        if tokens.intersection(candidates):
            selected.append(row)

    if not selected:
        raise ShellyCtlError(
            f"Kein Gerät passt zu --target {target!r}."
        )

    return selected


class PasswordProvider:
    def __init__(self, explicit_password: str | None) -> None:
        self.password = (
            explicit_password
            if explicit_password is not None
            else os.environ.get("SHELLY_PASSWORD")
        )
        self.prompted = False

    def ask_if_possible(self) -> str | None:
        if self.password is not None:
            return self.password

        if not self.prompted and sys.stdin.isatty():
            self.prompted = True
            entered = getpass.getpass(
                "Shelly-Passwort "
                "(leer lassen, falls keines gesetzt ist): "
            )
            self.password = entered or None

        return self.password


class RpcClient:
    def __init__(
        self,
        ip: str,
        timeout: float,
        username: str,
        password_provider: PasswordProvider,
    ) -> None:
        self.ip = ip
        self.timeout = timeout
        self.username = username
        self.password_provider = password_provider
        self.request_id = 1000
        self.opener = self._build_opener(
            password_provider.password
        )

    def _build_opener(
        self,
        password: str | None,
    ) -> urllib.request.OpenerDirector:
        if password is None:
            return urllib.request.build_opener()

        manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(
            None,
            f"http://{self.ip}/",
            self.username,
            password,
        )
        digest_handler = urllib.request.HTTPDigestAuthHandler(
            manager
        )
        return urllib.request.build_opener(digest_handler)

    def _send(
        self,
        method: str,
        params: dict[str, Any],
    ) -> Any:
        self.request_id += 1

        body = json.dumps(
            {
                "id": self.request_id,
                "method": method,
                "params": params,
            },
            ensure_ascii=False,
        ).encode("utf-8")

        request = urllib.request.Request(
            f"http://{self.ip}/rpc",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "shellyctl/1.0",
            },
        )

        try:
            with self.opener.open(
                request,
                timeout=self.timeout,
            ) as response:
                text = response.read().decode(
                    "utf-8",
                    errors="replace",
                )
        except urllib.error.HTTPError as exc:
            response_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            if exc.code == 401:
                raise AuthenticationRequired(
                    "Authentifizierung erforderlich "
                    "oder Passwort falsch."
                ) from exc

            try:
                parsed = json.loads(response_body)
            except json.JSONDecodeError:
                parsed = None

            if isinstance(parsed, dict):
                error = parsed.get("error", parsed)
                if isinstance(error, dict):
                    raise ShellyCtlError(
                        f"{method}: "
                        f"{error.get('code')} – "
                        f"{error.get('message')}"
                    ) from exc

            raise ShellyCtlError(
                f"{method}: HTTP {exc.code}: "
                f"{response_body[:200]}"
            ) from exc

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
            raise ShellyCtlError(
                f"{method} nicht erreichbar: {exc}"
            ) from exc

        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ShellyCtlError(
                f"{method}: ungültige JSON-Antwort: "
                f"{text[:200]}"
            ) from exc

        if not isinstance(value, dict):
            raise ShellyCtlError(
                f"{method}: unerwartete Antwort."
            )

        if "error" in value:
            error = value["error"]
            if isinstance(error, dict):
                raise ShellyCtlError(
                    f"{method}: "
                    f"{error.get('code')} – "
                    f"{error.get('message')}"
                )
            raise ShellyCtlError(f"{method}: {error}")

        return value.get("result")

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        parameters = params or {}

        try:
            return self._send(method, parameters)
        except AuthenticationRequired:
            password = self.password_provider.ask_if_possible()

            if not password:
                raise AuthenticationRequired(
                    "Gerät verlangt ein Passwort. "
                    "SHELLY_PASSWORD setzen oder "
                    "--password verwenden."
                )

            self.opener = self._build_opener(password)
            return self._send(method, parameters)


def validate_identity(
    row: dict[str, str],
    info: dict[str, Any],
) -> None:
    problems: list[str] = []

    expected_mac = normalize_mac(row["mac"])
    actual_mac = normalize_mac(str(info.get("mac") or ""))
    if actual_mac != expected_mac:
        problems.append(
            f"MAC erwartet {expected_mac}, "
            f"erhalten {actual_mac}"
        )

    expected_model = row["model"].strip()
    actual_model = str(info.get("model") or "")
    if actual_model != expected_model:
        problems.append(
            f"Modell erwartet {expected_model}, "
            f"erhalten {actual_model}"
        )

    expected_id = row["device_id"].strip()
    actual_id = str(info.get("id") or "")
    if actual_id != expected_id:
        problems.append(
            f"device_id erwartet {expected_id}, "
            f"erhalten {actual_id}"
        )

    if info.get("gen") != 2:
        problems.append(
            f"Generation erwartet 2, "
            f"erhalten {info.get('gen')!r}"
        )

    if problems:
        raise ShellyCtlError("; ".join(problems))


def prepare_device(
    row: dict[str, str],
    timeout: float,
    username: str,
    password_provider: PasswordProvider,
) -> tuple[RpcClient, dict[str, Any], set[str]]:
    if not complete_identity(row):
        raise ShellyCtlError(
            "technische Identitätsdaten unvollständig"
        )

    client = RpcClient(
        row["ip"].strip(),
        timeout,
        username,
        password_provider,
    )

    info = client.call("Shelly.GetDeviceInfo")
    if not isinstance(info, dict):
        raise ShellyCtlError(
            "Shelly.GetDeviceInfo lieferte kein Objekt."
        )

    validate_identity(row, info)

    method_result = client.call("Shelly.ListMethods")
    if not isinstance(method_result, dict):
        raise ShellyCtlError(
            "Shelly.ListMethods lieferte kein Objekt."
        )

    raw_methods = method_result.get("methods")
    if not isinstance(raw_methods, list):
        raise ShellyCtlError(
            "Shelly.ListMethods enthält keine Methodenliste."
        )

    methods = {str(method) for method in raw_methods}
    return client, info, methods


def require_method(
    methods: set[str],
    method: str,
) -> None:
    if method not in methods:
        raise ShellyCtlError(
            f"RPC-Methode wird nicht unterstützt: {method}"
        )


def collect_snapshot(
    client: RpcClient,
    info: dict[str, Any],
    methods: set[str],
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "device_info": info,
        "methods": sorted(methods),
    }

    if "Shelly.GetConfig" in methods:
        snapshot["config"] = client.call(
            "Shelly.GetConfig"
        )

    if "Shelly.GetStatus" in methods:
        snapshot["status"] = client.call(
            "Shelly.GetStatus"
        )

    return snapshot


def save_snapshot(
    directory: Path,
    row: dict[str, str],
    phase: str,
    snapshot: dict[str, Any],
) -> Path:
    ip = row["ip"].strip()
    device_id = safe_filename(
        row["device_id"].strip() or "unknown"
    )
    path = directory / (
        f"{ip}_{device_id}_{phase}.json"
    )
    save_json(path, snapshot)
    return path


def method_is_read_only(method: str) -> bool:
    leaf = method.rsplit(".", 1)[-1]
    return leaf.startswith(READ_METHOD_PREFIXES)


def method_is_dangerous(method: str) -> bool:
    if method in DANGEROUS_METHODS:
        return True

    return any(
        fragment in method
        for fragment in DANGEROUS_FRAGMENTS
    )


def check_dangerous_permission(
    method: str,
    dangerous: bool,
    confirmation: str | None,
) -> None:
    if not method_is_dangerous(method):
        return

    if not dangerous or confirmation != method:
        raise ShellyCtlError(
            f"{method} ist als gefährlich eingestuft. "
            f"Zusätzlich erforderlich: "
            f"--dangerous --confirm '{method}'"
        )


def recursive_errors(
    value: Any,
    path: str = "",
) -> list[str]:
    found: list[str] = []

    if isinstance(value, dict):
        for key, item in value.items():
            child_path = (
                f"{path}.{key}" if path else key
            )

            if (
                key == "errors"
                and isinstance(item, list)
                and item
            ):
                found.append(
                    f"{child_path}={item}"
                )
            else:
                found.extend(
                    recursive_errors(item, child_path)
                )

    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(
                recursive_errors(
                    item,
                    f"{path}[{index}]",
                )
            )

    return found


def config_value(
    config: Any,
    component: str,
    field: str = "enable",
) -> Any:
    if not isinstance(config, dict):
        return None

    component_config = config.get(component)
    if not isinstance(component_config, dict):
        return None

    return component_config.get(field)


def readable_boolean(value: Any) -> str:
    if value is True:
        return "an"
    if value is False:
        return "aus"
    return "n/v"


def print_actions() -> None:
    print("Verfügbare Aktionen")
    print("====================")
    print()
    print("Lesen und prüfen:")
    print("  actions")
    print("  inventory")
    print("  methods")
    print("  status")
    print("  config")
    print("  audit")
    print("  backup")
    print("  firmware-check")
    print()
    print("Feste Änderungen:")
    print("  bt-off / bt-on")
    print("  cloud-off / cloud-on")
    print("  mqtt-off / mqtt-on")
    print("  socket-boot-on")
    print("  socket-boot-off")
    print("  socket-boot-restore")
    print("  socket-boot-match-input")
    print("  switch-boot-on")
    print("  switch-boot-off")
    print("  switch-boot-restore")
    print("  switch-boot-match-input")
    print("  firmware-update-stable")
    print("  reboot")
    print()
    print("Universal:")
    print("  rpc --method RPC.Methode --params '{...}'")
    print()
    print("Ziele:")
    print("  --target all")
    print("  --target sockets")
    print("  --target switches")
    print("  --target lights")
    print("  --target covers")
    print("  --target IP,device_id,Gerätename,Dokumentations-ID")
    print()
    print("Schreibende Aktionen sind immer Trockenlauf,")
    print("solange --apply fehlt.")


def process_read_action(
    action: str,
    row: dict[str, str],
    client: RpcClient,
    info: dict[str, Any],
    methods: set[str],
    output_directory: Path,
    run_stamp: str,
    entry: dict[str, Any],
) -> None:
    ip = row["ip"].strip()
    name = row["desired_device_name"].strip()

    if action == "inventory":
        entry["result"] = info
        print(
            f"[{ip}] {name} | "
            f"{info.get('model')} | "
            f"Gen {info.get('gen')} | "
            f"FW {info.get('ver') or info.get('fw_id')} | "
            f"Auth {'an' if info.get('auth_en') else 'aus'}"
        )
        return

    if action == "methods":
        entry["result"] = sorted(methods)
        print(
            f"[{ip}] {name}: "
            f"{len(methods)} RPC-Methoden"
        )
        for method in sorted(methods):
            print(f"  {method}")
        return

    if action in {"status", "config"}:
        method = (
            "Shelly.GetStatus"
            if action == "status"
            else "Shelly.GetConfig"
        )
        require_method(methods, method)
        result = client.call(method)
        entry["result"] = result

        path = output_directory / (
            f"shellyctl-{action}-"
            f"{safe_filename(ip)}-{run_stamp}.json"
        )
        save_json(path, result)
        print(f"[{ip}] {name}: {path.resolve()}")
        return

    if action == "backup":
        snapshot = collect_snapshot(
            client,
            info,
            methods,
        )
        directory = output_directory / (
            f"shellyctl-backup-{run_stamp}"
        )
        path = save_snapshot(
            directory,
            row,
            "backup",
            snapshot,
        )
        entry["result"] = {
            "backup": str(path.resolve())
        }
        print(
            f"[{ip}] {name}: "
            f"gesichert → {path.resolve()}"
        )
        return

    if action == "firmware-check":
        require_method(
            methods,
            "Shelly.CheckForUpdate",
        )
        result = client.call(
            "Shelly.CheckForUpdate"
        )
        entry["result"] = result
        print(
            f"[{ip}] {name}: "
            f"{compact_json(result or {})}"
        )
        return

    if action == "audit":
        snapshot = collect_snapshot(
            client,
            info,
            methods,
        )
        config = snapshot.get("config")
        status = snapshot.get("status")
        errors = recursive_errors(status)

        update: Any = None
        if "Shelly.CheckForUpdate" in methods:
            try:
                update = client.call(
                    "Shelly.CheckForUpdate"
                )
            except ShellyCtlError as exc:
                update = {"error": str(exc)}

        audit = {
            "firmware": (
                info.get("ver")
                or info.get("fw_id")
            ),
            "auth_enabled": bool(
                info.get("auth_en")
            ),
            "profile": info.get("profile"),
            "ble_enabled": config_value(
                config,
                "ble",
            ),
            "cloud_enabled": config_value(
                config,
                "cloud",
            ),
            "mqtt_enabled": config_value(
                config,
                "mqtt",
            ),
            "component_errors": errors,
            "available_update": update,
            "rpc_method_count": len(methods),
        }
        entry["result"] = {
            "audit": audit,
            "snapshot": snapshot,
        }

        update_text = (
            compact_json(update)
            if update
            else "nein"
        )

        print(
            f"[{ip}] {name} | "
            f"FW {audit['firmware']} | "
            f"Auth "
            f"{readable_boolean(audit['auth_enabled'])} | "
            f"BLE "
            f"{readable_boolean(audit['ble_enabled'])} | "
            f"Cloud "
            f"{readable_boolean(audit['cloud_enabled'])} | "
            f"MQTT "
            f"{readable_boolean(audit['mqtt_enabled'])} | "
            f"Fehler {len(errors)} | "
            f"Update {update_text}"
        )
        return

    raise ShellyCtlError(
        f"Nicht implementierte Leseaktion: {action}"
    )


def build_config_patch(
    action: str,
    current: dict[str, Any],
    extra_params: dict[str, Any],
) -> tuple[str, dict[str, Any], bool]:
    if action in {"bt-off", "bt-on"}:
        desired = action == "bt-on"
        patch: dict[str, Any] = {}

        if "enable" in current:
            patch["enable"] = desired

        rpc = current.get("rpc")
        if isinstance(rpc, dict) and "enable" in rpc:
            patch["rpc"] = {
                "enable": desired
            }

        if not desired:
            observer = current.get("observer")
            if (
                isinstance(observer, dict)
                and "enable" in observer
            ):
                patch["observer"] = {
                    "enable": False
                }

            if "keep_running" in current:
                patch["keep_running"] = False

        if not patch:
            raise ShellyCtlError(
                "BLE.GetConfig enthält keine "
                "unterstützten Schalter."
            )

        return "BLE", patch, desired

    if action in {"cloud-off", "cloud-on"}:
        desired = action == "cloud-on"
        return (
            "Cloud",
            {"enable": desired},
            desired,
        )

    if action in {"mqtt-off", "mqtt-on"}:
        desired = action == "mqtt-on"
        patch = dict(extra_params)
        patch["enable"] = desired
        return "MQTT", patch, desired

    raise ShellyCtlError(
        f"Keine Konfigurationsaktion für {action}."
    )


def config_matches(
    namespace: str,
    current: dict[str, Any],
    desired: bool,
) -> bool:
    if current.get("enable") is not desired:
        return False

    if namespace == "BLE":
        rpc = current.get("rpc")
        if isinstance(rpc, dict):
            if (
                "enable" in rpc
                and rpc.get("enable") is not desired
            ):
                return False

        if desired is False:
            observer = current.get("observer")
            if (
                isinstance(observer, dict)
                and observer.get("enable") is True
            ):
                return False

            if current.get("keep_running") is True:
                return False

    return True


def process_config_action(
    action: str,
    row: dict[str, str],
    client: RpcClient,
    info: dict[str, Any],
    methods: set[str],
    extra_params: dict[str, Any],
    apply_changes: bool,
    backup_directory: Path,
    entry: dict[str, Any],
) -> tuple[int, int, int]:
    namespace_guess = {
        "bt-off": "BLE",
        "bt-on": "BLE",
        "cloud-off": "Cloud",
        "cloud-on": "Cloud",
        "mqtt-off": "MQTT",
        "mqtt-on": "MQTT",
    }[action]

    get_method = f"{namespace_guess}.GetConfig"
    set_method = f"{namespace_guess}.SetConfig"

    require_method(methods, get_method)
    require_method(methods, set_method)

    current = client.call(get_method)
    if not isinstance(current, dict):
        raise ShellyCtlError(
            f"{get_method} lieferte kein Objekt."
        )

    namespace, patch, desired = build_config_patch(
        action,
        current,
        extra_params,
    )

    entry["before"] = current
    entry["patch"] = patch

    if config_matches(namespace, current, desired):
        print("  OK: gewünschter Zustand ist bereits gesetzt.")
        entry["status"] = "already-correct"
        return 1, 0, 0

    print(
        f"  Geplant: {set_method} "
        f"{compact_json({'config': patch})}"
    )

    if not apply_changes:
        entry["status"] = "dry-run-change"
        return 0, 1, 0

    before_snapshot = collect_snapshot(
        client,
        info,
        methods,
    )
    save_snapshot(
        backup_directory,
        row,
        "before",
        before_snapshot,
    )

    result = client.call(
        set_method,
        {"config": patch},
    )
    entry["rpc_result"] = result

    after = client.call(get_method)
    entry["after"] = after

    if not isinstance(after, dict):
        raise ShellyCtlError(
            f"{get_method} lieferte nach Änderung "
            "kein Objekt."
        )

    if not config_matches(
        namespace,
        after,
        desired,
    ):
        raise ShellyCtlError(
            "Verifikation nach SetConfig fehlgeschlagen."
        )

    after_snapshot = collect_snapshot(
        client,
        info,
        methods,
    )
    save_snapshot(
        backup_directory,
        row,
        "after",
        after_snapshot,
    )

    entry["status"] = "applied-and-verified"
    print("  ANGEWENDET UND VERIFIZIERT.")
    return 0, 1, 1


def boot_channels(
    row: dict[str, str],
    action: str,
) -> list[tuple[int, str, str]]:
    sockets_only = action.startswith("socket-")
    return channel_records(
        row,
        component_type="switch",
        sockets_only=sockets_only,
    )


def process_boot_action(
    action: str,
    row: dict[str, str],
    client: RpcClient,
    info: dict[str, Any],
    methods: set[str],
    apply_changes: bool,
    backup_directory: Path,
    entry: dict[str, Any],
) -> tuple[int, int, int]:
    targets = boot_channels(row, action)

    if not targets:
        entry["status"] = "no-target-channels"
        return 0, 0, 0

    require_method(methods, "Switch.GetConfig")
    require_method(methods, "Switch.SetConfig")

    desired = BOOT_ACTION_VALUES[action]
    already = 0
    needed = 0
    applied = 0
    snapshot_saved = False

    for channel, _, channel_name in targets:
        current = client.call(
            "Switch.GetConfig",
            {"id": channel},
        )
        if not isinstance(current, dict):
            raise ShellyCtlError(
                f"Switch.GetConfig für Kanal {channel} "
                "lieferte kein Objekt."
            )

        current_state = current.get("initial_state")
        channel_entry: dict[str, Any] = {
            "channel": channel,
            "name": channel_name,
            "before": current,
            "desired_initial_state": desired,
        }

        if current_state == desired:
            already += 1
            channel_entry["status"] = "already-correct"
            print(
                f"  switch:{channel} {channel_name}: "
                f"bereits {desired!r}."
            )
            entry.setdefault(
                "channels",
                [],
            ).append(channel_entry)
            continue

        needed += 1
        print(
            f"  switch:{channel} {channel_name}: "
            f"{current_state!r} → {desired!r}"
        )

        if not apply_changes:
            channel_entry["status"] = "dry-run-change"
            entry.setdefault(
                "channels",
                [],
            ).append(channel_entry)
            continue

        if not snapshot_saved:
            before_snapshot = collect_snapshot(
                client,
                info,
                methods,
            )
            save_snapshot(
                backup_directory,
                row,
                "before",
                before_snapshot,
            )
            snapshot_saved = True

        result = client.call(
            "Switch.SetConfig",
            {
                "id": channel,
                "config": {
                    "initial_state": desired
                },
            },
        )
        channel_entry["rpc_result"] = result

        after = client.call(
            "Switch.GetConfig",
            {"id": channel},
        )
        channel_entry["after"] = after

        if not isinstance(after, dict):
            raise ShellyCtlError(
                f"Switch.GetConfig für Kanal {channel} "
                "lieferte nach Änderung kein Objekt."
            )

        if after.get("initial_state") != desired:
            raise ShellyCtlError(
                f"Verifikation für switch:{channel} "
                "fehlgeschlagen."
            )

        applied += 1
        channel_entry["status"] = (
            "applied-and-verified"
        )
        print("    ANGEWENDET UND VERIFIZIERT.")

        entry.setdefault(
            "channels",
            [],
        ).append(channel_entry)

    if apply_changes and snapshot_saved:
        after_snapshot = collect_snapshot(
            client,
            info,
            methods,
        )
        save_snapshot(
            backup_directory,
            row,
            "after",
            after_snapshot,
        )

    entry["status"] = (
        "applied"
        if applied
        else "processed"
    )
    return already, needed, applied


def parse_channel_option(
    raw: str | None,
    row: dict[str, str],
    method: str,
    target: str,
) -> list[tuple[int, str]] | None:
    if raw is None:
        return None

    namespace = method.split(".", 1)[0].lower()

    if raw.lower() == "all":
        sockets_only = target.lower() == "sockets"
        return [
            (channel, name)
            for channel, _, name in channel_records(
                row,
                component_type=namespace,
                sockets_only=sockets_only,
            )
        ]

    result: list[tuple[int, str]] = []

    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue

        try:
            channel = int(token)
        except ValueError as exc:
            raise ShellyCtlError(
                f"Ungültiger Kanal {token!r}."
            ) from exc

        if channel < 0:
            raise ShellyCtlError(
                "Kanäle dürfen nicht negativ sein."
            )

        channel_name = row[
            f"desired_channel_{channel}_name"
        ].strip() if channel <= 3 else ""

        result.append((channel, channel_name))

    if not result:
        raise ShellyCtlError(
            "--channels enthält keine Kanäle."
        )

    return result


def process_rpc_action(
    row: dict[str, str],
    client: RpcClient,
    info: dict[str, Any],
    methods: set[str],
    method: str,
    base_params: dict[str, Any],
    channels_raw: str | None,
    target: str,
    apply_changes: bool,
    dangerous: bool,
    confirmation: str | None,
    backup_directory: Path,
    entry: dict[str, Any],
) -> tuple[int, int, int]:
    require_method(methods, method)
    check_dangerous_permission(
        method,
        dangerous,
        confirmation,
    )

    is_read_only = method_is_read_only(method)
    channels = parse_channel_option(
        channels_raw,
        row,
        method,
        target,
    )

    calls: list[tuple[int | None, str, dict[str, Any]]] = []

    if channels is None:
        markers = {
            "{ip}": row["ip"].strip(),
            "{device_id}": row["device_id"].strip(),
            "{device_name}": row[
                "desired_device_name"
            ].strip(),
            "{channel}": "",
            "{channel_name}": "",
        }
        calls.append(
            (
                None,
                "",
                replace_markers(base_params, markers),
            )
        )
    else:
        for channel, channel_name in channels:
            markers = {
                "{ip}": row["ip"].strip(),
                "{device_id}": row["device_id"].strip(),
                "{device_name}": row[
                    "desired_device_name"
                ].strip(),
                "{channel}": str(channel),
                "{channel_name}": channel_name,
            }
            params = replace_markers(
                base_params,
                markers,
            )
            params["id"] = channel
            calls.append(
                (channel, channel_name, params)
            )

    executed = 0
    planned = 0
    applied = 0
    snapshot_saved = False

    for channel, channel_name, params in calls:
        label = (
            f" Kanal {channel} {channel_name}"
            if channel is not None
            else ""
        )

        if not is_read_only and not apply_changes:
            planned += 1
            print(
                f"  TROCKENLAUF{label}: "
                f"{method} {compact_json(params)}"
            )
            entry.setdefault("calls", []).append(
                {
                    "channel": channel,
                    "params": params,
                    "status": "dry-run",
                }
            )
            continue

        if not is_read_only and not snapshot_saved:
            before_snapshot = collect_snapshot(
                client,
                info,
                methods,
            )
            save_snapshot(
                backup_directory,
                row,
                "before",
                before_snapshot,
            )
            snapshot_saved = True

        result = client.call(method, params)
        executed += 1
        if not is_read_only:
            applied += 1

        print(
            f"  AUSGEFÜHRT{label}: "
            f"{compact_json(result)}"
        )
        entry.setdefault("calls", []).append(
            {
                "channel": channel,
                "params": params,
                "result": result,
                "status": "executed",
            }
        )

    if snapshot_saved:
        if method == "Shelly.Reboot":
            time.sleep(0.5)
        else:
            after_snapshot = collect_snapshot(
                client,
                info,
                methods,
            )
            save_snapshot(
                backup_directory,
                row,
                "after",
                after_snapshot,
            )

    entry["status"] = "processed"
    return executed, planned, applied



def wait_for_expected_firmware(
    row: dict[str, str],
    expected_version: str,
    timeout: float,
    poll_interval: float,
    rpc_timeout: float,
    username: str,
    password_provider: PasswordProvider,
) -> tuple[RpcClient, dict[str, Any], set[str]]:
    deadline = time.monotonic() + timeout
    last_version: str | None = None
    last_error: str | None = None

    while time.monotonic() < deadline:
        try:
            client, info, methods = prepare_device(
                row,
                rpc_timeout,
                username,
                password_provider,
            )

            current_version = str(
                info.get("ver")
                or info.get("fw_id")
                or ""
            )
            last_version = current_version

            if current_version == expected_version:
                return client, info, methods

        except ShellyCtlError as exc:
            last_error = str(exc)

        time.sleep(poll_interval)

    details = (
        f"zuletzt gemeldete Version {last_version!r}"
        if last_version is not None
        else f"letzter Fehler: {last_error or 'unbekannt'}"
    )
    raise ShellyCtlError(
        f"Firmware {expected_version!r} wurde innerhalb von "
        f"{timeout:g} Sekunden nicht verifiziert; {details}."
    )


def process_firmware_update_stable(
    row: dict[str, str],
    client: RpcClient,
    info: dict[str, Any],
    methods: set[str],
    apply_changes: bool,
    backup_directory: Path,
    wait_timeout: float,
    poll_interval: float,
    rpc_timeout: float,
    username: str,
    password_provider: PasswordProvider,
    entry: dict[str, Any],
) -> tuple[int, int, int]:
    require_method(methods, "Shelly.CheckForUpdate")
    require_method(methods, "Shelly.Update")

    available = client.call("Shelly.CheckForUpdate")
    if not isinstance(available, dict):
        raise ShellyCtlError(
            "Shelly.CheckForUpdate lieferte kein Objekt."
        )

    entry["available_update"] = available

    stable = available.get("stable")
    if not isinstance(stable, dict):
        beta = available.get("beta")
        if isinstance(beta, dict):
            print(
                "  ÜBERSPRUNGEN: kein stabiles Update; "
                f"nur Beta {beta.get('version')!r} verfügbar."
            )
            entry["status"] = "skipped-beta-only"
        else:
            print("  OK: kein stabiles Update verfügbar.")
            entry["status"] = "no-stable-update"
        return 1, 0, 0

    expected_version = str(stable.get("version") or "").strip()
    build_id = str(stable.get("build_id") or "").strip()

    if not expected_version:
        raise ShellyCtlError(
            "Stabiles Update enthält keine Versionsangabe."
        )

    current_version = str(
        info.get("ver")
        or info.get("fw_id")
        or ""
    )

    entry["current_version"] = current_version
    entry["expected_version"] = expected_version
    entry["expected_build_id"] = build_id

    print(
        f"  Stabil verfügbar: {current_version!r} → "
        f"{expected_version!r}"
        + (f" ({build_id})" if build_id else "")
    )

    if not apply_changes:
        print(
            "  TROCKENLAUF: Shelly.Update "
            '{"stage":"stable"}'
        )
        entry["status"] = "dry-run-update"
        return 0, 1, 0

    before_snapshot = collect_snapshot(
        client,
        info,
        methods,
    )
    before_path = save_snapshot(
        backup_directory,
        row,
        "before",
        before_snapshot,
    )
    entry["backup_before"] = str(before_path.resolve())

    result = client.call(
        "Shelly.Update",
        {"stage": "stable"},
    )
    entry["update_result"] = result
    print("  UPDATE AUSGELÖST; warte auf Neustart und Verifikation …")

    verified_client, verified_info, verified_methods = (
        wait_for_expected_firmware(
            row,
            expected_version,
            wait_timeout,
            poll_interval,
            rpc_timeout,
            username,
            password_provider,
        )
    )

    after_snapshot = collect_snapshot(
        verified_client,
        verified_info,
        verified_methods,
    )
    after_path = save_snapshot(
        backup_directory,
        row,
        "after",
        after_snapshot,
    )
    entry["backup_after"] = str(after_path.resolve())
    entry["verified_identity"] = verified_info
    entry["status"] = "updated-and-verified"

    print(
        f"  AKTUALISIERT UND VERIFIZIERT: "
        f"{verified_info.get('ver')!r}."
    )
    return 0, 1, 1

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Universelles Shelly-Gen2-Verwaltungswerkzeug. "
            "Schreibende Aktionen sind standardmäßig Trockenlauf."
        )
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {PROGRAM_VERSION}",
    )

    parser.add_argument(
        "action",
        choices=sorted(ALL_ACTIONS),
        help="Auszuführende Aktion.",
    )
    parser.add_argument(
        "--tsv",
        default=DEFAULT_TSV,
        help=(
            "Geräte-TSV; Standard: "
            f"{DEFAULT_TSV}"
        ),
    )
    parser.add_argument(
        "--target",
        default="all",
        help=(
            "all, sockets, switches, lights, covers "
            "oder kommaseparierte IPs/IDs/Namen."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Schreibende Aktion tatsächlich ausführen. "
            "Ohne diese Option nur Trockenlauf."
        ),
    )
    parser.add_argument(
        "--method",
        help="RPC-Methode für die Aktion rpc.",
    )
    parser.add_argument(
        "--params",
        help="RPC-Parameter als JSON-Objekt.",
    )
    parser.add_argument(
        "--params-file",
        help="Datei mit RPC-Parametern als JSON-Objekt.",
    )
    parser.add_argument(
        "--channels",
        help=(
            "Für rpc: all oder kommaseparierte Kanalnummern. "
            "Die Kanal-ID wird als Parameter id eingesetzt."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=(
            f"HTTP-Timeout in Sekunden; "
            f"Standard: {DEFAULT_TIMEOUT}"
        ),
    )
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=300.0,
        help=(
            "Maximale Wartezeit pro Firmware-Update in Sekunden; "
            "Standard: 300."
        ),
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help=(
            "Prüfintervall während eines Firmware-Updates in Sekunden; "
            "Standard: 5."
        ),
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Benutzername; Standard: admin",
    )
    parser.add_argument(
        "--password",
        help=(
            "Gerätepasswort. Sicherer ist "
            "die Umgebungsvariable SHELLY_PASSWORD."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help=(
            "Verzeichnis für Protokolle und Sicherungen; "
            "Standard: aktuelles Verzeichnis."
        ),
    )
    parser.add_argument(
        "--dangerous",
        action="store_true",
        help="Gefährliche RPC-Methode ausdrücklich erlauben.",
    )
    parser.add_argument(
        "--confirm",
        help=(
            "Exakter RPC-Methodenname zur Bestätigung "
            "einer gefährlichen Methode."
        ),
    )

    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.action == "actions":
        print_actions()
        return 0

    if args.action == "rpc" and not args.method:
        parser.error(
            "Für die Aktion rpc ist --method erforderlich."
        )

    if args.channels and args.action != "rpc":
        parser.error(
            "--channels ist nur mit der Aktion rpc zulässig."
        )

    if args.timeout <= 0:
        parser.error("--timeout muss größer als 0 sein.")

    if args.wait_timeout <= 0:
        parser.error("--wait-timeout muss größer als 0 sein.")

    if args.poll_interval <= 0:
        parser.error("--poll-interval muss größer als 0 sein.")

    try:
        extra_params = parse_params(
            args.params,
            args.params_file,
        )
    except ShellyCtlError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2

    source = Path(args.tsv)
    output_directory = Path(args.output_dir)
    run_stamp = timestamp()

    try:
        rows = load_tsv(source)
        selected_rows = select_rows(
            rows,
            args.target,
        )
    except ShellyCtlError as exc:
        print(f"DATEIFEHLER: {exc}", file=sys.stderr)
        return 2

    password_provider = PasswordProvider(
        args.password
    )

    action_is_write = args.action in WRITE_ACTIONS
    if args.action == "rpc":
        action_is_write = not method_is_read_only(
            args.method
        )

    print(
        "MODUS:",
        "ANWENDEN"
        if action_is_write and args.apply
        else (
            "TROCKENLAUF"
            if action_is_write
            else "LESEN"
        ),
    )
    print(
        "Identitätsprüfung: IP, MAC, Modell, "
        "technische device_id und Generation 2."
    )

    if action_is_write and not args.apply:
        print(
            "Es werden keine Änderungen ausgeführt, "
            "weil --apply fehlt."
        )

    print(
        f"Aktion: {args.action}; "
        f"Ziel: {args.target}; "
        f"Geräte: {len(selected_rows)}"
    )
    print()

    backup_directory = output_directory / (
        f"shellyctl-backup-{args.action}-{run_stamp}"
    )
    log_path = output_directory / (
        f"shellyctl-{args.action}-{run_stamp}.json"
    )

    log: dict[str, Any] = {
        "timestamp": run_stamp,
        "action": args.action,
        "target": args.target,
        "mode": (
            "apply"
            if action_is_write and args.apply
            else (
                "dry-run"
                if action_is_write
                else "read"
            )
        ),
        "source": str(source.resolve()),
        "devices": [],
    }

    devices_ok = 0
    devices_skipped = 0
    errors = 0
    already_correct = 0
    changes_needed = 0
    applied = 0
    calls_executed = 0

    for row in selected_rows:
        ip = row["ip"].strip()
        name = row[
            "desired_device_name"
        ].strip() or row["device_id"].strip()

        entry: dict[str, Any] = {
            "ip": ip,
            "device_name": name,
            "device_id": row["device_id"].strip(),
            "status": "",
            "errors": [],
        }

        if not complete_identity(row):
            devices_skipped += 1
            entry["status"] = "skipped-incomplete"
            entry["errors"].append(
                "technische Identitätsdaten unvollständig"
            )
            log["devices"].append(entry)
            print(
                f"[{ip}] {name}\n"
                "  ÜBERSPRUNGEN: technische "
                "Identitätsdaten unvollständig"
            )
            continue

        try:
            client, info, methods = prepare_device(
                row,
                args.timeout,
                args.username,
                password_provider,
            )
            entry["identity"] = info
            print(f"[{ip}] {name}")

            if args.action in READ_ACTIONS:
                process_read_action(
                    args.action,
                    row,
                    client,
                    info,
                    methods,
                    output_directory,
                    run_stamp,
                    entry,
                )
                devices_ok += 1
                entry["status"] = "ok"

            elif args.action in CONFIG_ACTIONS:
                current_already, current_needed, current_applied = (
                    process_config_action(
                        args.action,
                        row,
                        client,
                        info,
                        methods,
                        extra_params,
                        args.apply,
                        backup_directory,
                        entry,
                    )
                )
                already_correct += current_already
                changes_needed += current_needed
                applied += current_applied
                devices_ok += 1

            elif args.action in BOOT_ACTION_VALUES:
                current_already, current_needed, current_applied = (
                    process_boot_action(
                        args.action,
                        row,
                        client,
                        info,
                        methods,
                        args.apply,
                        backup_directory,
                        entry,
                    )
                )
                already_correct += current_already
                changes_needed += current_needed
                applied += current_applied
                devices_ok += 1

            elif args.action == "firmware-update-stable":
                current_skipped, current_needed, current_applied = (
                    process_firmware_update_stable(
                        row,
                        client,
                        info,
                        methods,
                        args.apply,
                        backup_directory,
                        args.wait_timeout,
                        args.poll_interval,
                        args.timeout,
                        args.username,
                        password_provider,
                        entry,
                    )
                )
                devices_skipped += current_skipped
                changes_needed += current_needed
                applied += current_applied
                devices_ok += 1

            elif args.action == "reboot":
                require_method(
                    methods,
                    "Shelly.Reboot",
                )

                if not args.apply:
                    changes_needed += 1
                    entry["status"] = "dry-run-change"
                    print("  TROCKENLAUF: Shelly.Reboot")
                else:
                    before_snapshot = collect_snapshot(
                        client,
                        info,
                        methods,
                    )
                    save_snapshot(
                        backup_directory,
                        row,
                        "before",
                        before_snapshot,
                    )
                    result = client.call(
                        "Shelly.Reboot"
                    )
                    entry["result"] = result
                    entry["status"] = "applied"
                    applied += 1
                    print("  NEUSTART AUSGELÖST.")
                devices_ok += 1

            elif args.action == "rpc":
                executed, planned, current_applied = (
                    process_rpc_action(
                        row,
                        client,
                        info,
                        methods,
                        args.method,
                        extra_params,
                        args.channels,
                        args.target,
                        args.apply,
                        args.dangerous,
                        args.confirm,
                        backup_directory,
                        entry,
                    )
                )
                calls_executed += executed
                changes_needed += planned
                applied += current_applied
                devices_ok += 1

            else:
                raise ShellyCtlError(
                    f"Aktion nicht implementiert: "
                    f"{args.action}"
                )

        except ShellyCtlError as exc:
            errors += 1
            message = str(exc)
            entry["status"] = "error"
            entry["errors"].append(message)
            print(f"  FEHLER: {message}")

        log["devices"].append(entry)

    log["summary"] = {
        "devices_selected": len(selected_rows),
        "devices_ok": devices_ok,
        "devices_skipped": devices_skipped,
        "already_correct": already_correct,
        "changes_needed_or_planned": changes_needed,
        "applied": applied,
        "rpc_calls_executed": calls_executed,
        "errors": errors,
    }
    save_json(log_path, log)

    print()
    print(
        f"Ergebnis: {len(selected_rows)} ausgewählt, "
        f"{devices_ok} verarbeitet, "
        f"{devices_skipped} übersprungen, "
        f"{already_correct} bereits korrekt, "
        f"{changes_needed} Änderungen geplant, "
        f"{applied} angewendet, "
        f"{calls_executed} RPC-Aufrufe ausgeführt, "
        f"{errors} Fehler."
    )
    print(f"Protokoll: {log_path.resolve()}")

    if backup_directory.exists():
        print(
            f"Sicherungen: "
            f"{backup_directory.resolve()}"
        )

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
