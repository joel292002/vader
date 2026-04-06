from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any


DEFAULT_STATE: dict[str, Any] = {
    "target": "",
    "platform": "",
    "authorized": False,
    "started_at": "",
    "status": "idle",
    "open_ports": [],
    "credentials": [],
    "flags": [],
    "hashes": [],
    "shell_access": False,
    "root_access": False,
    "urls": [],
    "interesting_files": [],
    "next_command": "",
    "last_output": "",
    "last_command_run": "",
    "codex_notes": "",
    "raw_outputs": [],
    "agent_status": {
        "recon": "idle",
        "web": "idle",
        "brute": "idle",
        "exploit": "idle",
        "report": "idle",
    },
    "timeline": [],
}


class FindingsBoard:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.lock = Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps(DEFAULT_STATE, indent=2), encoding="utf-8")

    def load(self) -> dict[str, Any]:
        with self.lock:
            data = self._normalize(self._unsafe_load())
            self._unsafe_save(data)
            return deepcopy(data)

    def save(self, data: dict[str, Any]) -> None:
        with self.lock:
            self._unsafe_save(self._normalize(data))

    def update(self, key: str, value: Any) -> None:
        with self.lock:
            data = self._normalize(self._unsafe_load())
            target: Any = data
            parts = key.split(".")
            for part in parts[:-1]:
                if part not in target or not isinstance(target[part], dict):
                    target[part] = {}
                target = target[part]
            target[parts[-1]] = value
            self._unsafe_save(data)

    def add_port(self, port: int, service: str, banner: str = "", version: str = "") -> None:
        record = {"port": int(port), "service": service, "banner": banner, "version": version}
        with self.lock:
            data = self._normalize(self._unsafe_load())
            if record not in data["open_ports"]:
                data["open_ports"].append(record)
                data["open_ports"].sort(key=lambda item: item["port"])
            self._unsafe_save(data)

    def add_credential(self, username: str, password: str, source: str, tried_on: list[str] | None = None) -> None:
        record = {
            "username": username,
            "password": password,
            "source": source,
            "tried_on": tried_on or [],
        }
        with self.lock:
            data = self._normalize(self._unsafe_load())
            if record not in data["credentials"]:
                data["credentials"].append(record)
            self._unsafe_save(data)

    def add_flag(self, value: str, location: str, verified: bool = False) -> None:
        record = {"value": value, "location": location, "verified": verified}
        with self.lock:
            data = self._normalize(self._unsafe_load())
            if record not in data["flags"]:
                data["flags"].append(record)
            self._unsafe_save(data)

    def add_hash(self, value: str, hash_type: str, cracked: bool = False, plaintext: str = "") -> None:
        record = {"value": value, "type": hash_type, "cracked": cracked, "plaintext": plaintext}
        with self.lock:
            data = self._normalize(self._unsafe_load())
            if record not in data["hashes"]:
                data["hashes"].append(record)
            self._unsafe_save(data)

    def append_raw_output(self, command: str, output: str, source: str) -> None:
        with self.lock:
            data = self._normalize(self._unsafe_load())
            item = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "command": command,
                "source": source,
                "output": output,
            }
            data["raw_outputs"].append(item)
            data["raw_outputs"] = data["raw_outputs"][-50:]
            data["last_output"] = output
            self._unsafe_save(data)

    def add_timeline(self, agent: str, action: str, finding: str = "") -> None:
        with self.lock:
            data = self._normalize(self._unsafe_load())
            data["timeline"].append(
                {
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "agent": agent,
                    "action": action,
                    "finding": finding,
                }
            )
            data["timeline"] = data["timeline"][-200:]
            self._unsafe_save(data)

    def _normalize(self, data: dict[str, Any]) -> dict[str, Any]:
        merged = deepcopy(DEFAULT_STATE)
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
        return merged

    def _unsafe_load(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return deepcopy(DEFAULT_STATE)

    def _unsafe_save(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
