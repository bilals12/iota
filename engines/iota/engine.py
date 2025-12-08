#!/usr/bin/env python3

import json
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Any


class Rule:
    def __init__(self, path: Path):
        self.path = path
        self.rule_id = path.stem
        self.module = self._load_module()

    def _load_module(self):
        spec = importlib.util.spec_from_file_location(self.rule_id, self.path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def matches(self, event: Dict[str, Any]) -> bool:
        if not hasattr(self.module, "rule"):
            return False
        try:
            return bool(self.module.rule(event))
        except Exception:
            return False

    def get_title(self, event: Dict[str, Any]) -> str:
        if not hasattr(self.module, "title"):
            return self.rule_id
        try:
            return str(self.module.title(event))
        except Exception:
            return self.rule_id

    def get_severity(self) -> str:
        if hasattr(self.module, "severity"):
            try:
                return str(self.module.severity())
            except Exception:
                pass
        return "INFO"

    def get_dedup(self, event: Dict[str, Any]) -> str:
        if not hasattr(self.module, "dedup"):
            return self.rule_id
        try:
            return str(self.module.dedup(event))
        except Exception:
            return self.rule_id


class Engine:
    def __init__(self, rules_dir: str):
        self.rules = self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str) -> List[Rule]:
        rules = []
        path = Path(rules_dir)
        for rule_file in path.rglob("*.py"):
            if rule_file.name.startswith("_"):
                continue
            try:
                rules.append(Rule(rule_file))
            except Exception:
                continue
        return rules

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        matches = []
        for event in events:
            for rule in self.rules:
                if rule.matches(event):
                    matches.append(
                        {
                            "rule_id": rule.rule_id,
                            "title": rule.get_title(event),
                            "severity": rule.get_severity(),
                            "dedup": rule.get_dedup(event),
                            "event": event,
                        }
                    )
        return matches


def main():
    request = json.load(sys.stdin)
    rules_dir = request.get("rules_dir")
    events = request.get("events", [])

    engine = Engine(rules_dir)
    matches = engine.analyze(events)

    response = {"matches": matches}
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    main()
