"""
Threshold rule engine for Sentinel_Sandbox.

Every event is offered to the engine. A rule matches events whose
``event_type`` equals the rule's ``pattern``, groups them by source IP, and
fires when its measure over the last ``window`` seconds is greater than
``threshold``. The rules and their numbers come from the ``rules`` table, so
the dashboard shows exactly what the engine applies.

Measures:
  count          number of matching events
  sum:<field>    sum of a numeric field (e.g. packets per burst)
  distinct:<f>   number of distinct values of a field (e.g. ports probed)

After a rule fires for a source, that source's window is cleared, so one
burst produces one alert rather than one per further event.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str  # event_type this rule watches
    measure: str  # "count", "sum:<field>" or "distinct:<field>"
    threshold: int  # fires when the measure is greater than this
    window: int  # seconds
    severity: str
    condition_text: str = ""

    def value_of(self, event: dict):
        """What one event contributes to this rule's measure."""
        if self.measure == "count":
            return 1
        _, field = self.measure.split(":", 1)
        return event.get(field)


class RuleEngine:
    """Sliding-window threshold evaluation over the event stream."""

    def __init__(self, rules, alert_callback, clock=time.monotonic):
        self.alert_callback = alert_callback
        self.clock = clock
        self.rules: list[Rule] = []
        # (rule name, source ip) -> deque of (timestamp, contribution)
        self._windows: dict[tuple[str, str], deque] = defaultdict(deque)
        self.load(rules)

    def load(self, rules):
        """Replace the active rules (e.g. after the rules table changes)."""
        self.rules = list(rules)
        self._windows.clear()

    def _measure(self, rule: Rule, items) -> int:
        values = [v for _, v in items if v is not None]
        if rule.measure.startswith("distinct:"):
            return len(set(values))
        return sum(values)

    def process(self, event: dict) -> list[dict]:
        """Feed one event; returns (and reports) any alerts it caused."""
        fired = []
        source = event.get("ip") or event.get("source_ip") or "N/A"
        now = self.clock()
        for rule in self.rules:
            if event.get("event_type") != rule.pattern:
                continue
            window = self._windows[(rule.name, source)]
            window.append((now, rule.value_of(event)))
            while window and now - window[0][0] > rule.window:
                window.popleft()

            value = self._measure(rule, window)
            if value > rule.threshold:
                alert = self._build_alert(rule, source, value, window)
                window.clear()
                fired.append(alert)
                self.alert_callback(alert)
        return fired

    def _build_alert(self, rule: Rule, source: str, value: int, window) -> dict:
        unit = rule.measure.split(":", 1)[-1] if ":" in rule.measure else "events"
        alert = {
            "category": "alert",
            "type": rule.name,
            "source_ip": source,
            "description": (
                f"{value} {unit} from {source} within {rule.window}s "
                f"(rule fires above {rule.threshold})"
            ),
            "severity": rule.severity,
            "rule_name": rule.name,
            "packets_detected": value,
            "time_window": f"{rule.window}s",
            "ports_accessed": None,
            "time": time.strftime("%H:%M:%S"),
        }
        if rule.measure == "distinct:port":
            alert["ports_accessed"] = sorted({v for _, v in window if v is not None})
        return alert
