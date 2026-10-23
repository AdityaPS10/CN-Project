"""Member 4 - mitigation decision handler (policy only, no OpenFlow yet).

Feed it Member 3's decisions one window at a time, in time order. For each
it returns one action:

    start  mitigation was off and an attack decision arrived
    keep   mitigation stays on
    stop   mitigation was on and enough clean windows have passed
    none   mitigation stays off

The controller app (a later step) turns start/stop into OpenFlow rules.
"""
from dataclasses import dataclass

from member4_mitigation import config
from member4_mitigation.decisions import Decision


@dataclass(frozen=True)
class Action:
    timestamp: float
    action: str          # start | keep | stop | none
    traffic_class: str
    rule: str
    why: str


class MitigationPolicy:
    def __init__(self, cfg=config):
        self.cfg = cfg
        self.active = False
        self.clean_streak = 0    # consecutive non-attack windows while active

    def reset(self):
        """Forget all state (e.g. the detector restarted). Returns True if
        mitigation was on, so the caller knows it must remove its rules."""
        was_active = self.active
        self.active = False
        self.clean_streak = 0
        return was_active

    def _wants_mitigation(self, d: Decision):
        if d.traffic_class not in self.cfg.MITIGATE_CLASSES:
            return False
        if d.rule == "hold" and not self.cfg.KEEP_DURING_HOLD:
            return False
        return True

    def process(self, d: Decision) -> Action:
        def out(action, why):
            return Action(d.timestamp, action, d.traffic_class, d.rule, why)

        if d.traffic_class == "unknown" and self.cfg.UNKNOWN_KEEPS_STATE:
            return out("keep" if self.active else "none",
                       "detector had no input; state unchanged")

        if self._wants_mitigation(d):
            self.clean_streak = 0
            if self.active:
                return out("keep", "attack continues")
            self.active = True
            return out("start", "attack decision")

        if not self.active:
            return out("none", "no attack")
        self.clean_streak += 1
        if self.clean_streak >= self.cfg.RELEASE_AFTER_CLEAN_WINDOWS:
            self.active = False
            self.clean_streak = 0
            return out("stop", "clean windows reached release limit")
        return out("keep", "clean window %d of %d before release"
                   % (self.clean_streak, self.cfg.RELEASE_AFTER_CLEAN_WINDOWS))


if __name__ == "__main__":
    # Replay a recorded decision file through the policy:
    #   python3 -m member4_mitigation.mitigation detection/data/decisions_naive_ddos.csv
    # This is a REPLAY of Member 3's recorded output, not an experiment result.
    import sys
    from collections import Counter
    from member4_mitigation.decisions import read_decisions

    symbol = {"start": "S", "keep": "#", "stop": "x", "none": "."}
    for path in sys.argv[1:]:
        policy = MitigationPolicy()
        actions = [policy.process(d) for d in read_decisions(path)]
        print("\n%s  (replay, not experimental data)" % path)
        print("".join(symbol[a.action] for a in actions))
        for a in actions:
            if a.action in ("start", "stop"):
                print("  t=%.2f %-5s class=%s rule=%s (%s)"
                      % (a.timestamp, a.action, a.traffic_class, a.rule, a.why))
        print("  ", dict(Counter(a.action for a in actions)))
    print("\nLegend: . off  S start  # mitigating  x stop")
