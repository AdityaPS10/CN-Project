import types
import unittest

from member4_mitigation import config
from member4_mitigation.decisions import Decision
from member4_mitigation.mitigation import MitigationPolicy


def d(cls, rule="none", t=0.0):
    return Decision(t, cls, 0.0, "", rule)


def run(classes, cfg=config):
    """classes: list of (traffic_class, rule) -> list of action names"""
    p = MitigationPolicy(cfg)
    return [p.process(d(c, r, i)).action for i, (c, r) in enumerate(classes)]


def cfg_with(**overrides):
    values = {k: getattr(config, k) for k in dir(config) if k.isupper()}
    values.update(overrides)
    return types.SimpleNamespace(**values)


N = ("normal", "none")
F = ("flash_crowd", "threshold")
ND = ("naive_ddos", "onset_jump")
AD = ("adaptive_ddos", "repeat_burst")
H = ("adaptive_ddos", "hold")
U = ("unknown", "missing_input")


class TestPolicy(unittest.TestCase):
    def test_normal_never_mitigates(self):
        self.assertEqual(run([N] * 5), ["none"] * 5)

    def test_flash_crowd_never_mitigates(self):
        self.assertEqual(run([N, F, F, F, N]), ["none"] * 5)

    def test_naive_attack_starts_and_stops(self):
        self.assertEqual(run([N, ND, ND, N]), ["none", "start", "keep", "stop"])

    def test_hold_keeps_mitigation_on(self):
        self.assertEqual(run([AD, H, H, AD, N]), ["start", "keep", "keep", "keep", "stop"])

    def test_hold_releases_when_disabled(self):
        cfg = cfg_with(KEEP_DURING_HOLD=False)
        self.assertEqual(run([AD, H, AD], cfg), ["start", "stop", "start"])

    def test_unknown_keeps_state(self):
        self.assertEqual(run([U, ND, U, N, U]), ["none", "start", "keep", "stop", "none"])

    def test_release_delay(self):
        cfg = cfg_with(RELEASE_AFTER_CLEAN_WINDOWS=3)
        self.assertEqual(run([ND, N, N, N, N], cfg), ["start", "keep", "keep", "stop", "none"])

    def test_attack_during_release_countdown_resets_it(self):
        cfg = cfg_with(RELEASE_AFTER_CLEAN_WINDOWS=2)
        self.assertEqual(run([ND, N, ND, N, N], cfg), ["start", "keep", "keep", "keep", "stop"])


if __name__ == "__main__":
    unittest.main()
