from config import (CUSUM_FEATURE, CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR,
                    THRESHOLD_FEATURES, NAIVE_JUMP_FACTOR, MIN_PAUSE,
                    MAX_PAUSE, HOLD_WINDOWS)
from cusum import Cusum

FEATURE = CUSUM_FEATURE


class Detector:
    """Looks at one window at a time (in time order) and returns a decision.

    It only uses the past, never future windows, so it could run live.

    Signals
      score      = max(rate / limit, S / h)   (both are 'ratio to own limit',
                   so they are on the same scale; score > 1 means abnormal)
      raw_hi     = rate > limit               (used to find bursts)
      max_jump   = biggest one-window rise during the current sequence
      bursts     = number of separate high-rate bursts in the sequence
    """

    def __init__(self, baseline):
        self.mu = baseline[FEATURE]
        self.limit = THRESHOLD_FEATURES[FEATURE] * self.mu
        self.jump_limit = NAIVE_JUMP_FACTOR * self.mu
        self.cusum = Cusum(self.mu, CUSUM_K, CUSUM_H, CUSUM_CAP_FACTOR)
        self.prev = None
        self.gap = 0            # consecutive windows with raw_hi False
        self.bursts = 0
        self.max_jump = 0.0

    def _out(self, row, cls, score, reason, rule):
        return {"timestamp": row.get("timestamp"), "traffic_class": cls,
                "score": round(score, 3), "reason": reason, "rule": rule}

    def process(self, row):
        x = row.get(FEATURE)
        if x is None:
            return self._out(row, "unknown", 0.0,
                             FEATURE + " missing; window not analysed",
                             "missing_input")

        S, cus_alarm = self.cusum.update(x)
        raw_hi = x > self.limit
        jump = 0.0 if self.prev is None else x - self.prev
        self.prev = x
        score = max(x / self.limit, S / CUSUM_H)
        abnormal = raw_hi or cus_alarm

        # ---- burst bookkeeping (uses the raw rate, not CUSUM) ----
        if raw_hi:
            if self.bursts == 0:
                self.bursts = 1
            elif self.gap >= MIN_PAUSE:
                if self.gap <= MAX_PAUSE:
                    self.bursts += 1          # a repeat after a real pause
                else:
                    self.bursts = 1           # too long ago: new sequence
                    self.max_jump = 0.0
            self.max_jump = max(self.max_jump, jump)
            self.gap = 0
        else:
            self.gap += 1
            if self.bursts > 0 and self.gap > MAX_PAUSE:
                self.bursts = 0               # sequence over
                self.max_jump = 0.0

        # ---- classification ----
        if abnormal and self.max_jump >= self.jump_limit:
            return self._out(
                row, "naive_ddos", score,
                "rate jumped %.0f in one window (limit %.0f)"
                % (self.max_jump, self.jump_limit), "onset_jump")
        if self.bursts >= 2 and (abnormal or self.gap <= HOLD_WINDOWS):
            why = ("repeated bursts separated by pauses"
                   if abnormal else "pause inside repeated-burst pattern")
            return self._out(row, "adaptive_ddos", score, why,
                             "repeat_burst" if abnormal else "hold")
        if abnormal:
            if raw_hi:
                return self._out(
                    row, "flash_crowd", score,
                    "rate %.0f above limit %.0f, gradual onset"
                    % (x, self.limit), "threshold")
            return self._out(row, "flash_crowd", score,
                             "CUSUM sustained rise (S=%.0f > h=%.0f)"
                             % (S, CUSUM_H), "cusum")
        return self._out(row, "normal", score, "within normal range", "none")
