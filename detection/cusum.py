class Cusum:
    """One-sided CUSUM that detects a sustained INCREASE in a feature.

        S_t = max(0, S_(t-1) + (x_t - mu - k))
        alarm when S_t > h

    mu  : baseline (expected normal value)
    k   : slack/reference value. Differences smaller than k are ignored, so
          ordinary noise does not build up. Bigger k = less sensitive.
    h   : alarm level. Bigger h = slower but fewer false alarms.
    cap : upper limit for S (cap_factor * h). Without it, a long attack
          piles up a huge S and the alarm keeps ringing for a long time
          after the attack has ended. Here S drains in a few windows.
    """

    def __init__(self, mu, k, h, cap_factor=2.0):
        self.mu = mu
        self.k = k
        self.h = h
        self.cap = cap_factor * h
        self.s = 0.0

    def update(self, x):
        """Feed one window value. Returns (S, alarm).

        If x is None (missing measurement) S is left unchanged: we do not
        invent a value.
        """
        if x is not None:
            self.s = max(0.0, self.s + (x - self.mu - self.k))
            self.s = min(self.s, self.cap)
        return self.s, self.s > self.h

    def reset(self):
        self.s = 0.0
