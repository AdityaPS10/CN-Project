"""Member 4 - reads and checks Member 3's decision records.

Interface (agreed with Member 3, see README.md "Interface with Member 3"):

    timestamp,traffic_class,score,reason,rule

One row per 1-second window, in time order. Columns are read by NAME, so
Member 3 may add columns later without breaking us; renaming or removing
one of these five is a breaking change.

`score` is max(rate/limit, CUSUM/h): above 1 means abnormal. It is NOT a
probability or confidence, and we never treat it as one.
"""
import csv
import os
from dataclasses import dataclass

REQUIRED_COLUMNS = ["timestamp", "traffic_class", "score", "reason", "rule"]

VALID_CLASSES = {"normal", "flash_crowd", "naive_ddos", "adaptive_ddos", "unknown"}
ATTACK_CLASSES = {"naive_ddos", "adaptive_ddos"}

# Member 3's rules, plus "entropy" from member4_mitigation/baseline_detectors.py.
VALID_RULES = {"none", "threshold", "cusum", "onset_jump", "repeat_burst",
               "hold", "missing_input", "entropy"}


@dataclass(frozen=True)
class Decision:
    timestamp: float
    traffic_class: str
    score: float
    reason: str
    rule: str

    @property
    def is_attack(self):
        # 'hold' rows carry traffic_class=adaptive_ddos, so they count as
        # attack: mitigation stays on during an adaptive attacker's pauses.
        return self.traffic_class in ATTACK_CLASSES


def parse_row(row):
    """Turn one CSV row (dict) into a Decision. Raises ValueError if bad."""
    missing = [c for c in REQUIRED_COLUMNS if c not in row or row[c] is None]
    if missing:
        raise ValueError("missing column(s): %s" % ", ".join(missing))

    try:
        timestamp = float(row["timestamp"])
    except ValueError:
        raise ValueError("timestamp %r is not a number" % row["timestamp"])
    try:
        score = float(row["score"])
    except ValueError:
        raise ValueError("score %r is not a number" % row["score"])

    cls = row["traffic_class"].strip()
    rule = row["rule"].strip()
    if cls not in VALID_CLASSES:
        raise ValueError("unknown traffic_class %r" % cls)
    if rule not in VALID_RULES:
        raise ValueError("unknown rule %r" % rule)

    return Decision(timestamp, cls, score, row["reason"], rule)


def read_decisions(path):
    """Read a whole decision CSV. Handles both \\n and \\r\\n line endings."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError("%s: header lacks %s" % (path, ", ".join(missing)))
        decisions = []
        for lineno, row in enumerate(reader, start=2):
            try:
                decisions.append(parse_row(row))
            except ValueError as e:
                raise ValueError("%s line %d: %s" % (path, lineno, e))
    for a, b in zip(decisions, decisions[1:]):
        if b.timestamp < a.timestamp:
            raise ValueError("%s: timestamps go backwards at %.3f" % (path, b.timestamp))
    return decisions


class DecisionFollower:
    """Follows Member 3's live decision CSV while it is being written.

    Call poll() repeatedly; it returns (new_decisions, notes). notes is a
    list of (kind, message) with kind 'reset' (file replaced or truncated,
    i.e. the detector restarted) or 'bad_row' (row skipped, not fatal).

    skip_existing=True ignores rows already in the file when we first open
    it, so decisions left over from an earlier run never trigger mitigation.
    After a reset the new file is always read from its first row.
    """

    def __init__(self, path, skip_existing=True):
        self.path = path
        self.skip_existing = skip_existing
        self.opened = False
        self.offset = 0
        self.inode = None
        self.buf = b""
        self.header = None

    def _restart(self):
        self.offset, self.buf, self.header = 0, b"", None

    def poll(self):
        notes = []
        if not os.path.exists(self.path):
            return [], notes
        st = os.stat(self.path)

        if not self.opened:
            self.opened = True
            self.inode = st.st_ino
            if self.skip_existing:
                with open(self.path, "rb") as f:
                    data = f.read()
                nl = data.find(b"\n")
                if nl < 0:
                    return [], notes          # header not complete yet; read later
                self.header = next(csv.reader([data[:nl].decode().strip("\r")]))
                self.offset = data.rfind(b"\n") + 1
        elif st.st_ino != self.inode or st.st_size < self.offset:
            notes.append(("reset", "decision file replaced/truncated (detector restarted)"))
            self.inode = st.st_ino
            self._restart()

        if st.st_size <= self.offset:
            return [], notes
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            chunk = f.read()
        self.offset += len(chunk)
        self.buf += chunk
        *lines, self.buf = self.buf.split(b"\n")   # keep a half-written last line

        decisions = []
        for raw in lines:
            line = raw.decode("utf-8", "replace").strip("\r")
            if not line:
                continue
            values = next(csv.reader([line]))
            if self.header is None:
                self.header = values
                continue
            try:
                decisions.append(parse_row(dict(zip(self.header, values))))
            except ValueError as e:
                notes.append(("bad_row", "skipped row %r: %s" % (line, e)))
        return decisions, notes


if __name__ == "__main__":
    # Quick check: python3 -m member4_mitigation.decisions <file.csv> ...
    import sys
    from collections import Counter

    for path in sys.argv[1:]:
        ds = read_decisions(path)
        counts = Counter(d.traffic_class for d in ds)
        attack = sum(d.is_attack for d in ds)
        print("%-45s rows=%4d attack_windows=%3d %s" % (path, len(ds), attack, dict(counts)))
