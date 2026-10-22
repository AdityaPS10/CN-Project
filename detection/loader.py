import csv
import math

from config import EXPECTED_COLUMNS, REQUIRED_FEATURES


def parse_value(text):
    """Convert a CSV cell to a float. Return None if empty or invalid."""
    if text is None:
        return None
    text = text.strip()
    if text == "":
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def parse_row(raw, line_no=None, problems=None):
    """Turn one CSV row (a dict of strings) into a clean row of floats/None.

    Returns None if the timestamp is unusable (the row must be skipped).
    Anything suspicious is appended to `problems` as (line_no, message).
    """
    if problems is None:
        problems = []
    row = {c: parse_value(raw.get(c)) for c in EXPECTED_COLUMNS}

    if row["timestamp"] is None:
        problems.append((line_no, "timestamp missing or invalid; row skipped"))
        return None

    for col in REQUIRED_FEATURES:
        if row[col] is None:
            problems.append((line_no, col + " missing or invalid"))
        elif row[col] < 0:
            problems.append((line_no, col + " is negative; set to None"))
            row[col] = None
    return row


def load_features(path):
    """Read a whole feature CSV from Member 2.

    Returns (rows, problems):
      rows     - list of dicts, one per window, values are float or None
      problems - list of (line_number, message) for anything suspicious
    """
    rows = []
    problems = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        missing = [c for c in EXPECTED_COLUMNS if c not in header]
        if missing:
            raise ValueError("CSV is missing columns: " + ", ".join(missing))

        for line_no, raw in enumerate(reader, start=2):
            row = parse_row(raw, line_no, problems)
            if row is not None:
                rows.append(row)
    return rows, problems
