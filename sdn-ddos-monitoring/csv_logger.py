"""Member 2 - CSV writer. One row per observation window.

Fixed column order agreed with Member 3, plus DataPlanePacketRate as an
extra column at the end. HalfOpenTCPRatio is written empty (NaN in pandas)
because the dataset contains no TCP traffic.
"""
import csv
import os
import time

COLUMNS = [
    "timestamp",
    "PacketInRate",
    "FlowCreationRate",
    "SourceIPEntropy",
    "MeanIAT",
    "Jitter",
    "FlowTableOccupancy",
    "ControllerRequestRate",
    "HalfOpenTCPRatio",
    "DataPlanePacketRate",
]


class CsvLogger:
    def __init__(self, path):
        path = os.path.abspath(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            stamp = time.strftime("%Y%m%d_%H%M%S",
                                  time.localtime(os.path.getmtime(path)))
            os.rename(path, path[:-4] + "_" + stamp + ".csv")
        self.path = path
        self._fh = open(path, "w", newline="")
        self._writer = csv.writer(self._fh, lineterminator="\n")
        self._writer.writerow(COLUMNS)
        self._fh.flush()

    def write_row(self, values):
        assert len(values) == len(COLUMNS), "row has wrong number of fields"
        self._writer.writerow(values)
        self._fh.flush()

    def close(self):
        self._fh.close()
