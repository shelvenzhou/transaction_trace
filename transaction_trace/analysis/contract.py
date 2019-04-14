import logging
from collections import defaultdict

from ..local import EthereumDatabase
from ..datetime_utils import time_to_str, str_to_time

l = logging.getLogger("transaction-trace.analysis.ContractAnalyzer")


class Contract:
    def __init__(self, db_folder, log_file):
        self.database = EthereumDatabase(db_folder)
        self.log_file = log_file

    def record_abnormal_detail(self, date, abnormal_type, detail):
        print("[%s][%s]: %s" %
              (date, abnormal_type, detail), file=self.log_file)

    def find_call_after_destruct(self, from_time, to_time):
        ABNORMAL_TYPE = "CallAfterDestruct"

        dead_contracts = defaultdict(dict)
        call_after_destruct = defaultdict(dict)
        for db_conn in self.database.get_connections(from_time, to_time):
            for row in db_conn.read_traces():
                if row["trace_type"] == "suicide":
                    dead_contracts[row["from_address"]
                                   ]["death_time"] = time_to_str(row["block_timestamp"])
                    dead_contracts[row["from_address"]
                                   ]["death_tx"] = row["transaction_hash"]
                elif row["to_address"] in dead_contracts and time_to_str(row["block_timestamp"]) > dead_contracts[row["to_address"]]["death_time"] and row["to_address"] not in call_after_destruct:
                    call_after_destruct[row["to_address"]] = {
                        "death_time": dead_contracts[row["to_address"]]["death_time"],
                        "death_tx": dead_contracts[row["to_address"]]["death_tx"],
                        "call_time": time_to_str(row["block_timestamp"]),
                        "call_tx": row["transaction_hash"]
                    }
                    l.info("CallAfterDestruct found for contract: %s death time: %s call time: %s",
                           row["to_address"], call_after_destruct[row["to_address"]]["death_time"], call_after_destruct[row["to_address"]]["call_time"])
                    self.record_abnormal_detail(db_conn.date, ABNORMAL_TYPE, "death time: %s death tx: %s call time: %s call tx: %s" % (
                        call_after_destruct[row["to_address"]]["death_time"],
                        call_after_destruct[row["to_address"]]["death_tx"],
                        call_after_destruct[row["to_address"]]["call_time"],
                        call_after_destruct[row["to_address"]]["call_tx"]))
