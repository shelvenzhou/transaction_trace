import logging
from collections import defaultdict

from ..datetime_utils import str_to_time, time_to_str
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.CallAfterDestruct")


class CallAfterDestruct(TraceAnalysis):
    def __init__(self, db_folder, log_file):
        super(CallAfterDestruct, self).__init__(db_folder, log_file)

    def find_call_after_destruct(self, from_time, to_time):
        ABNORMAL_TYPE = "CallAfterDestruct"

        dead_contracts = defaultdict(dict)
        call_after_destruct = defaultdict(dict)
        for db_conn in self.database.get_connections(from_time, to_time):
            for row in db_conn.read_traces():
                if row["status"] == 0:
                    continue
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
                    detail = {
                        "date": db_conn.date,
                        "abnormal_type": ABNORMAL_TYPE,
                        "contract": row["to_address"],
                        "death time": call_after_destruct[row["to_address"]]["death_time"],
                        "death tx": call_after_destruct[row["to_address"]]["death_tx"],
                        "call time": call_after_destruct[row["to_address"]]["call_time"],
                        "call tx": call_after_destruct[row["to_address"]]["call_tx"]
                    }
                    self.record_abnormal_detail(detail)
