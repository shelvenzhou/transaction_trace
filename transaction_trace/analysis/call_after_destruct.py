import logging
from collections import defaultdict

from ..datetime_utils import str_to_time, time_to_str
from .trace_analysis import TraceAnalysis
from .trace_util import TraceUtil
from .knowledge.sensitive_apis import SensitiveAPIs

l = logging.getLogger("transaction-trace.analysis.CallAfterDestruct")


class CallAfterDestruct(TraceAnalysis):
    def __init__(self, db_folder, log_file):
        super(CallAfterDestruct, self).__init__(db_folder, log_file)

    def find_call_after_destruct(self, from_time, to_time):
        ABNORMAL_TYPE = "CallAfterDestruct"

        dead_contracts = defaultdict(dict)
        # call_after_destruct = defaultdict(dict)
        for conn in self.database.get_connections(from_time, to_time):
            l.info("construct for %s", conn)
            traces = defaultdict(list)
            for row in conn.read_traces(with_rowid=True):
                if row['trace_type'] not in ('call', 'create', 'suicide'):
                    l.info("ignore trace of type %s", row['trace_type'])
                    continue
                tx_hash = row['transaction_hash']
                traces[tx_hash].append(row)

            for tx_hash in traces:
                call_after_destruct = list()
                for trace in traces[tx_hash]:
                    if trace["status"] == 0:
                        continue
                    if trace["trace_type"] == "suicide":
                        dead_contracts[trace["from_address"]] = {
                            "death_time": time_to_str(trace["block_timestamp"]),
                            "death_tx": tx_hash
                        }
                    elif trace["trace_type"] == "call" and trace["to_address"] in dead_contracts and time_to_str(trace["block_timestamp"]) > dead_contracts[trace["to_address"]]["death_time"]:
                        callee = SensitiveAPIs.func_name(trace["input"])
                        if SensitiveAPIs.sensitive_function_call(trace["input"]):
                            callee = SensitiveAPIs.func_name(trace["input"])
                            detail = {
                                "contract": trace["to_address"],
                                "death_time": dead_contracts[trace["to_address"]]["death_time"],
                                "death_tx": dead_contracts[trace["to_address"]]["death_tx"],
                                "callee": callee
                            }
                            call_after_destruct.append(detail)

                if len(call_after_destruct) > 0:
                    l.info("CallAfterDestruct found for tx: %s", tx_hash)
                    self.record_abnormal_detail({
                        "tx_hash": tx_hash,
                        "time": time_to_str(traces[tx_hash][0]["block_timestamp"]),
                        "detail": call_after_destruct
                    })
