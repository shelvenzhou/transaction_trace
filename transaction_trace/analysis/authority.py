import logging
from collections import defaultdict

from ..local import EthereumDatabase
from .trace_util import TraceUtil

l = logging.getLogger("transaction-trace.analysis.AuthorityAnalyzer")

class AuthorityAnalyzer:
    def __init__(self, db_folder, log_file):
        self.database = EthereumDatabase(db_folder)
        self.log_file = log_file

    def record_abnormal_detail(self, detail):
        print(detail, file=self.log_file)

    def find_failed_call_injection(self, from_time, to_time, input_log):
        call_injection = defaultdict(dict)

        with open(input_log, "r") as f:
            l.info("analyzing log")
            for line in f.readlines():
                one = eval(line.strip("\n"))
                if one["abnormal_type"] == "CallInjection":
                    call_injection[one["entry"]][one["parent_func"]] = False

        for db_conn in self.database.get_connections(from_time, to_time):
            l.info("Prepare data: %s", db_conn)
            traces = db_conn.read_traces(True)
            subtraces = defaultdict(dict)
            for row in db_conn.read_subtraces():
                tx_hash = row["transaction_hash"]
                trace_id = row["trace_id"]
                parent_trace_id = row["parent_trace_id"]
                subtraces[tx_hash][trace_id] = parent_trace_id
            trees = TraceUtil.build_call_tree(subtraces)
            for trace in traces:
                tx_hash = trace["transaction_hash"]
                if trace["error"] == "Reverted" or trace["rowid"] not in trees[tx_hash]:
                    func = TraceUtil.get_callee(trace["trace_type"], trace["input"])
                    if trace["to_address"] in call_injection and func in call_injection[trace["to_address"]]:
                        call_injection[trace["to_address"]][func] = True
                        l.info("failed call injection found for tx_hash %s to_address %s func %s" % (tx_hash, trace["to_address"], func))
                        detail = {
                            "date": db_conn.date,
                            "abnormal_type": "FailedCallInjection",
                            "tx_hash": tx_hash,
                            "to_address": trace["to_address"],
                            "func": func
                        }
                        self.record_abnormal_detail(detail)
