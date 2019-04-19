import os
import sys
import time
from collections import defaultdict
import logging

from transaction_trace.local.ethereum_database import EthereumDatabase
from transaction_trace.analysis.trace_util import TraceUtil


def main(db_folder, from_time, to_time, log_file):
    call_injection = defaultdict(dict)

    with open(log_file, "r") as f:
        print("analyzing log...")
        for line in f.readlines():
            one = eval(line.strip("\n"))
            if one["abnormal_type"] == "CallInjection":
                call_injection[one["entry"]][one["parent_func"]] = False

    log_path = log_file.strip(log_file.split("/")[-1])
    with open(os.path.join(log_path, "failed-call-injection-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        db = EthereumDatabase(db_folder)
        for db_conn in db.get_connections(from_time, to_time):
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
                        print("tx_hash %s to_address %s func %s" % (tx_hash, trace["to_address"], func))
                        call_injection[trace["to_address"]][func] = True
    import IPython;IPython.embed()

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time log_file" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
