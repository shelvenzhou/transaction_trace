import os
import sys
import time

from transaction_trace.analysis import CallInjection, SubtraceGraph
from transaction_trace.local import EthereumDatabase

def main(db_folder, from_time, to_time, log_path):
    with open(os.path.join(log_path, "call-injection-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        call_injection_analyzer = CallInjection(log_file)
        db = EthereumDatabase(db_folder)
        for db_conn in db.get_connections(from_time, to_time):
            if db_conn.date == "2016-10-01":
                continue
            subtrace_graph = SubtraceGraph(db_conn)
            call_injection_analyzer.setup(subtrace_graph)
            call_injection_analyzer.analyze()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
