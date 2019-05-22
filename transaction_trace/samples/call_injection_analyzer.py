import os
import sys
import time

from transaction_trace.analysis import CallInjection, SubtraceGraph
from transaction_trace.local import EthereumDatabase

def main(db_folder, from_time, to_time, log_path, input_log_file):
    with open(os.path.join(log_path, "call-injection-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        call_injection_analyzer = CallInjection(log_file)
        if input_log_file == None:
            db = EthereumDatabase(db_folder)
            for db_conn in db.get_connections(from_time, to_time):
                if db_conn.date == "2016-10-01":
                    continue
                subtrace_graph = SubtraceGraph(db_conn)
                call_injection_analyzer.setup(subtrace_graph)
                call_injection_analyzer.analyze()
        else:
            call_injection_analyzer.filter_by_profitability(db_folder, os.path.join(log_path, input_log_file), from_time, to_time)



if __name__ == "__main__":
    if len(sys.argv) not in [5, 6]:
        print("Usage: python3 %s db_folder from_time to_time log_path [input_log_file]" %
              sys.argv[0])
        exit(-1)
    if len(sys.argv) == 5:
        sys.argv.append(None)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
