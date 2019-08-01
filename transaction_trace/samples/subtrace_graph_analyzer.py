import os
import sys
import time

import transaction_trace
from transaction_trace.analysis import SubtraceGraph, SubtraceGraphAnalyzer
from transaction_trace.local.ethereum_database import EthereumDatabase


def main(db_folder, log_path):
    with open(os.path.join(log_path, "new-reentrancy-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        db = EthereumDatabase(db_folder)
        for db_conn in db.get_all_connections():
            subtrace_graph = SubtraceGraph(db_conn)
            subtrace_graph_analyzer = SubtraceGraphAnalyzer(
                subtrace_graph, log_file)

            subtrace_graph_analyzer.find_all_abnormal_behaviors(log_file)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 %s db_folder log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2])
