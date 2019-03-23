import os
import sys
import time

import transaction_trace
from transaction_trace.analysis import SubtraceGraph, SubtraceGraphAnalyzer
from transaction_trace.local.ethereum_database import EthereumDatabase


def main(db_folder, from_time, to_time, log_path):
    with open(
            os.path.join(
                log_path, "subtrace-graph-analyzer-%s.log" % str(
                    time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        db = EthereumDatabase(db_folder)
        for db_conn in db.get_connections(from_time, to_time):
            subtrace_graph = SubtraceGraph(db_conn)
            subtrace_graph_analyzer = SubtraceGraphAnalyzer(
                subtrace_graph, db_folder, log_file)

            subtrace_graph_analyzer.find_all_abnormal_behaviors()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
