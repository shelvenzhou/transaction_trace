import sys

import transaction_trace
from transaction_trace.local.ethereum_database import EthereumDatabase
from transaction_trace.analysis import SubtraceGraph, SubtraceGraphAnalyzer


def main(db_folder, from_time, to_time, log_path):
    db = EthereumDatabase(db_folder)
    for db_conn in db.get_connections(from_time, to_time):
        subtrace_graph = SubtraceGraph(db_conn)
        subtrace_graph_analyzer = SubtraceGraphAnalyzer(subtrace_graph, log_path)

        subtrace_graph_analyzer.find_all_abnormal_behaviors()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time log_path" % sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
