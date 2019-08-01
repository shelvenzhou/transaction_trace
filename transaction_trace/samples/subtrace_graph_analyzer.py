import os
import sys
import time

import pickle

from collections import defaultdict
import transaction_trace
from transaction_trace.analysis import SubtraceGraph, SubtraceGraphAnalyzer
from transaction_trace.local.ethereum_database import EthereumDatabase


def main(db_folder, log_path, contract_filepath):
    with open(os.path.join(log_path, "new-reentrancy-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        sensitive_contracts = list()
        with open(contract_filepath, "r") as f:
            for line in f.readline():
                sensitive_contracts.append(line.replace("\n", ""))
        concerned_contract = defaultdict(int)

        db = EthereumDatabase(db_folder)
        for db_conn in db.get_all_connections():
            subtrace_graph = SubtraceGraph(db_conn, sensitive_contracts, concerned_contract)
            subtrace_graph_analyzer = SubtraceGraphAnalyzer(
                subtrace_graph, log_file)

            subtrace_graph_analyzer.find_all_abnormal_behaviors(log_file)

            with open("contract_txs.pickle", "wb") as f:
                pickle.dump(concerned_contract,f)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 %s db_folder log_path contract_filepath" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
