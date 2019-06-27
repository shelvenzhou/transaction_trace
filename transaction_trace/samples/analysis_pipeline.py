import logging
import sys
import os
import time

import transaction_trace
from transaction_trace.analysis import TransactionCentricAnalysis, ContractCentricAnalysis, PreProcess
from transaction_trace.analysis.checkers import CallInjectionChecker, AirdropHuntingChecker, IntegerOverflowChecker, ReentrancyChecker, ProfitChecker

l = logging.getLogger('driver')


def main(db_folder, log_path):
    p = PreProcess(db_folder)

    with open(os.path.join(log_path, "smart-contract-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        tca = TransactionCentricAnalysis(log_file)
        tca.register_transaction_centric_checker(CallInjectionChecker())
        tca.register_transaction_centric_checker(AirdropHuntingChecker(5))
        tca.register_transaction_centric_checker(IntegerOverflowChecker(10**60))
        tca.register_transaction_centric_checker(ReentrancyChecker(5))

        cca = ContractCentricAnalysis(log_file)
        cca.register_contract_centric_checker(ProfitChecker(db_folder))

        candidates = list()
        for call_tree, result_graph in p.preprocess():
            tca.do_analysis(call_tree, result_graph)
            if call_tree.tx.is_attack == True:
                candidates.append(call_tree.tx)

        for tx in candidates:
            cca.do_analysis(tx)




if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 %s db_folder log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2])
