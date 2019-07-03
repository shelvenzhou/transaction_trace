import logging
import sys
import os
import time
import pickle

import transaction_trace
from transaction_trace.analysis.intermediate_representations import Transaction
from transaction_trace.analysis import TransactionCentricAnalysis, ContractCentricAnalysis, PreProcess
from transaction_trace.analysis.checkers import CallInjectionChecker, AirdropHuntingChecker, IntegerOverflowChecker, ReentrancyChecker, ProfitChecker

l = logging.getLogger('driver')


def main(db_folder, log_path, input_log_file=None):
    p = PreProcess(db_folder)

    with open(os.path.join(log_path, "smart-contract-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        with open('/home/xiangjie/txs', 'rb') as f:
            txs = pickle.load(f)

        candidates = list()
        if input_log_file == None:
            tca = TransactionCentricAnalysis(log_file)
            tca.register_transaction_centric_checker(CallInjectionChecker())
            tca.register_transaction_centric_checker(AirdropHuntingChecker(5))
            tca.register_transaction_centric_checker(IntegerOverflowChecker(10**60))
            tca.register_transaction_centric_checker(ReentrancyChecker(5))

            for call_tree, result_graph in p.preprocess(txs):
                if call_tree == None:
                    continue
                if call_tree.tx.tx_hash not in txs:
                    continue
                tca.do_analysis(call_tree, result_graph)
                if call_tree.tx.is_attack == True:
                    candidates.append(call_tree.tx)
        else:
            with open(os.path.join(log_path, input_log_file)) as input_log:
                lines = input_log.readlines()
                for line in lines:
                    d = eval(line.strip('\n'))
                    candidates.append(Transaction.from_dict(d))

        cca = ContractCentricAnalysis(log_file)
        cca.register_contract_centric_checker(ProfitChecker(db_folder))

        for tx in candidates:
            cca.do_analysis(tx)




if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 %s db_folder log_path [log_file]" %
              sys.argv[0])
        exit(-1)
    if len(sys.argv) == 3:
        sys.argv.append(None)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
