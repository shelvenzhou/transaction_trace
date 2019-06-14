import logging

import transaction_trace
from transaction_trace.analysis import TransactionCentricAnalysis, ContractCentricAnalysis, PreProcess
from transaction_trace.analysis.checkers import CallInjectionChecker

l = logging.getLogger('driver')


db_folder = "/Users/shelven/Documents/Projects/smart-contract/databases"

def main():
    p = PreProcess(db_folder)

    tca = TransactionCentricAnalysis()
    tca.register_transaction_centric_checker(CallInjectionChecker())

    cca = ContractCentricAnalysis()

    for call_tree, result_graph in p.preprocess():
        tca.do_analysis(call_tree, result_graph)

if __name__ == '__main__':
    main()
