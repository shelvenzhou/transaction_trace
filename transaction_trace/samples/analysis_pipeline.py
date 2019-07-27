import logging
import os
import pickle
import sys
import time

import transaction_trace
from transaction_trace.analysis import (ContractCentricAnalysis, PreProcess,
                                        TransactionCentricAnalysis)
from transaction_trace.analysis.checkers import *
from transaction_trace.analysis.intermediate_representations import Transaction
from transaction_trace.analysis.results import AttackCandidateExporter

l = logging.getLogger('analysis_pipeline')


def main(db_folder, log_path):

    p = PreProcess(db_folder)

    attack_candidates = open(os.path.join(log_path, "attack-candidates-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+")
    failed_attacks = open(os.path.join(log_path, "failed-attacks-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+")
    candidate_file = AttackCandidateExporter(attack_candidates)
    failure_file = AttackCandidateExporter(failed_attacks)

    # candidates = list()

    tca = TransactionCentricAnalysis()
    tca.register_transaction_centric_checker(CallInjectionChecker())
    tca.register_transaction_centric_checker(AirdropHuntingChecker())
    tca.register_transaction_centric_checker(IntegerOverflowChecker(10**60))
    # tca.register_transaction_centric_checker(ReentrancyChecker(5))

    for call_tree, result_graph in p.preprocess():
        if call_tree == None:
            continue
        tca.do_analysis(call_tree, result_graph)
        if call_tree.tx.is_attack:
            for candidate in call_tree.tx.attack_candidates:
                candidate_file.dump_candidate(candidate)
            for failure in call_tree.tx.failed_attacks:
                failure_file.dump_candidate(failure)

        # if len(call_tree.tx.destruct_contracts) > 0:
        #     pass

    # cca = ContractCentricAnalysis(db_folder)
    # cca.register_contract_centric_checker(ProfitChecker())
    # cca.register_contract_centric_checker(CallAfterDestructChecker(log_file))

    # cca.do_analysis(candidates)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 %s db_folder log_path" % sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2])
