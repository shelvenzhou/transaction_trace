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


def main(db_folder, mysql_password, log_path):

    p = PreProcess(db_folder)

    attack_candidates = open(os.path.join(log_path, "attack-candidates-%s.log" %
                                          str(time.strftime('%Y%m%d%H%M%S'))), "w+")
    failed_attacks = open(os.path.join(log_path, "failed-attacks-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+")
    candidate_file = AttackCandidateExporter(attack_candidates)
    failure_file = AttackCandidateExporter(failed_attacks)

    tca = TransactionCentricAnalysis()
    tca.register_transaction_centric_checker(CallInjectionChecker())
    tca.register_transaction_centric_checker(AirdropHuntingChecker())
    tca.register_transaction_centric_checker(IntegerOverflowChecker(10**60))
    tca.register_transaction_centric_checker(ReentrancyChecker(5))
    tca.register_transaction_centric_checker(HoneypotChecker())
    tca.register_transaction_centric_checker(CallAfterDestructChecker())
    # tca.register_transaction_centric_checker(TODChecker(mysql_password))

    for call_tree, result_graph in p.preprocess():
        if call_tree is None:
            continue
        tca.do_analysis(call_tree, result_graph)
        if call_tree.tx.is_attack:
            for candidate in call_tree.tx.attack_candidates:
                candidate_file.dump_candidate(candidate)
            for failure in call_tree.tx.failed_attacks:
                failure_file.dump_candidate(failure)

    if "honeypot" in tca.checkers:
        honeypot_checker = tca.checkers["honeypot"]
        for honeypot in honeypot_checker.attack_candidates():
            candidate_file.dump_candidate(honeypot)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python3 %s db_folder mysql_password log_path" % sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
