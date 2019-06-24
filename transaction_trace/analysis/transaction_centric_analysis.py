import logging

from .checkers import CheckerType
from .trace_analysis import TraceAnalysis
from ..datetime_utils import time_to_str

l = logging.getLogger("transaction-trace.analysis.TransactionCentricAnalysis")


class TransactionCentricAnalysis(TraceAnalysis):

    def __init__(self, log_file):
        super(TransactionCentricAnalysis, self).__init__(log_file=log_file)
        self.checkers = dict()

    def register_transaction_centric_checker(self, checker):
        assert checker.checker_type == CheckerType.TRANSACTION_CENTRIC, "try to register a checker of wrong type"
        self.checkers[checker.name] = checker

    def do_analysis(self, call_tree, result_graph):
        if call_tree is None:
            return
        # l.info(call_tree.tx.tx_hash)
        for checker_name, checker in self.checkers.items():
            checker.check_transaction(call_tree, result_graph)

        tx = call_tree.tx
        if tx.is_attack:
            l.info("%s | %s %s", time_to_str(tx.block_timestamp), tx.tx_hash, str(
                set([attack['checker'] for attack in tx.attack_details])))
            self.record_abnormal_detail(tx.to_string())
