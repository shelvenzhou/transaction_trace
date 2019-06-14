import logging

from .checkers import CheckerType

l = logging.getLogger("transaction-trace.analysis.TransactionCentricAnalysis")


class TransactionCentricAnalysis:

    def __init__(self):
        self.checkers = dict()

    def register_transaction_centric_checker(self, checker):
        assert checker.checker_type == CheckerType.TRANSACTION_CENTRIC, "try to register a checker of wrong type"
        self.checkers[checker.name] = checker

    def do_analysis(self, call_tree, result_graph):
        for checker_name, checker in self.checkers.items():
            checker.check_transaction(call_tree, result_graph)
