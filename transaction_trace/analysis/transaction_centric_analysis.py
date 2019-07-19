import logging

from ..basic_utils import DatetimeUtils
from .checkers import CheckerType
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.TransactionCentricAnalysis")


class TransactionCentricAnalysis(TraceAnalysis):

    def __init__(self):
        super(TransactionCentricAnalysis, self).__init__()
        self.checkers = dict()

    def register_transaction_centric_checker(self, checker):
        assert checker.checker_type == CheckerType.TRANSACTION_CENTRIC, "try to register a checker of wrong type"
        self.checkers[checker.name] = checker

    def do_analysis(self, call_tree, result_graph):
        if call_tree is None:
            return
        for checker_name, checker in self.checkers.items():
            checker.check_transaction(call_tree, result_graph)
