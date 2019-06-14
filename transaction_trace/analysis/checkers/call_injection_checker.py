from .checker import Checker, CheckerType

class CallInjectionChecker(Checker):

    def __init__(self, log_file=sys.stdout):
        super(CallInjectionChecker, self).__init__(log_file)

    @property
    def name(self):
        return "call-injection checker"

    @property
    def checker_type(self):
        raise CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        pass
