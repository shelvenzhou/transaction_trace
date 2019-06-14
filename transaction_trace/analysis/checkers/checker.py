import sys


class CheckerType:

    TRANSACTION_CENTRIC = 'TRANSACTION_CENTRIC'
    CONTRACT_CENTRIC = 'CONTRACT_CENTRIC'


class Checker:
    def __init__(self, log_file=sys.stdout):
        self.log_file = log_file

    @property
    def name(self):
        raise NotImplementedError

    @property
    def checker_type(self):
        raise NotImplementedError

    def check_transaction(self, action_tree, result_graph):
        raise NotImplementedError

    def check_contract(self, contract):
        raise NotImplementedError

    def record_abnormal_detail(self, *args):
        if len(args) == 1:
            print(args[0], file=self.log_file)
        else:
            date = args[0]
            abnormal_type = args[1]
            detail = args[2]
            print("[%s][%s]: %s" %
                  (date, abnormal_type, detail), file=self.log_file)
