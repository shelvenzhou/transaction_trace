from .checker import Checker, CheckerType


class DestructContractChecker(Checker):
    def __init__(self):
        super(DestructContractChecker, self).__init__("destruct_contract")

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        # search for destrcut contracts edge by edge
        edges = action_tree.t.edges()
        for e in edges:
            trace = action_tree.t.edges[e]
            if trace["status"] == 0:
                continue
            if trace["trace_type"] == "suicide":
                tx.destruct_contracts.append({
                    'contract': trace['from_address'],
                    'value': trace['value']
                })
