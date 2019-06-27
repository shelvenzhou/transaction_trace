from .checker import Checker, CheckerType
from ..intermediate_representations.result_graph import ResultGraph, ResultType
from ..knowledge import SensitiveAPIs


class IntegerOverflowChecker(Checker):

    def __init__(self, threshold):
        super(IntegerOverflowChecker, self).__init__("integer-overflow")
        self.threshold = threshold

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        candidates = list()
        # search for integer-overflow candidates edge by edge
        edges = action_tree.t.edges()
        for e in edges:
            trace = action_tree.t.edges[e]
            if trace['trace_type'] != "call":
                continue

            if SensitiveAPIs.sensitive_function_call(trace['input']):
                func_name = SensitiveAPIs.func_name(trace['input'])
                candidates.append((e, func_name))

        tx = action_tree.tx
        attacks = list()
        # search partial-result-graph for each candidate
        for (edge, func_name) in candidates:
            prg = ResultGraph.build_partial_result_graph(result_graph.t, edge[0], True)

            results = list()
            for e in prg.edges():
                if ResultType.TOKEN_TRANSFER in prg.edges[e]:
                    for token in prg.edges[e][ResultType.TOKEN_TRANSFER]:
                        if prg.edges[e][ResultType.TOKEN_TRANSFER][token] > self.threshold:
                            results.append((token, prg.edges[e][ResultType.TOKEN_TRANSFER][token]))

            if len(results) > 0:
                attacks.append({
                    'edge': edge,
                    'func_name': func_name,
                    'results': results
                })

        if len(attacks) > 0:
            tx.is_attack = True
            tx.attack_details.append({
                'checker': self.name,
                'attacks': attacks
            })
