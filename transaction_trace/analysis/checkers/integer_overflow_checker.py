from .checker import Checker, CheckerType
from ..intermediate_representations import ResultGraph, ResultType
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
                if func_name in SensitiveAPIs._integer_overflow_sensitive_functions:
                    candidates.append((e, func_name))
                # candidates.append((e, func_name))

        tx = action_tree.tx
        attacks = list()
        sensitive_nodes = set()
        # search partial-result-graph for each candidate
        for (edge, func_name) in candidates:
            prg = ResultGraph.build_partial_result_graph(result_graph.t, edge[0], edge)

            results = dict()
            for e in prg.edges():
                result = dict()
                for result_type in prg.edges[e]:
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt != ResultType.TOKEN_TRANSFER:
                        continue
                    if prg.edges[e][result_type] > self.threshold:
                        result[result_type] = prg.edges[e][result_type]
                        sensitive_nodes.add(e[1])
                if len(result) > 0:
                    results[e] = result

            if len(results) > 0:
                attacks.append({
                    'edge': edge,
                    'func_name': func_name,
                    'results': results
                })


        if len(attacks) > 0:
            rg = result_graph
            profits = dict()
            for node in rg.g.nodes():
                if node not in sensitive_nodes:
                    continue
                profit = dict()
                for result_type in rg.g.nodes[node]:
                    if ResultGraph.extract_result_type(result_type) != ResultType.TOKEN_TRANSFER_EVENT:
                        continue
                    if rg.g.nodes[node][result_type] > self.minimum_profit_amount[ResultType.TOKEN_TRANSFER]:
                        profit[result_type] = rg.g.nodes[node][result_type]
                if len(profit) > 0:
                    profits[node] = profit

            if len(profits) > 0:
                tx.is_attack = True
                tx.attack_details.append({
                    "checker": self.name,
                    "attacks": attacks,
                    "profit": profits
                })
