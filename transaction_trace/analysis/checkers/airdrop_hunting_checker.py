from .checker import Checker, CheckerType
from ..intermediate_representations import ResultGraph, ResultType
from collections import defaultdict


class AirdropHuntingChecker(Checker):

    def __init__(self, threshold):
        super(AirdropHuntingChecker, self).__init__("airdrop-hunting")
        self.threshold = threshold

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        candidates = list()
        # search for airdrop-hunting candidates edge by edge
        edges = action_tree.t.edges()
        if len(edges) < self.threshold:
            return
        for e in edges:
            trace = action_tree.t.edges[e]
            # add the created slave contract to candidates
            if trace['trace_type'] == 'create':
                candidates.append(e[1])

        tx = action_tree.tx
        hunting_time = list()
        # search partial-result-graph for each candidate
        for n in candidates:
            prg = ResultGraph.build_partial_result_graph(result_graph.t, n)

            results = list()
            for node in prg.nodes():
                for result_type in prg.nodes[node]:
                    if ResultGraph.extract_result_type(result_type) != ResultType.TOKEN_TRANSFER:
                        continue
                    if prg.nodes[node][result_type] > 0:
                        results.append({
                            "profit_node": node,
                            "result_type": result_type,
                            "amount": prg.nodes[node][result_type]
                        })

            if len(results) > 0:
                hunting_time.append(results)

        if len(hunting_time) > self.threshold:
            rg = result_graph
            profits = dict()
            for node in rg.g.nodes():
                profit = dict()
                if result_type in rg.g.nodes[node]:
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
                    "hunting_time": len(hunting_time),
                    "profit": profits
                })
