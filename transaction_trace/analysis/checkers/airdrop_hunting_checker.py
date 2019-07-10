from collections import defaultdict

from ..intermediate_representations import ResultGraph, ResultType
from .checker import Checker, CheckerType


class AirdropHuntingChecker(Checker):

    def __init__(self):
        super(AirdropHuntingChecker, self).__init__("airdrop-hunting")

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        at = action_tree.t
        rg = result_graph.g

        slaves = list()
        # search for airdrop-hunting candidates edge by edge
        edges = at.edges()
        for e in edges:
            trace = at.edges[e]
            # add the created slave contract to candidates
            if trace['trace_type'] == 'create':
                slaves.append(e[1])

        huntings = list()
        # search partial-result-graph for each candidate
        for s in slaves:
            prg = ResultGraph.build_partial_result_graph(at, s)

            results = list()
            for node in prg.nodes():
                for result_type in prg.nodes[node]:
                    # in airdrop hunting, we only concern about token transfer
                    if ResultGraph.extract_result_type(result_type) == ResultType.TOKEN_TRANSFER:
                        amount = prg.nodes[node][result_type]
                        if amount > 0:
                            results.append({
                                "profit_node": node,
                                "result_type": result_type,
                                "amount": amount,
                            })

            if len(results) > 0:
                huntings.append(results)

        if len(huntings) > 0:
            profits = dict()
            for node in rg.nodes():
                profit = dict()
                for result_type in rg.nodes[node]:
                    if ResultGraph.extract_result_type(result_type) != ResultType.TOKEN_TRANSFER_EVENT:
                        continue
                    if rg.nodes[node][result_type] > self.minimum_profit_amount[ResultType.TOKEN_TRANSFER]:
                        profit[result_type] = rg.nodes[node][result_type]
                if len(profit) > 0:
                    profits[node] = profit

            if len(profits) > 0:
                tx.is_attack = True
                tx.attack_details.append({
                    "checker": self.name,
                    "hunting_time": len(huntings),
                    "profit": profits
                })
