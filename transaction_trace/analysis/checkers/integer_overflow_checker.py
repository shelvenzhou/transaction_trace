from ..intermediate_representations import ResultGraph
from ..knowledge import SensitiveAPIs
from ..results import ResultType, AttackCandidate
from .checker import Checker, CheckerType


class IntegerOverflowChecker(Checker):

    def __init__(self, threshold):
        super(IntegerOverflowChecker, self).__init__("integer-overflow")
        self.threshold = threshold

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        at = action_tree.t
        rg = result_graph.g

        candidates = list()
        for e in at.edges():
            trace = at.edges[e]
            if trace['trace_type'] != "call":
                continue

            if SensitiveAPIs.sensitive_function_call(trace['input']):
                func_name = SensitiveAPIs.func_name(trace['input'])
                # if func_name in SensitiveAPIs._integer_overflow_sensitive_functions:
                #     candidates.append((e, func_name))
                candidates.append((e, func_name))

        intentions = list()
        sensitive_nodes = set()
        expected_token_transfers = set()
        # search partial-result-graph for each candidate
        for (edge, func_name) in candidates:
            prg = ResultGraph.build_partial_result_graph(result_graph.t, edge[0], True)

            intention = dict()
            for e in prg.edges():
                result = dict()
                for result_type in prg.edges[e]:
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt != ResultType.TOKEN_TRANSFER:
                        continue
                    if prg.edges[e][result_type] > self.threshold:
                        expected_token_transfers.add(ResultGraph.extract_token_address(result_type))
                        result[result_type] = prg.edges[e][result_type]
                        sensitive_nodes.add(e[1])
                if len(result) > 0:
                    intention[str(e)] = result

            if len(intention) > 0:
                intentions.append({
                    'edge': edge,
                    'func_name': func_name,
                    'intention': intention
                })

        if len(intentions) > 0:
            tx.is_attack = True

            profits = dict()
            real_token_transfers = set()
            for node in rg.nodes():
                if node not in sensitive_nodes:
                    continue
                profit = dict()
                for result_type in rg.nodes[node]:
                    if ResultGraph.extract_result_type(result_type) != ResultType.TOKEN_TRANSFER_EVENT:
                        continue
                    real_token_transfers.add(ResultGraph.extract_token_address(result_type))
                    if rg.nodes[node][result_type] > self.minimum_profit_amount[ResultType.TOKEN_TRANSFER]:
                        profit[result_type] = rg.nodes[node][result_type]
                if len(profit) > 0:
                    profits[node] = profit

            candidate = AttackCandidate(
                self.name,
                {
                    "transaction": tx.tx_hash,
                    "attacks": intentions,
                },
                profits,
            )
            if expected_token_transfers != real_token_transfers or len(action_tree.errs) > 0:
                tx.failed_attacks.append(candidate)
            else:
                tx.attack_candidates.append(candidate)
