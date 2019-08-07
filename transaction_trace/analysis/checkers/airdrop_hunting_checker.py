from collections import defaultdict

from ...basic_utils import DatetimeUtils
from ..intermediate_representations import ResultGraph
from ..results import AttackCandidate, ResultType
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
        for e in at.edges():
            trace = at.edges[e]
            if trace['trace_type'] == 'create':
                slaves.append(e[1])

        intentions = list()
        expected_token_transfers = set()
        for s in slaves:  # check whether these slaves cause any token transfers
            prg = ResultGraph.build_partial_result_graph(result_graph.t, s)

            results = list()
            for node in prg.nodes():
                for result_type in prg.nodes[node]:
                    # in airdrop hunting, we only concern about token transfer
                    if ResultGraph.extract_result_type(result_type) == ResultType.TOKEN_TRANSFER:
                        expected_token_transfers.add(ResultGraph.extract_token_address(result_type))
                        amount = prg.nodes[node][result_type]
                        if amount > 0:
                            results.append({
                                "profit_node": node,
                                "result_type": result_type,
                                "amount": amount,
                            })

            if len(results) > 0:
                intentions.extend(results)

        if len(intentions) > 0:
            tx.is_attack = True

            profits = dict()
            real_token_transfers = set()
            for node in rg.nodes():
                profit = dict()
                for result_type in rg.nodes[node]:
                    if ResultGraph.extract_result_type(result_type) != ResultType.TOKEN_TRANSFER_EVENT:
                        continue
                    real_token_transfers.add(ResultGraph.extract_token_address(result_type))
                    if rg.nodes[node][result_type] > self.minimum_profit_amount[ResultType.TOKEN_TRANSFER_EVENT]:
                        profit[result_type] = rg.nodes[node][result_type]
                if len(profit) > 0:
                    profits[node] = profit

            candidate = AttackCandidate(
                self.name,
                {
                    "transaction": tx.tx_hash,
                    "tx_time": DatetimeUtils.time_to_str(tx.block_timestamp),
                    "slave_number": len(slaves),
                    "hunting_time": len(intentions),
                },
                # intentions,
                profits,
            )
            if expected_token_transfers != real_token_transfers or len(action_tree.errs) > 0:
                if expected_token_transfers != real_token_transfers:
                    candidate.add_failed_reason("unrealized token transfer")
                if len(action_tree.errs) > 0:
                    errs = set()
                    for err in action_tree.errs:
                        if err["error"] not in errs:
                            candidate.add_failed_reason(err["error"])
                        errs.add(err["error"])
                tx.failed_attacks.append(candidate)
            else:
                tx.attack_candidates.append(candidate)
