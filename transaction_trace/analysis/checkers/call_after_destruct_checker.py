import logging
from collections import defaultdict

from ...basic_utils import DatetimeUtils
from ...local import DatabaseName
from ..intermediate_representations import ActionTree
from ..knowledge import SensitiveAPIs
from ..results import AttackCandidate, ResultType
from .checker import Checker, CheckerType

l = logging.getLogger("transaction-trace.analysis.checkers.CallAfterDestructChecker")


class DestructLog:

    def __init__(self, tx_hash, contract, block_number, tx_index):
        self.tx_hash = tx_hash
        self.contract = contract
        self.block_number = block_number
        self.tx_index = tx_index


class CallAfterDestructChecker(Checker):

    def __init__(self):
        super(CallAfterDestructChecker, self).__init__("call-after-destruct")
        self.destruct_contracts = dict()

    @property
    def checker_type(self):
        return CheckerType.CONTRACT_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        at = action_tree.t

        for e in at.edges():
            from_address = ActionTree.extract_address_from_node(e[0])
            to_address = ActionTree.extract_address_from_node(e[1])
            trace = at.edges[e]

            if trace["status"] == 0:
                continue

            if trace["trace_type"] == "call" and to_address in self.destruct_contracts:
                tx.is_attack = True
                l.debug("%s call %s after suicide in %s", tx.tx_hash,
                        to_address, self.destruct_contracts[to_address].tx_hash)
                if trace["value"] > 0:
                    tx.attack_candidates.append(
                        AttackCandidate(
                            self.name,
                            {"transaction": tx.tx_hash, "suicided_contract": to_address},
                            {ResultType.ETHER_TRANSFER: trace["value"]}
                        )
                    )
                else:
                    for result_type, src, dst, amount in SensitiveAPIs.get_result_details(trace):
                        if result_type == ResultType.TOKEN_TRANSFER:
                            token_contract = to_address
                            tx.attack_candidates.append(
                                AttackCandidate(
                                    self.name,
                                    {"transaction": tx.tx_hash, "suicided_contract": to_address},
                                    {f"{ResultType.TOKEN_TRANSFER}:{token_contract}": amount}
                                )
                            )
                        elif result_type == ResultType.OWNER_CHANGE:
                            tx.attack_candidates.append(
                                AttackCandidate(
                                    self.name,
                                    {"transaction": tx.tx_hash, "suicided_contract": to_address},
                                    {f"{ResultType.OWNER_CHANGE}": f"owned_contract:{src} to_owner:{dst}"}
                                )
                            )
                        else:
                            tx.failed_attacks.append(
                                AttackCandidate(
                                    self.name,
                                    {"transaction": tx.tx_hash, "suicided_contract": to_address},
                                    {"CALL": result_type}
                                )
                            )

        # save destructed contracts after we have checked all the calls
        # TODO: shall we check same-tx CAD?
        for contract in action_tree.destructed_contracts:
            if contract in self.destruct_contracts:
                l.warning("contract suicides twice")
            self.destruct_contracts[contract] = DestructLog(tx.tx_hash, contract, tx.block_number, tx.tx_index)
