import logging
from collections import defaultdict

from ...local import ContractCode, EVMExecutor
from ..results import AttackCandidate, ResultType
from .checker import Checker, CheckerType

l = logging.getLogger("transaction-trace.analysis.checker.TODChecker")

evm = EVMExecutor()


class StorageAccess:

    def __init__(self, tx_hash, tx_caller, contract, gas, gas_used, cause_ether_flow):
        self.tx_hash = tx_hash
        self.tx_caller = tx_caller
        self.contract = contract
        self.gas = gas
        self.gas_used = gas_used
        self.cause_ether_flow = cause_ether_flow

    def __eq__(self, other):
        if not isinstance(other, StorageAccess):
            return False
        return self.tx_hash == other.tx_hash and self.tx_caller == other.tx_caller and self.contract == other.contract and self.gas == other.gas

    def similar_gas(self, other):
        if not isinstance(other, StorageAccess):
            return True
        if self.gas == 0 or other.gas == 0:
            # import ipdb; ipdb.set_trace()
            return True
        return (abs(self.gas - other.gas) / self.gas) < 0.5


class SimplifiedTODChecker(Checker):

    def __init__(self):
        super(SimplifiedTODChecker, self).__init__("simplified-transaction-order-dependence-checker")
        self.latest_block = None
        self.contract_accesses = defaultdict(list)

    @property
    def checker_type(self):
        return CheckerType.CONTRACT_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        at = action_tree.t
        rg = result_graph.g

        if self.latest_block is None:
            self.latest_block = tx.block_number

        if tx.block_number != self.latest_block:
            # check whether TOD happens in previous block
            for contract, accessed_txs in self.contract_accesses.items():
                if len(accessed_txs) < 2:
                    continue

                # skip txs which cause no ether flow
                ether_related = False
                for accessed_tx in accessed_txs:
                    if accessed_tx.cause_ether_flow:
                        ether_related = True
                        break
                if not ether_related:
                    continue

                # cross-tx read after write is regarded as TOD
                ether_flow = False
                affected_txs = list()
                for i, accessed_tx in enumerate(accessed_txs):
                    for j in range(i, len(accessed_txs)):
                        other_tx = accessed_txs[j]

                        # one cannot attack himself
                        if accessed_tx.tx_caller == other_tx.tx_caller:
                            continue

                        if accessed_tx.similar_gas(other_tx):
                            continue

                        if accessed_tx.cause_ether_flow or other_tx.cause_ether_flow:
                            ether_flow = True

                        affected_txs.append(
                            {
                                "txs": [accessed_tx.tx_hash, other_tx.tx_hash],
                                "gases": [accessed_tx.gas, other_tx.gas],
                            }
                        )

                if len(affected_txs) > 0:
                    tx.is_attack = True
                    candidate = AttackCandidate(
                        self.name,
                        {
                            "contract": contract,
                            "block_number": self.latest_block,
                        },
                        {
                            "affected_txs": affected_txs,
                        }
                    )
                    if ether_flow:
                        tx.attack_candidates.append(candidate)
                    else:
                        candidate.add_failed_reason("cause no ether flow")
                        tx.failed_attacks.append(candidate)

            self.latest_block = tx.block_number
            self.contract_accesses.clear()

        # we only consider the storage dependence in direct call
        root = [n for n, d in at.in_degree() if d == 0][0]
        if len(at.edges(root)) != 1:
            l.warning("%d direct call from root of %s", len(at.edges(root)), tx.tx_hash)

        ether_flow = False
        for e in rg.edges:
            for result_type in rg.edges[e]:
                if result_type == ResultType.ETHER_TRANSFER and rg.edges[e][result_type] > self.minimum_profit_amount[result_type]:
                    ether_flow = True

        for e in at.edges(root):
            trace = at.edges[e]
            if trace["status"] == 0 or trace["trace_type"] != "call":
                return

            called_contract = trace["to_address"]
            access = StorageAccess(
                tx.tx_hash,
                trace["from_address"],
                called_contract,
                trace["gas"],
                trace["gas_used"],
                ether_flow
            )
            self.contract_accesses[called_contract].append(access)
