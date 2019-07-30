import logging
from collections import defaultdict

from ...local import ContractCode, EVMExecutor
from ..results import AttackCandidate, ResultType
from .checker import Checker, CheckerType

l = logging.getLogger("transaction-trace.analysis.checker.TODChecker")

evm = EVMExecutor()


class StorageAccess:

    def __init__(self, tx_hash, contract, contract_code):
        self.tx_hash = tx_hash
        self.contract = contract

        if contract_code is not None:
            deployed_code = evm.deployed_code(contract_code)
        else:
            deployed_code = "0x"
        self.deployed_code = deployed_code if deployed_code != "0x" else contract_code

        self.inputs = set()

        self.cause_ether_flow = False

        self._storage_accesses = None

    def __eq__(self, other):
        if not isinstance(other, StorageAccess):
            return False
        return self.tx_hash == other.tx_hash and self.contract == other.contract

    def storage_accesses(self):
        if self._storage_accesses is None:
            self._storage_accesses = set()
            for input_data in self.inputs:
                self._storage_accesses = self._storage_accesses.union(
                    evm.log_storage_accesses(self.deployed_code, input_data))
        return self._storage_accesses


class CachedCodeDatabase:

    def __init__(self, passwd):
        self.code_database = ContractCode(passwd=passwd)

        self.bytecodes = dict()
        l.info("preload bytecodes")
        for row in self.code_database.read("byte_code", "distinct(bytecode_hash), bytecode"):
            self.bytecodes[row[0]] = row[1]

        l.info("preload contracts' code hashes")
        self.contract_bytecode = dict()
        for row in self.code_database.read("byte_code", "address, bytecode_hash"):
            self.contract_bytecode[row[0]] = row[1]

    def read_bytecode(self, contract):
        if contract not in self.contract_bytecode:
            return None
        return self.bytecodes[self.contract_bytecode[contract]]


class TODChecker(Checker):

    def __init__(self, passwd="password"):
        super(TODChecker, self).__init__("transaction-order-dependence-checker")
        self.code_database = CachedCodeDatabase(passwd)

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
                stored_index = dict()
                affected_txs = list()
                ether_flow = False
                for accessed_tx in accessed_txs:
                    affected = False
                    affected_by = list()
                    affected_index = list()
                    for op, index in accessed_tx.storage_accesses():
                        if op == "load":
                            if index in stored_index and stored_index[index] != accessed_tx.tx_hash:
                                affected = True
                                if index not in affected_index:
                                    affected_index.append(index)
                                    affected_by.append(stored_index[index])
                        elif op == "store":
                            stored_index[index] = accessed_tx.tx_hash

                    if affected:
                        if accessed_tx.cause_ether_flow:
                            ether_flow = True

                        affected_txs.append(
                            {
                                "affected_tx": accessed_tx.tx_hash,
                                "affected_by": list(zip(affected_by, affected_index)),
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
        for e in at.edges(root):
            direct_call = e

        trace = at.edges[direct_call]
        if trace["status"] == 0 or trace["trace_type"] != "call":
            return

        called_contract = trace["to_address"]
        access = StorageAccess(tx.tx_hash, called_contract, self.code_database.read_bytecode(called_contract))
        access.inputs.add(trace["input"])
        access.cause_ether_flow = (trace["value"] > 0)
        for e in rg.edges:
            for result_type in rg.edges[e]:
                if result_type == ResultType.ETHER_TRANSFER and rg.edges[e][result_type] > self.minimum_profit_amount[result_type]:
                    ether_flow = True

        self.contract_accesses[called_contract].append(access)
