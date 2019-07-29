import logging
from collections import defaultdict

from ...local import ContractCode, EVMExecutor
from ..results import AttackCandidate
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
        self.cache = dict()

    def read_bytecode(self, contract):
        if contract not in self.cache:
            code = list(self.code_database.read_bytecode(contract))
            if len(code) == 1:
                self.cache[contract] = code[0][0]
            else:
                l.debug("%d byte code for %s", len(code), contract)
                self.cache[contract] = None
        return self.cache[contract]


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

        if self.latest_block is None:
            self.latest_block = tx.block_number
        if tx.block_number != self.latest_block:
            # check whether TOD happens in previous block
            for contract, accessed_txs in self.contract_accesses.items():
                if len(accessed_txs) < 2:
                    continue

                # cross-tx read after write is regarded as TOD
                stored_index = dict()
                affected_txs = list()
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
                        affected_txs.append(
                            {
                                "affected_tx": accessed_tx.tx_hash,
                                "affected_by": list(zip(affected_by, affected_index)),
                            }
                        )

                if len(affected_txs) > 0:
                    tx.is_attack = True
                    tx.attack_candidates.append(
                        AttackCandidate(
                            self.name,
                            {
                                "contract": contract,
                                "block_number": self.latest_block,
                            },
                            {
                                "affected_txs": affected_txs,
                            }
                        )
                    )

            self.latest_block = tx.block_number
            self.contract_accesses.clear()

        accesses = dict()
        for e in at.edges:
            trace = at.edges[e]
            if trace["status"] == 0 or trace["trace_type"] != "call":
                continue

            called_contract = trace["to_address"]
            if called_contract not in accesses:
                accesses[called_contract] = StorageAccess(
                    tx.tx_hash, called_contract, self.code_database.read_bytecode(called_contract))
            accesses[called_contract].inputs.add(trace["input"])

        for contract, access_log in accesses.items():
            self.contract_accesses[contract].append(access_log)
