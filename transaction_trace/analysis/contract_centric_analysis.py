import logging
from collections import defaultdict

from ..local import ContractTransactions
from .checkers import CheckerType

l = logging.getLogger("transaction-trace.analysis.ContractCentricAnalysis")


class ContractCentricAnalysis:

    def __init__(self, tx_index_filepath):
        self.tx_index_db = ContractTransactions(tx_index_filepath)

        self.checkers = dict()

    def register_contract_centric_checker(self, checker):
        assert checker.checker_type == CheckerType.CONTRACT_CENTRIC, "try to register a checker of wrong type"
        self.checkers[checker.name] = checker

    def build_contract_transactions_index(self, pre_process, column_index=False):
        self.tx_index_db.create_contract_transactions_table()

        for _, result_graph in pre_process.preprocess():
            if result_graph is None or len(result_graph.g.nodes) == 0:
                continue

            contracts = set()
            for contract in result_graph.g.nodes:
                contracts.add(contract)

            self.tx_index_db.insert_transactions_of_contract(result_graph.tx.tx_hash,
                                                             result_graph.tx.block_timestamp,
                                                             contracts)
            self.tx_index_db.commit()

        if column_index:
            self.tx_index_db.create_contract_index()
