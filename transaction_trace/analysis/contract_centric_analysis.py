import logging
from collections import defaultdict

from ..local import ContractTransactions
from .checkers import CheckerType

l = logging.getLogger("transaction-trace.analysis.ContractCentricAnalysis")


class ContractCentricAnalysis:

    def __init__(self, idx_db_user="contract_txs_idx", idx_db_passwd="password", idx_db="contract_txs_idx"):
        self.tx_index_db = ContractTransactions("", user=idx_db_user, passwd=idx_db_passwd, db=idx_db)

        self.checkers = dict()

    def register_contract_centric_checker(self, checker):
        assert checker.checker_type == CheckerType.CONTRACT_CENTRIC, "try to register a checker of wrong type"
        self.checkers[checker.name] = checker

    def build_contract_transactions_index(self, pre_process, column_index=False):
        self.tx_index_db.create_contract_transactions_table()

        for call_tree, result_graph in pre_process.preprocess():
            if call_tree is None:
                continue

            normal_contracts = set()
            for e in call_tree.t.edges:
                trace = call_tree.t.edges[e]
                if trace['status'] == 0:
                    continue

                normal_contracts.add(trace['from_address'])
                normal_contracts.add(trace['to_address'])

            sensitive_contracts = set()
            for contract in result_graph.g.nodes:
                sensitive_contracts.add(contract)

            unsensitive_contracts = normal_contracts - sensitive_contracts

            l.debug("save index of %s", call_tree.tx.tx_hash)
            if len(sensitive_contracts) > 0:
                self.tx_index_db.insert_transactions_of_contract(call_tree.tx.tx_hash,
                                                                call_tree.tx.block_timestamp.date(),
                                                                sensitive_contracts,
                                                                True)
            if len(unsensitive_contracts) > 0:
                self.tx_index_db.insert_transactions_of_contract(call_tree.tx.tx_hash,
                                                                call_tree.tx.block_timestamp.date(),
                                                                unsensitive_contracts,
                                                                False)
            self.tx_index_db.commit()

        if column_index:
            self.tx_index_db.create_contract_index()
        import IPython
        IPython.embed()
