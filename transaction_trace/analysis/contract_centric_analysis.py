import logging
from collections import defaultdict

from ..local import ContractTransactions
from .checkers import CheckerType

l = logging.getLogger("transaction-trace.analysis.ContractCentricAnalysis")


class ContractCentricAnalysis:

    def __init__(self):
        # self.tx_index_db = ContractTransactions(tx_index_filepath)

        self.checkers = dict()

    def register_contract_centric_checker(self, checker):
        assert checker.checker_type == CheckerType.CONTRACT_CENTRIC, "try to register a checker of wrong type"
        self.checkers[checker.name] = checker

    def build_contract_transactions_index(self, pre_process, column_index=False):
        # self.tx_index_db.create_contract_transactions_table()
        contract_txs_index = dict()

        for call_tree, result_graph in pre_process.preprocess():
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

            l.debug("save index of %s", result_graph.tx.tx_hash)
            # self.tx_index_db.insert_transactions_of_contract(result_graph.tx.tx_hash,
            #                                                  result_graph.tx.block_timestamp,
            #                                                  contracts)
            # self.tx_index_db.commit()

            for c in sensitive_contracts:
                contract_txs_index[c] = (call_tree.tx.block_timestamp, call_tree.tx.tx_hash, True)
            for c in (normal_contracts - sensitive_contracts):
                contract_txs_index[c] = (call_tree.tx.block_timestamp, call_tree.tx.tx_hash, False)

        # if column_index:
        #     self.tx_index_db.create_contract_index()
        import IPython
        IPython.embed()
