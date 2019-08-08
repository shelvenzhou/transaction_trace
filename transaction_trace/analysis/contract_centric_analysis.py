import logging
from collections import defaultdict

from ..basic_utils import DatetimeUtils
from ..local import ContractTransactions, ContractTokenTransactions, DatabaseName
from .checkers import CheckerType
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.ContractCentricAnalysis")


class ContractCentricAnalysis(TraceAnalysis):

    def __init__(self, db_folder, idx_db_user="contract_txs_idx", idx_db_passwd="password", idx_db="contract_txs_idx"):
        super(ContractCentricAnalysis, self).__init__(db_folder, [
            DatabaseName.TRACE_DATABASE, DatabaseName.TOKEN_TRANSFER_DATABASE])
        tx_index_db = ContractTokenTransactions(
            user=idx_db_user, passwd=idx_db_passwd, db=idx_db)
        self.database[DatabaseName.CONTRACT_TRANSACTIONS_DATABASE] = tx_index_db

        self.checkers = dict()

    def register_contract_centric_checker(self, checker):
        assert checker.checker_type == CheckerType.CONTRACT_CENTRIC, "try to register a checker of wrong type"
        checker.set_database(self.database)
        self.checkers[checker.name] = checker

    def do_analysis(self, **kwargs):
        for _, checker in self.checkers.items():
            checker.do_check(**kwargs)

    def build_contract_transactions_index(self, pre_process, column_index=False, db_cache_len=100000):
        tx_index_db = self.database[DatabaseName.CONTRACT_TRANSACTIONS_DATABASE]
        tx_index_db.create_contract_transactions_table()

        db_cache = list()

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
                db_cache.append((call_tree.tx.tx_hash,
                                 call_tree.tx.block_timestamp.date(),
                                 sensitive_contracts,
                                 True))
            if len(unsensitive_contracts) > 0:
                db_cache.append((call_tree.tx.tx_hash,
                                 call_tree.tx.block_timestamp.date(),
                                 unsensitive_contracts,
                                 False))

            if len(db_cache) > db_cache_len:
                l.info("insert data from cache to database")
                for d in db_cache:
                    tx_index_db.insert_transactions_of_contract(*d)

                tx_index_db.commit()
                db_cache.clear()

        for d in db_cache:
            tx_index_db.insert_transactions_of_contract(*d)
        tx_index_db.commit()

        if column_index:
            tx_index_db.create_contract_index()
