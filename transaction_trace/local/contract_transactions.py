from collections import defaultdict

from ..datetime_utils import date_to_str
from .database import Database


class ContractTransactions(Database):

    def __init__(self, db_filepath, user="contract_txs_idx", passwd="password", db="contract_txs_idx"):
        super(ContractTransactions, self).__init__(db_filepath, "", inner_db="mysql",
                                                   user=user,
                                                   passwd=passwd,
                                                   db=db)

    def __repr__(self):
        return "contract-centric transaction index"

    def create_contract_transactions_table(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contract_transactions(
                contract TEXT,
                transaction_date TIMESTAMP,
                transaction_hash TEXT,
                sensitive_result BOOLEAN
            );
        """)

    def create_contract_index(self):
        cur = self._conn.cursor()
        cur.execute("""
            ALTER TABLE contract_transactions ADD INDEX contract_index (contract(42))
        """)

    def insert_transactions_of_contract(self, tx_hash, date, contracts, sensitive):
        rows = [(contract, date, tx_hash, sensitive) for contract in contracts]
        self.batch_insert("contract_transactions", "(contract, transaction_date, transaction_hash, sensitive_result)", "%s, %s, %s, %s", rows)

    def read_transactions_of_contract(self, contract):
        rows = self.read("contract_transactions", "transaction_date, transaction_hash", "WHERE contract=%s", (contract,))
        txs = defaultdict(list)
        for row in rows:
            txs[date_to_str(row[0])].append(row[1])
        return txs
