from collections import defaultdict

from ..datetime_utils import date_to_str
from .database import Database


class ContractTransactions(Database):

    def __init__(self, db_filepath):
        super(ContractTransactions, self).__init__(db_filepath, "")

    def __repr__(self):
        return "contract-centric transaction index"

    def create_contract_transactions_table(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contract_transactions(
                contract TEXT,
                transaction_date TIMESTAMP,
                transaction_hash TEXT
            );
        """)

    def create_contract_index(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE INDEX IF NO EXISTS contract_index ON contract_transactions(
                contract
            )
        """)

    def insert_transactions_of_contract(self, tx_hash, date, contracts):
        rows = [(contract, date, tx_hash) for contract in contracts]
        self.batch_insert("contract_transactions", "contract, transaction_date, transaction_hash", "?, ?, ?", rows)

    def read_transactions_of_contract(self, contract):
        rows = self.read("contract_transactions", "transaction_date, transaction_hash", "WHERE contract=?", (contract,))
        txs = defaultdict(list)
        for row in rows:
            txs[date_to_str(row["transaction_date"])].append(row["transaction_hash"])
        return txs
