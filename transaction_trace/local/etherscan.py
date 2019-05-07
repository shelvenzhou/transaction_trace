import json
import sqlite3

from aioetherscan import Client

from .database import Database


class Etherscan(Database):
    key_order = ['ContractAddress', 'SourceCode', 'ABI', 'ContractName', 'CompilerVersion',
                 'OptimizationUsed', 'Runs', 'ConstructorArguments', 'Library', 'SwarmSource']

    def __init__(self, api_key_filepath, db_filepath, date):
        super(Etherscan, self).__init__(db_filepath, date)

        with open(api_key_filepath, 'r') as key_file:
            key = json.loads(key_file.read())['key']

        self.client = Client(key)

    def __del__(self):
        self.client.close()

    def create_contracts_table(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contracts(
                ContractAddress TEXT PRIMARY KEY,
                SourceCode TEXT,
                ABI TEXT,
                ContractName TEXT,
                CompilerVersion TEXT,
                OptimizationUsed TEXT,
                Runs TEXT,
                ConstructorArguments TEXT,
                Library TEXT,
                SwarmSource TEXT
            );
        """)

    async def insert_contract(self, row):
        try:
            self.insert("contracts", "", "?, ?, ?, ?, ?, ?, ?, ?, ?, ?", row)
        except sqlite3.Error as e:
            print(e)

        self.commit()

    def read_contract(self, addr):
        return self.read("contracts", "*", "WHERE ContractAddress=?", (addr,))

    async def get_contract_info(self, addr):
        try:
            contract = (await self.client.contract.contract_source_code(addr))[0]
        except Exception as e:
            print(e)
            return
        contract['ContractAddress'] = addr

        await self.insert_contract([contract[x] for x in Etherscan.key_order])
