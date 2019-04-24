import json

from etherscan.contracts import Contract

from .database import Database


class Etherscan(Database):
    key_order = ['ContractAddress', 'SourceCode', 'ABI', 'ContractName', 'CompilerVersion',
                 'OptimizationUsed', 'Runs', 'ConstructorArguments', 'Library', 'SwarmSource']

    def __init__(self, api_key_filepath, db_filepath, date):
        super(Etherscan, self).__init__(db_filepath, date)

        with open(api_key_filepath, 'r') as key_file:
            self.key = json.loads(key_file.read())['key']

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

    def insert_contract(self, row):
        self.insert("contracts", "", "?, ?, ?, ?, ?, ?, ?, ?, ?, ?", row)

    def read_contract(self, addr):
        return self.read("contracts", "*", "WHERE ContractAddress=?", (addr,))

    def get_contract_info(self, addr):
        for local_record in self.read_contract(addr):
            return local_record

        contract = Contract(address=addr, api_key=self.key).get_sourcecode()[0]
        contract['ContractAddress'] = addr

        self.insert_contract([contract[x] for x in Etherscan.key_order])
        self.commit()

        return contract
