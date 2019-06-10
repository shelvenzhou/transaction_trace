from .database import Database


class ContractCode(Database):
    key_order = ['ContractAddress', 'SourceCode', 'ABI', 'ContractName', 'CompilerVersion',
                 'OptimizationUsed', 'Runs', 'ConstructorArguments', 'Library', 'SwarmSource']

    def __init__(self, db_filepath, date):
        super(ContractCode, self).__init__(db_filepath, date)

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
