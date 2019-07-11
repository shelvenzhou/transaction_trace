from .database import Database


class ContractCode(Database):
    key_order = ['ContractAddress', 'SourceCode', 'ABI', 'ContractName', 'CompilerVersion',
                 'OptimizationUsed', 'Runs', 'ConstructorArguments', 'Library', 'SwarmSource']

    def __init__(self, db_filepath, date):
        super(ContractCode, self).__init__(db_filepath, date)

    def create_contracts_table(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS source_code(
                BytecodeHash TEXT PRIMARY KEY,
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contract_bytecode_hash(
                ContractAddress TEXT PRIMARY KEY,
                BytecodeHash TEXT
            )
        """)

    def update_source_code(self, bytecode_hash, row):
        self.delete("source_code", "WHERE BytecodeHash=?", (bytecode_hash,))
        self.insert_source_code(row)

    def insert_source_code(self, row):
        self.insert("source_code", "", "?, ?, ?, ?, ?, ?, ?, ?, ?, ?", row)

    def read_source_code(self, bytecode_hash):
        return self.read("source_code", "*", "WHERE BytecodeHash=?", (bytecode_hash,))

    def insert_contract_bytecode_hash(self, row):
        self.insert("contract_bytecode_hash", "", "?, ?", row)

    def read_contract_bytecode_hash(self, addr):
        return self.read("contract_bytecode_hash", "*", "WHERE ContractAddress=?", (addr,))
