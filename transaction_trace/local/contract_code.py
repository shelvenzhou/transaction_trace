from .database import Database


class ContractCode(Database):

    def __init__(self, user="contract_code", passwd="password", db="contract_code"):
        super(ContractCode, self).__init__("mysql-contract_code", "", inner_db="mysql",
                                           user=user,
                                           passwd=passwd,
                                           db=db,
                                           charset="utf8mb4")

    def create_tables(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `byte_code`(
                `address` char(42) PRIMARY KEY,
                `bytecode` TEXT,
                `bytecode_hash` char(64),
                `function_sighashes` TEXT,
                `is_erc20` BOOLEAN,
                `is_erc721` BOOLEAN,
                `block_timestamp` TIMESTAMP NOT NULL,
                `block_number` INT NOT NULL,
                `block_hash` char(66) NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `source_code`(
                `bytecode_hash` char(64) PRIMARY KEY,
                `source_code` LONGTEXT,
                `abi` TEXT,
                `contract_name` TEXT,
                `compiler_version` TEXT,
                `optimization_used` TEXT,
                `runs` TEXT,
                `constructor_arguments` TEXT,
                `library` TEXT,
                `swarm_source` TEXT
            );
        """)

    def insert_byte_code(self, row):
        self.insert("byte_code", "", "%s, %s, %s, %s, %s, %s, %s, %s, %s", row)

    def insert_source_code(self, row):
        self.insert("source_code", "", "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s", row)

    def create_bytecode_index(self):
        cur = self._conn.cursor()
        cur.execute("CREATE INDEX `bytecode_hash_index` ON `byte_code`(`bytecode_hash`);")

    def create_source_code_index(self):
        cur = self._conn.cursor()
        cur.execute("CREATE FULLTEXT INDEX `source_code_index` ON `source_code`(`source_code`);")

    def search_keyword_in_source(self, keyword, columns="address", case_sensitive=True):
        if case_sensitive:
            condition = "WHERE source_code LIKE \"%%%s%%\""
        else:
            keyword = keyword.lower()
            condition = "WHERE LOWER(source_code) LIKE \"%%%s%%\""

        return self.read(
            "byte_code INNER JOIN source_code ON byte_code.bytecode_hash = source_code.bytecode_hash",
            columns,
            condition,
            (keyword,)
        )
