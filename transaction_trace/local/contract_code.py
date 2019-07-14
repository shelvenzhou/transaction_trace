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
                `block_hash` char(66) NOT NULL,
                INDEX `bytecode_hash_index` (`bytecode_hash`)
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
