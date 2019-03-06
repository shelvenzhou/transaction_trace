import sqlite3


class StatisticDatabase(object):
    def __init__(self, db_filepath):
        self.db_filepath = db_filepath
        self.conn = sqlite3.connect(
            self.db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
        self.cur = self.conn.cursor()

    def __del__(self):
        self.conn.close()

    def database_create(self):
        self.cur.execute("""
            CREATE TABLE transactions(
                transaction_hash TEXT,
                subtrace_hash TEXT,
                node_addresses TEXT,
                PRIMARY KEY(transaction_hash, subtrace_hash)
            )
        """)

        self.cur.execute("""
            CREATE TABLE nodes(
                node_address TEXT,
                subtrace_hash TEXT,
                count INT,
                PRIMARY KEY(node_address, subtrace_hash)
            )
        """)

    def database_index_create(self):
        self.cur.execute("""
            CREATE INDEX transaction_hash_index on transactions(transaction_hash)
        """)
        self.cur.execute("""
            CREATE INDEX subtrace_hash_index on transactions(subtrace_hash)
        """)

        self.cur.execute("""
            CREATE INDEX node_address_index on nodes(node_address)
        """)

    def database_commit(self):
        self.conn.commit()

    def read_from_database(self, table, columns, index="", clause="", vals={}):
        cur = self.conn.cursor()
        return cur.execute(f"SELECT {columns} FROM {table} {index} {clause}",
                           vals)

    def write_into_database(self, table, vals, placeholder, columns=""):
        return self.cur.execute(
            f"INSERT INTO {table}({columns}) VALUES ({placeholder})", vals)

    def update_on_database(self, table, assign, vals, clause=""):
        return self.cur.execute(f"UPDATE {table} SET {assign} {clause}",
                                vals)

    def delete_on_database(self, table, clause="", vals={}):
        return self.cur.execute(f"DELETE FROM {table} {clause}", vals)