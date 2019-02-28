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
                transaction_hash TEXT PRIMARY KEY,
                nodes_address TEXT,
                trace_hash TEXT
            )
        """)

        self.cur.execute("""
            CREATE TABLE nodes(
                node_address TEXT,
                hash TEXT,
                count INT,
                PRIMARY KEY(node_address, hash)
            )
        """)

    def database_index_create(self):
        self.cur.execute("""
            CREATE INDEX transaction_hash_index on transactions(transaction_hash)
        """)

        self.cur.execute("""
            CREATE INDEX node_address_index on nodes(node_address)
        """)

    def database_commit(self):
        self.conn.commit()

    def read_from_database(self, table, columns, index="", clause="", vals={}):
        cur = self.conn.cursor()
        return cur.execute(f"SELECT {columns} FROM {table} {index} {clause}", vals)

    def write_into_database(self, table, vals, placeholder, columns=""):
        return self.cur.execute(
            f"INSERT INTO {table}({columns}) VALUES ({placeholder})", vals)

    def delete_on_database(self, table, clause="", vals={}):
        return self.cur.execute(f"DELETE FROM {table} {clause}", vals)

    def database_insert(self, tx_attr, node_attr, tx2hash):
        for tx in tx_attr:
            nodes_address = list(tx_attr[tx].keys())
            self.cur.execute(
                """
                INSERT INTO transactions(transaction_hash, nodes_address)
                VALUES(?, ?);
            """, (tx, str(nodes_address)))

        for tx in tx2hash:
            self.cur.execute(
                """
                UPDATE transactions SET trace_hash = :trace_hash WHERE transaction_hash = :tx_hash
            """, {
                    "trace_hash": tx2hash[tx],
                    "tx_hash": tx
                })

        for node in node_attr:
            for h in node_attr[node]:
                re = self.cur.execute(
                    """
                    SELECT count from nodes WHERE node_address = :node AND hash = :hash
                """, {
                        "node": node,
                        "hash": h
                    }).fetchall()
                if len(re) == 0:
                    self.cur.execute(
                        """
                        INSERT INTO nodes(node_address, hash, count)
                        VALUES(?, ?, ?)
                    """, (node, h, node_attr[node][h]))
                else:
                    self.cur.execute(
                        """
                        UPDATE nodes SET count = :count WHERE node_address = :node AND hash = :hash
                    """, {
                            "count": re[0][0] + node_attr[node][h],
                            "node": node,
                            "hash": h
                        })