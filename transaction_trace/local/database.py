import sqlite3


class Database:
    def __init__(self, db_filepath):
        self._filepath = db_filepath

        conn = sqlite3.connect(
            db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row

        self._conn = conn

    def __repr__(self):
        return "connection to %s" % self._filepath

    def commit(self):
        self._conn.commit()

    def create_table(self, table_name, columns):
        cur = self._conn.cursor()
        cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name}({columns});")

    def drop_table(self, table):
        cur = self._conn.cursor()
        cur.execute(f"DROP TABLE IF EXISTS {table};")

    def read(self, table, columns, conditions="", args=dict()):
        cur = self._conn.cursor()
        return cur.execute(f"SELECT {columns} FROM {table} {conditions}", args)

    def insert(self, table, columns, placeholders, rows):
        cur = self._conn.cursor()
        cur.execute(
            f"INSERT INTO {table}{columns} VALUES ({placeholders})", rows)

    def delete(self, table, conditions="", args=dict()):
        cur = self._conn.cursor()
        cur.execute(f"DELETE FROM {table} {conditions}", args)
