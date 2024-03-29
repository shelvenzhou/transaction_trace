import sqlite3
import MySQLdb


class Database:
    def __init__(self, db_filepath, date, inner_db="sqlite3", **args):
        self._filepath = db_filepath
        self._date = date
        self.inner_db = inner_db

        if inner_db == "sqlite3":
            conn = sqlite3.connect(
                db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
            conn.row_factory = sqlite3.Row
        elif inner_db == "mysql":
            conn = MySQLdb.connect(**args)

        self._conn = conn

    def __repr__(self):
        return "connection to %s" % self._filepath

    @property
    def date(self):
        return self._date

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
        cur.execute(f"SELECT {columns} FROM {table} {conditions}", args)
        return cur

    def insert(self, table, columns, placeholders, row):
        cur = self._conn.cursor()
        cur.execute(
            f"INSERT INTO {table}{columns} VALUES ({placeholders})", row)

    def batch_insert(self, table, columns, placeholders, rows):
        cur = self._conn.cursor()
        cur.executemany(
            f"INSERT INTO {table}{columns} VALUES ({placeholders})", rows)

    def delete(self, table, conditions="", args=dict()):
        cur = self._conn.cursor()
        cur.execute(f"DELETE FROM {table} {conditions}", args)
