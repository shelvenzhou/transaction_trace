import sqlite3
from .database import Database


class ExtractantDatabase(Database):
    def __init__(self, db_filepath):
        super(ExtractantDatabase, self).__init__(db_filepath)

    def create_func2hash_table(self):
        self.create_table(table_name="func2hash",
                          columns="func_name TEXT PRIMARY KEY, func_hash TEXT, func_type TEXT")
