from google.cloud import bigquery
import sqlite3
from datetime import datetime
import logging

l = logging.getLogger("bigquery-ethereum-crawler.ethereum_database")

DB_FILEPATH = "bigquery_ethereum_traces.sqlite3"

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"

SCHEME = {
    'transaction_hash':     "STRING",
    'transaction_index':    "INTEGER",
    'from_address':         "STRING",
    'to_address':           "STRING",
    'value':                "INTEGER",
    'input':                "STRING",
    'output':               "STRING",
    'trace_type':           "STRING",
    'call_type':            "STRING",
    'reward_type':          "STRING",
    'gas':                  "INTEGER",
    'gas_used':             "INTEGER",
    'subtraces':            "INTEGER",
    'trace_address':        "STRING",
    'error':                "STRING",
    'status':               "INTEGER",
    'block_timestamp':      "TIMESTAM",
    'block_number':         "INTEGER",
    'block_hash':           "STRING",
}


class EthereumDatabase(object):

    def __init__(self, db_filepath=DB_FILEPATH):
        self.db_filepath = db_filepath
        self.conn = sqlite3.connect(self.db_filepath)
        self.conn.row_factory = sqlite3.Row

        self.client = bigquery.Client()

    def __del__(self):
        self.conn.close()

    @staticmethod
    def time_to_str(timestamp):
        return timestamp.strftime(DATETIME_FORMAT)

    @staticmethod
    def str_to_time(string):
        return datetime.strptime(string, DATETIME_FORMAT)

    def get_ethereum_data(self, from_time, to_time):
        query_str = (
            f'SELECT * FROM `bigquery-public-data.ethereum_blockchain.traces` '
            f'WHERE block_timestamp >= "{time_to_str(from_time)}" AND block_timestamp < "{time_to_str(to_time)}" AND from_address IS NOT NULL'
        )

        return self.client.query(query_str).result()


    def insert_to_database(self, rows):
        with self.conn.cursor() as c:
            c.executemany("INSERT INTO traces(transaction_hash, transaction_index, from_address, to_address, value, input, output, trace_type, call_type, reward_type, gas, gas_used, subtraces, trace_address, error, status, block_timestamp, block_number, block_hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    def read_from_database(self):
        '''
            'transaction_hash':     STRING,     NULLABLE
            'transaction_index':    INTEGER,    NULLABLE
            'from_address':         STRING,     NULLABLE
            'to_address':           STRING,     NULLABLE
            'value':                INTEGER,    NULLABLE
            'input':                STRING,     NULLABLE
            'output':               STRING,     NULLABLE
            'trace_type':           STRING,     REQUIRED
            'call_type':            STRING,     NULLABLE
            'reward_type':          STRING,     NULLABLE
            'gas':                  INTEGER,    NULLABLE
            'gas_used':             INTEGER,    NULLABLE
            'subtraces':            INTEGER,    NULLABLE
            'trace_address':        STRING,     NULLABLE
            'error':                STRING,     NULLABLE
            'status':               INTEGER,    NULLABLE
            'block_timestamp':      TIMESTAMP,  REQUIRED
            'block_number':         INTEGER,    REQUIRED
            'block_hash':           STRING,     REQUIRED
        '''
        pass
