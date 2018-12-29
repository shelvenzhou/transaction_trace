import sqlite3
from datetime import datetime
import decimal
import logging

l = logging.getLogger("bigquery-ethereum-crawler.ethereum_database")

DB_FILEPATH = "bigquery_ethereum.sqlite3"

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def time_to_str(t):
    return t.strftime(DATETIME_FORMAT)


def str_to_time(s):
    return datetime.strptime(s, DATETIME_FORMAT)


def adapt_decimal(d):
    return str(d)


def convert_decimal(s):
    return decimal.Decimal(s)


sqlite3.register_adapter(decimal.Decimal, adapt_decimal)
sqlite3.register_converter("DECIMAL", convert_decimal)


class EthereumDatabase(object):

    def __init__(self, db_filepath=DB_FILEPATH):
        self.db_filepath = db_filepath
        self.conn = sqlite3.connect(
            self.db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()

    def __del__(self):
        self.conn.close()

    def database_create(self):
        self.cur.execute("""
            CREATE TABLE traces(
                transaction_hash TEXT,
                transaction_index INT,
                from_address TEXT,
                to_address TEXT,
                value DECIMAL,
                input TEXT,
                output TEXT,
                trace_type TEXT NOT NULL,
                call_type TEXT,
                reward_type TEXT,
                gas INT,
                gas_used INT,
                subtraces INT,
                trace_address TEXT,
                error TEXT,
                status INT,
                block_timestamp TIMESTAMP NOT NULL,
                block_number INT NOT NULL,
                block_hash STRING NOT NULL
            );
            """)

        self.database_commit()

    def database_insert(self, rows):
        self.cur.executemany("""
            INSERT INTO traces(transaction_hash, transaction_index, from_address, to_address, value, input, output, trace_type, call_type, reward_type, gas, gas_used, subtraces, trace_address, error, status, block_timestamp, block_number, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, rows)

    def database_commit(self):
        self.conn.commit()

    def read_from_database(self):
        '''
            'transaction_hash':     STRING,     NULLABLE
            'transaction_index':    INTEGER,    NULLABLE
            'from_address':         STRING,     NULLABLE
            'to_address':           STRING,     NULLABLE
            'value':                DECIMAL,    NULLABLE
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
