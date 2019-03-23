import datetime
import decimal
import logging
import os
import re
import sqlite3
import sys

from sortedcontainers import SortedList

from ..datetime_utils import date_to_str, str_to_date, str_to_time

l = logging.getLogger("transaction-trace.local.ethereum_database")


def adapt_decimal(d):
    return str(d)


def tz_aware_timestamp_adapter(val):
    datepart, timepart = val.split(b" ")
    year, month, day = map(int, datepart.split(b"-"))

    if b"+" in timepart:
        timepart, tz_offset = timepart.rsplit(b"+", 1)
        if tz_offset == b'00:00':
            tzinfo = datetime.timezone.utc
        else:
            hours, minutes = map(int, tz_offset.split(b':', 1))
            tzinfo = datetime.timezone(
                datetime.timedelta(hours=hours, minutes=minutes))
    else:
        tzinfo = None

    timepart_full = timepart.split(b".")
    hours, minutes, seconds = map(int, timepart_full[0].split(b":"))

    if len(timepart_full) == 2:
        microseconds = int('{:0<6.6}'.format(timepart_full[1].decode()))
    else:
        microseconds = 0

    val = datetime.datetime(year, month, day, hours,
                            minutes, seconds, microseconds, tzinfo)

    return val


sqlite3.register_converter('timestamp', tz_aware_timestamp_adapter)
sqlite3.register_adapter(decimal.Decimal, adapt_decimal)

class SimpleAnalysisDatabase:
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
        cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name}{columns};")

    def drop_table(self, table):
        cur = self._conn.cursor()
        cur.execute(f"DROP TABLE IF EXISTS {table};")

    def read(self, table, columns, conditions="", args=dict()):
        cur = self._conn.cursor()
        return cur.execute(f"SELECT {columns} FROM {table} {conditions}", args)

    def insert(self, table, columns, placeholders, rows):
        cur = self._conn.cursor()
        cur.execute(
            f"INSERT INTO {table}({columns}) VALUES ({placeholders})", rows)

    def delete(self, table, conditions="", args=dict()):
        cur = self._conn.cursor()
        cur.execute(f"DELETE FROM {table} {conditions}", args)

        

class SingleDatabase:
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

    def create_traces_table(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traces(
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

    def create_subtraces_table(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS subtraces(
                transaction_hash TEXT,
                trace_id INT PRIMARY KEY,
                parent_trace_id INT
            );
        """)

    def index_traces(self):
        """
        This should ONLY be called after all data is crawled.
        """
        cur = self._conn.cursor()
        cur.execute(
            "CREATE INDEX IF NOT EXISTS transaction_hash_index ON traces(transaction_hash);")

    def index_subtraces(self):
        cur = self._conn.cursor()
        cur.execute(
            "CREATE INDEX IF NOT EXISTS subtraces_transaction_hash_index ON subtraces(transaction_hash);")

    def drop_index(self, index):
        cur = self._conn.cursor()
        cur.execute(f"DROP INDEX IF EXISTS {index};")

    def drop_table(self, table):
        cur = self._conn.cursor()
        cur.execute(f"DROP TABLE IF EXISTS {table};")

    def read(self, table, columns, conditions="", args=dict()):
        cur = self._conn.cursor()
        return cur.execute(f"SELECT {columns} FROM {table} {conditions}", args)

    def insert(self, table, columns, placeholders, rows):
        cur = self._conn.cursor()
        cur.execute(
            f"INSERT INTO {table}({columns}) VALUES ({placeholders})", rows)

    def delete(self, table, conditions="", args=dict()):
        cur = self._conn.cursor()
        cur.execute(f"DELETE FROM {table} {conditions}", args)

    def insert_traces(self, rows):
        """
        Manual database commit is needed.
        """
        self.insert(
            "traces",
            "transaction_hash, transaction_index, from_address, to_address, value, input, output, trace_type, call_type, reward_type, gas, gas_used, subtraces, trace_address, error, status, block_timestamp, block_number, block_hash",
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?",
            rows
        )

    def read_traces(self, with_rowid=False):
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
        columns = "rowid, *" if with_rowid else "*"
        return self.read("traces", columns)

    def insert_subtrace(self, row):
        """
        Manual database commit is needed.
        """
        self.insert(
            "subtraces",
            "transaction_hash, trace_id, parent_trace_id",
            "?, ?, ?",
            row
        )

    def read_subtraces(self, with_rowid=False):
        columns = "rowid, *" if with_rowid else "*"
        return self.read("subtraces", columns)

    def clear_subtraces(self):
        self.delete("subtraces")


def data_time_range(db_folder):
    prog = re.compile(r"bigquery_ethereum_(\d{4}\-\d{2}\-\d{2})\.sqlite3")
    dates = SortedList(key=lambda x: str_to_date(x))
    for file in os.listdir(db_folder):
        m = prog.match(file)
        if m is not None:
            dates.add(m[1])

    return dates


def db_filename(date):
    return "bigquery_ethereum_%s.sqlite3" % date


class EthereumDatabase:

    def __init__(self, db_folder):
        self._db_folder = db_folder
        self._table_name = "traces"

        self._data_time_range = data_time_range(db_folder)
        self._connection_cache = dict()

    def __repr__(self):
        return "database manager of %s" % self._db_folder

    @property
    def table_name(self):
        return self._table_name

    @property
    def time_range(self):
        return self._data_time_range

    def get_connection(self, date):
        if isinstance(date, datetime.datetime):
            date = date_to_str(date)

        if date not in self._data_time_range:
            return None

        if date in self._connection_cache:
            return self._connection_cache[date]

        db_filepath = os.path.join(self._db_folder, db_filename(date))
        db = SingleDatabase(db_filepath)
        self._connection_cache[date] = db
        return db

    def get_connections(self, from_time, to_time):
        '''
        Time range can be datetime.datetime or string.
        '''
        if isinstance(from_time, datetime.datetime):
            from_time = date_to_str(from_time)
        if isinstance(to_time, datetime.datetime):
            to_time = date_to_str(to_time)

        for i in range(self._data_time_range.bisect_left(from_time), self._data_time_range.bisect_right(to_time)):
            date = self._data_time_range[i]
            yield self.get_connection(date)

    def read_traces(self, from_time, to_time):
        '''
        Time range can be datetime.datetime or string.
        '''
        for db in self.get_connections(from_time, to_time):
            for row in db.read_traces():
                yield row
