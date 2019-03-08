import datetime
import decimal
import logging
import os
import re
import sqlite3
import sys

from sortedcontainers import SortedList

from ..datetime_utils import date_to_str, str_to_date

l = logging.getLogger("bigquery-ethereum-crawler.local.ethereum_database")


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


class SingleDatabase:
    def __init__(self, db_filepath):
        conn = sqlite3.connect(
            db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row

        self._conn = conn

    def create_tables(self):
        cur = self._conn.cursor()
        cur.execute("""
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
        cur.execute("""
            CREATE TABLE subtraces(
                transaction_hash TEXT,
                id INT PRIMARY KEY,
                parent_trace_id INT
            );
        """)

    def create_index(self):
        """
        This should ONLY be called after all data is crawled.
        """
        cur = self._conn.cursor()
        cur.execute(
            "CREATE INDEX transaction_hash_index ON traces(transaction_hash);")

        cur.execute(
            "CREATE INDEX subtraces_transaction_hash_index ON subtraces(transaction_hash);")

        self._conn.commit()

    def insert(self, rows, show_progress=False):
        """
        Manual database commit is needed.
        """
        trace_count = 0

        cur = self._conn.cursor()
        for row in rows:
            try:
                cur.execute("""
                    INSERT INTO traces(
                        transaction_hash, transaction_index,
                        from_address, to_address,
                        value,
                        input, output,
                        trace_type,
                        call_type,
                        reward_type,
                        gas, gas_used,
                        subtraces, trace_address,
                        error,
                        status,
                        block_timestamp, block_number, block_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, row)
                trace_count += 1
            except sqlite3.Error as e:
                l.error("database insertion failed with error %s", e)
                return trace_count

            if show_progress:
                sys.stdout.write(str(trace_count) + '\r')
                sys.stdout.flush()

        return trace_count

    def commit(self):
        self._conn.commit()

    def read(self):
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
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM traces")
        for row in cur:
            yield row


def data_time_ranges(db_folder):
    prog = re.compile(r"bigquery_ethereum_(\d{4}\-\d{2}\-\d{2})\.sqlite3")
    dates = SortedList(key=lambda x: str_to_date(x))
    for file in os.listdir(db_folder):
        m = prog.match(file)
        if m is not None:
            dates.add(m[1])

    return dates


def db_filename(date):
    return "bigquery_ethereum_%s.sqlite3" % date


class EthereumDatabase(object):

    def __init__(self, db_folder):
        self._db_folder = db_folder
        self._table_name = "traces"

        self._data_time_ranges = data_time_ranges(db_folder)

    @property
    def table_name(self):
        return self._table_name

    def read(self, from_time, to_time):
        '''
        Time range can be datetime.datetime or string.
        '''
        if isinstance(from_time, datetime.datetime):
            from_time = date_to_str(from_time)
        if isinstance(to_time, datetime.datetime):
            to_time = date_to_str(to_time)

        for i in range(self._data_time_ranges.bisect_left(from_time), self._data_time_ranges.bisect_right(to_time)):
            db_filepath = os.path.join(self._db_folder, db_filename(self._data_time_ranges[i]))
            l.info("read from %s", db_filepath)

            db = SingleDatabase(db_filepath)
            for row in db.read():
                yield row
