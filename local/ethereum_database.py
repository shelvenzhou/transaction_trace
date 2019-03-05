import sqlite3
import decimal
import logging
import sys
import datetime

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


class EthereumDatabase(object):

    def __init__(self, db_filepath):
        self._db_filepath = db_filepath
        self._table_name = "traces"

        self._conn = sqlite3.connect(
            self._db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
        self._conn.row_factory = sqlite3.Row

    def __del__(self):
        self._conn.close()

    @property
    def table_name(self):
        return self._table_name

    def database_create(self):
        with self._conn.cursor() as cur:
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

    def database_index_create(self):
        """
        This should ONLY be called after all data is crawled.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "CREATE INDEX transaction_hash_index ON traces(transaction_hash);")

            cur.execute(
                "CREATE INDEX subtraces_transaction_hash_index ON subtraces(transaction_hash);")

            self.database_commit()

    def database_insert(self, rows, show_progress=False):
        trace_count = 0

        with self._conn.cursor() as cur:
            for row in rows:
                try:
                    cur.execute("""
                        INSERT INTO traces(transaction_hash, transaction_index, from_address, to_address, value, input, output, trace_type, call_type, reward_type, gas, gas_used, subtraces, trace_address, error, status, block_timestamp, block_number, block_hash)
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

    def database_commit(self):
        self._conn.commit()

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
