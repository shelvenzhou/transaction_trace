import datetime
import decimal
import sqlite3

from ..datetime_utils import date_to_str, str_to_date, str_to_time
from .database import Database


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
        tzinfo = datetime.timezone.utc

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
sqlite3.register_adapter(list, lambda x: str(x))


class SingleTraceDatabase(Database):
    def __init__(self, db_filepath, date):
        super(SingleTraceDatabase, self).__init__(db_filepath, date)

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

    def insert_trace(self, row):
        """
        Manual database commit is needed.
        """
        self.insert(
            "traces",
            # "transaction_hash, transaction_index, from_address, to_address, value, input, output, trace_type, call_type, reward_type, gas, gas_used, subtraces, trace_address, error, status, block_timestamp, block_number, block_hash",
            "",
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?",
            row
        )

    def insert_traces(self, rows):
        """
        Manual database commit is needed.
        """
        self.batch_insert(
            "traces",
            # "transaction_hash, transaction_index, from_address, to_address, value, input, output, trace_type, call_type, reward_type, gas, gas_used, subtraces, trace_address, error, status, block_timestamp, block_number, block_hash",
            "",
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
        # columns = "rowid, *" if with_rowid else "*"
        columns = "rowid, transaction_hash, transaction_index, from_address, to_address, value, input, trace_type, call_type, trace_address, error, status, block_timestamp, block_number, block_hash" if with_rowid else "*"
        return self.read("traces", columns)

    def insert_subtrace(self, row):
        """
        Manual database commit is needed.
        """
        self.insert(
            "subtraces",
            "",
            "?, ?, ?",
            row
        )

    def read_subtraces(self, with_rowid=False):
        columns = "rowid, *" if with_rowid else "*"
        return self.read("subtraces", columns)

    def clear_subtraces(self):
        self.delete("subtraces")


class SingleBlockDatabase(Database):
    def __init__(self, db_filepath, date):
        super(SingleBlockDatabase, self).__init__(db_filepath, date)

    def create_blocks_table(self):
        self.create_table(
            table_name="blocks",
            columns='''
                timestamp TIMESTAMP NOT NULL,
                number INT NOT NULL,
                hash TEXT NOT NULL,
                parent_hash TEXT,
                nonce TEXT NOT NULL,
                sha3_uncles TEXT,
                logs_bloom TEXT,
                transactions_root TEXT,
                state_root TEXT,
                receipts_root TEXT,
                miner TEXT,
                difficulty INT,
                total_difficulty INT,
                size INT,
                extra_data TEXT,
                gas_limit INT,
                gas_used INT,
                transaction_count INT
            ''')

    def insert_block(self, row):
        self.insert(
            table="blocks",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?",
            row=row)

    def insert_blocks(self, rows):
        self.batch_insert(
            table="blocks",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?",
            rows=rows)


class SingleTransactionDatabase(Database):
    def __init__(self, db_filepath, date):
        super(SingleTransactionDatabase, self).__init__(db_filepath, date)

    def create_txs_table(self):
        self.create_table(
            table_name="transactions",
            columns='''
                hash TEXT PRIMARY KEY,
                nonce INT NOT NULL,
                transaction_index INT NOT NULL,
                from_address TEXT NOT NULL,
                to_address TEXT,
                value INT,
                gas INT,
                gas_price INT,
                input TEXT,
                receipt_cumulative_gas_used INT,
                receipt_gas_used INT,
                receipt_contract_address TEXT,
                receipt_root TEXT,
                receipt_status INT,
                block_timestamp TIMESTAMP NOT NULL,
                block_number INT NOT NULL,
                block_hash TEXT NOT NULL
            ''')

    def insert_tx(self, row):
        self.insert(
            table="transactions",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?",
            row=row)

    def insert_txs(self, rows):
        self.batch_insert(
            table="transactions",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?",
            rows=rows)


class SingleTokenTransferDatabase(Database):
    def __init__(self, db_filepath, date):
        super(SingleTokenTransferDatabase, self).__init__(db_filepath, date)

    def create_token_transfers_table(self):
        self.create_table(
            table_name="token_transfers",
            columns='''
                token_address TEXT NOT NULL,
                from_address TEXT,
                to_address TEXT,
                value TEXT,
                transaction_hash TEXT NOT NULL,
                log_index INT NOT NULL,
                block_timestamp TIMESTAMP NOT NULL,
                block_number INT NOT NULL,
                block_hash TEXT NOT NULL,
                PRIMARY KEY(transaction_hash, log_index)
            ''')

    def insert_token_transfer(self, row):
        self.insert(
            table="token_transfers",
            columns="",
            placeholders="? ,?, ?, ?, ? ,?, ?, ?, ?",
            row=row
        )

    def insert_token_transfers(self, rows):
        self.batch_insert(
            table="token_transfers",
            columns="",
            placeholders="? ,?, ?, ?, ? ,?, ?, ?, ?",
            rows=rows
        )


class SingleContractDatabase(Database):
    def __init__(self, db_filepath, date):
        super(SingleContractDatabase, self).__init__(db_filepath, date)

    def create_contracts_table(self):
        self.create_table(
            table_name="contracts",
            columns='''
                address TEXT PRIMARY KEY,
                bytecode TEXT,
                function_sighashes LIST,
                is_erc20 BOOLEAN,
                is_erc721 BOOLEAN,
                block_timestamp TIMESTAMP NOT NULL,
                block_number INT NOT NULL,
                block_hash TEXT NOT NULL
            '''
        )

    def insert_contract(self, row):
        self.insert(
            table="contracts",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?",
            row=row
        )

    def insert_contracts(self, rows):
        self.batch_insert(
            table="contracts",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?",
            rows=rows
        )

class SingleLogDatabase(Database):
    def __init__(self, db_filepath, date):
        super(SingleLogDatabase, self).__init__(db_filepath, date)

    def create_logs_table(self):
        self.create_table(
            table_name='logs',
            columns='''
                log_index INT NOT NULL,
                transaction_hash TEXT NOT NULL,
                transaction_index INT NOT NULL,
                address TEXT,
                data TEXT,
                topics TEXT,
                block_timestamp TIMESTAMP NOT NULL,
                block_number INT NOT NULL,
                block_hash TEXT NOT NULL,
                PRIMARY KEY(block_hash, log_index)
            '''
        )

    def insert_log(self, row):
        self.insert(
            table="logs",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?, ?",
            row=row
        )

    def insert_logs(self, rows):
        self.batch_insert(
            table="logs",
            columns="",
            placeholders="?, ?, ?, ?, ?, ?, ?, ?, ?",
            row=rows
        )
