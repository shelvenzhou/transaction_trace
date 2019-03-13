import sqlite3
from local.ethereum_database import EthereumDatabase
from datetime_utils import time_to_str, date_to_str, str_to_time
from datetime import datetime, timedelta
import decimal, sys

DB_PATH = "/Users/Still/Desktop/w/db/"


class SubTraceBuilder(object):
    def __init__(self):
        self.local = None

    def load_database(self, db_path, date):
        self.local = EthereumDatabase(
            f"{db_path}raw/bigquery_ethereum_{date_to_str(date)}.sqlite3")

    def build_subtrace(self, from_time=None, to_time=None):
        if from_time == None:
            clause = ""
        else:
            clause = "where block_timestamp >= :from_time and block_timestamp < :to_time"
        rows = self.local.read_from_database(
            table="traces",
            columns="rowid, transaction_hash, trace_address",
            clause=clause,
            vals={
                "from_time": from_time,
                "to_time": to_time
            })

        trace_map = {}
        trace_count = 0
        for row in rows:
            tx_hash = row['transaction_hash']
            trace_addr = row['trace_address']
            rowid = row['rowid']
            if tx_hash not in trace_map:
                trace_map[tx_hash] = {"p_trace_addr": {}, "taddr2rid": {}}
            if trace_addr == None:
                trace_map[tx_hash]["p_trace_addr"][rowid] = None
                trace_map[tx_hash]["taddr2rid"][''] = rowid
            else:
                trace_addr_list = trace_addr.split(',')
                trace_map[tx_hash]["p_trace_addr"][rowid] = ','.join(
                    trace_addr_list[:-1])
                trace_map[tx_hash]["taddr2rid"][trace_addr] = rowid

            trace_count += 1
            sys.stdout.write(str(trace_count) + '\r')
            sys.stdout.flush()
        print(trace_count, "traces")

        tx_count = 0
        for tx_hash in trace_map:
            for trace_id in trace_map[tx_hash]["p_trace_addr"]:
                parent_trace_addr = trace_map[tx_hash]["p_trace_addr"][
                    trace_id]
                if parent_trace_addr == None:
                    parent_trace_id = None
                else:
                    parent_trace_id = trace_map[tx_hash]["taddr2rid"][
                        parent_trace_addr]
                self.local.write_into_database(
                    "subtraces", (tx_hash, trace_id, parent_trace_id),
                    "?, ?, ?", "transaction_hash, id, parent_trace_id")

            tx_count += 1
            sys.stdout.write(str(tx_count) + '\r')
            sys.stdout.flush()
        print(tx_count, "txs")

        self.local.database_commit()

    def build_subtrace_on_multidb(self, from_time, to_time):
        date = from_time.date()
        while date <= to_time.date():
            print('building subtraces on', date_to_str(date))
            self.load_database(DB_PATH, date)
            self.local.drop_index("transaction_hash_index")
            self.local.drop_index("subtraces_transaction_hash_index")
            self.local.delete_on_database("subtraces")
            self.build_subtrace()
            # self.local.database_index_create()
            date += timedelta(days=1)


def main():
    builder = SubTraceBuilder()
    from_time = datetime(2018, 10, 7, 0, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 0, 0)

    builder.build_subtrace_on_multidb(from_time, to_time)


if __name__ == "__main__":
    main()
