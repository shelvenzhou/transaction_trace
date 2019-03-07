import sqlite3
from local.ethereum_database import EthereumDatabase
from datetime_utils import time_to_str, date_to_str, str_to_time
from datetime import datetime, timedelta
import decimal, sys

DB_PATH = "/Users/Still/Desktop/w/db/"


class SubTrace(object):
    def __init__(self,
                 txhash=None,
                 id=None,
                 level=None,
                 seq=None,
                 parent_level=None,
                 parent_seq=None):
        self.txhash = txhash
        self.id = id
        self.parent_id = None
        self.level = level
        self.seq = seq
        self.parent_level = parent_level
        self.parent_seq = parent_seq

    def update_parent_id(self, parent_id):
        self.parent_id = parent_id


class SubTraceBuilder(object):
    def __init__(self):
        self.local = None

    def load_database(self, db_path, date):
        self.local = EthereumDatabase(
            f"{db_path}raw/bigquery_ethereum_{date_to_str(date)}.sqlite3")

    def build_subtrace(self, from_time=None, to_time=None):
        traceoftxs = {}
        # re = self.query_db(from_time, to_time)
        if from_time == None:
            clause = ""
        else:
            clause = "where block_timestamp >= :from_time and block_timestamp < :to_time"
        re = self.local.read_from_database(
            table="traces",
            columns="rowid, *",
            clause=clause,
            vals={
                "from_time": from_time,
                "to_time": to_time
            })

        try:
            trace_count = 0
            for row in re:
                if row['trace_address'] != None:
                    trace_addr = row['trace_address'].split(',')
                    if len(trace_addr) == 1:
                        parent_level = 0
                        parent_seq = 0
                    else:
                        parent_level = len(trace_addr) - 1
                        parent_seq = int(trace_addr[-2])
                    st = SubTrace(
                        txhash=row['transaction_hash'],
                        id=row['rowid'],
                        level=len(trace_addr),
                        seq=int(trace_addr[-1]),
                        parent_level=parent_level,
                        parent_seq=parent_seq)
                else:
                    st = SubTrace(
                        txhash=row['transaction_hash'],
                        id=row['rowid'],
                        level=0,
                        seq=0)

                txhash = row['transaction_hash']
                if txhash in traceoftxs.keys():
                    traceoftxs[txhash]['traces'].append(st)
                    if st.level in traceoftxs[txhash]['trace_map'].keys():
                        traceoftxs[txhash]['trace_map'][st.level][
                            st.seq] = row['rowid']
                    else:
                        traceoftxs[txhash]['trace_map'][st.level] = {
                            st.seq: row['rowid']
                        }
                else:
                    traces = []
                    traces.append(st)
                    trace_map = {}
                    trace_map[st.level] = {st.seq: row['rowid']}
                    traceoftxs[txhash] = {
                        'traces': traces,
                        'trace_map': trace_map
                    }

                trace_count += 1
                sys.stdout.write(str(trace_count) + '\r')
                sys.stdout.flush()
            print(trace_count, "traces")
        except sqlite3.DatabaseError as e:
            error = time_to_str(from_time) + " " + time_to_str(
                to_time) + " " + str(e)
            print(error)
            with open("logs/database_error", 'a+') as f:
                f.write(error)
            return

        tx_count = 0
        for tx in traceoftxs.keys():
            for st in traceoftxs[tx]['traces']:
                parent_level = st.parent_level
                parent_seq = st.parent_seq
                if parent_level != None:
                    try:
                        parent_id = traceoftxs[tx]['trace_map'][parent_level][
                            parent_seq]
                        st.update_parent_id(parent_id)
                    except:
                        print(f"parent not found for {st.id}")
                # self.write_db(st)
                try:
                    self.local.write_into_database(
                        "subtraces", (st.txhash, st.id, st.parent_id),
                        "?, ?, ?", "transaction_hash, id, parent_trace_id")
                except sqlite3.Error as e:
                    print(e)
            tx_count += 1
            sys.stdout.write(str(tx_count) + '\r')
            sys.stdout.flush()
        print(tx_count, "txs")

        self.local.database_commit()
        del traceoftxs

    def build_subtrace_on_multidb(self, from_time, to_time):
        date = from_time.date()
        while date <= to_time.date():
            print('building subtraces on', date_to_str(date))
            self.load_database(DB_PATH, date)
            self.local.delete_on_database("subtraces")
            self.build_subtrace()
            self.local.database_index_create()
            date += timedelta(days=1)


def main():
    builder = SubTraceBuilder()
    from_time = datetime(2018, 10, 7, 0, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 0, 0)

    builder.build_subtrace_on_multidb(from_time, to_time)


if __name__ == "__main__":
    main()