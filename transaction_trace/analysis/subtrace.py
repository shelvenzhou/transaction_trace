import decimal
import sqlite3
import sys
from datetime import datetime, timedelta

from ..datetime_utils import date_to_str, str_to_time, time_to_str
from ..local.ethereum_database import EthereumDatabase


class Subtrace:
    def __init__(self, tx_hash, trace_id, level=None, seq=None, parent_level=None, parent_seq=None):
        self.tx_hash = tx_hash
        self.trace_id = trace_id

        self.parent_id = None

        self.level = level
        self.seq = seq
        self.parent_level = parent_level
        self.parent_seq = parent_seq

    def update_parent_id(self, parent_id):
        self.parent_id = parent_id


class SubtraceBuilder:
    def __init__(self, db_folder):
        self.database = EthereumDatabase(db_folder)

    def build_subtrace(self, from_time=None, to_time=None):
        traceoftxs = {}
        re = self.query_db(from_time, to_time)
        try:
            trace_count = 0
            for row in re:
                if row['trace_address'] != None:
                    trace_addr = row['trace_address'].split(',')
                    if len(trace_addr) == 1:
                        parent_level = 0
                        parent_seq = 0
                    else:
                        parent_level = len(trace_addr)-1
                        parent_seq = int(trace_addr[-2])
                    st = Subtrace(row['transaction_hash'], row['rowid'], level=len(trace_addr), seq=int(
                        trace_addr[-1]), parent_level=parent_level, parent_seq=parent_seq)
                else:
                    st = Subtrace(row['transaction_hash'],
                                  row['rowid'], level=0, seq=0)

                txhash = row['transaction_hash']
                if txhash in traceoftxs.keys():
                    traceoftxs[txhash]['traces'].append(st)
                    if st.level in traceoftxs[txhash]['trace_map'].keys():
                        traceoftxs[txhash]['trace_map'][st.level][st.seq] = row['rowid']
                    else:
                        traceoftxs[txhash]['trace_map'][st.level] = {
                            st.seq: row['rowid']}
                else:
                    traces = []
                    traces.append(st)
                    trace_map = {}
                    trace_map[st.level] = {st.seq: row['rowid']}
                    traceoftxs[txhash] = {
                        'traces': traces, 'trace_map': trace_map}

                trace_count += 1
                sys.stdout.write(str(trace_count) + '\r')
                sys.stdout.flush()
            print(trace_count, "traces")
        except sqlite3.DatabaseError as e:
            error = time_to_str(from_time) + " " + \
                time_to_str(to_time) + " " + str(e)
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
                        parent_id = traceoftxs[tx]['trace_map'][parent_level][parent_seq]
                        st.update_parent_id(parent_id)
                    except:
                        print(f"parent not found for {st.id}")
                # self.write_db(st)
            tx_count += 1
            sys.stdout.write(str(tx_count) + '\r')
            sys.stdout.flush()
        print(tx_count, "txs")

        # self.local.database_commit()
        traceoftxs = {}


def main(db_folder, from_time, to_time):
    builder = SubtraceBuilder(db_folder)

    # builder.build_subtrace_on_multidb(from_time, to_time)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: %s database_folder from_time to_time", sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
