import sqlite3
from local.ethereum_database import EthereumDatabase
from datetime_utils import time_to_str
from datetime import datetime,timedelta
import decimal

DB_FILEPATH = "/Users/Still/Desktop/w/db/bigquery_ethereum-t.sqlite3"


class SubTrace(object):

    def __init__(self, txhash=None, id=None, level=None, seq=None, parent_level=None, parent_seq=None):
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

    def __init__(self, db_filepath=DB_FILEPATH):
        self.local = EthereumDatabase(db_filepath)

    def query_db(self, from_time, to_time):
        return self.local.cur.execute("select rowid,* from traces where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time":from_time, "to_time":to_time})

    def write_db(self, st):
        try:
            self.local.cur.execute("insert into subtraces(transaction_hash, id, parent_trace_id) values(?, ?, ?);", (st.txhash, st.id, st.parent_id))
        except sqlite3.Error as e:
            print(e)

    def build_subtrace(self, from_time, to_time):
        traceoftxs = {}
        re = self.query_db(from_time, to_time)
        for row in re:
            if row['trace_address'] != None:
                trace_addr = row['trace_address'].split(',')
                if len(trace_addr) == 1:
                    parent_level = 0
                    parent_seq = 0
                else:
                    parent_level = len(trace_addr)-1
                    parent_seq = int(trace_addr[-2])
                st = SubTrace(txhash=row['transaction_hash'], id=row['rowid'], level=len(trace_addr), seq=int(trace_addr[-1]), parent_level=parent_level, parent_seq=parent_seq)
            else:
                st = SubTrace(txhash=row['transaction_hash'], id=row['rowid'], level=0, seq=0)

            txhash = row['transaction_hash']
            if txhash in traceoftxs.keys():
                traceoftxs[txhash]['traces'].append(st)
                if st.level in traceoftxs[txhash]['trace_map'].keys():
                    traceoftxs[txhash]['trace_map'][st.level][st.seq] = row['rowid']
                else:
                    traceoftxs[txhash]['trace_map'][st.level] = {st.seq:row['rowid']}
            else:
                traces = []
                traces.append(st)
                trace_map = {}
                trace_map[st.level] = {st.seq:row['rowid']}
                traceoftxs[txhash] = {'traces':traces, 'trace_map':trace_map}

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
                self.write_db(st)

        self.local.database_commit()
        traceoftxs = {}

def main():
    from_time = datetime(2018, 10, 5, 6, 0, 0)
    to_time = datetime(2018, 10, 8, 7, 0, 0)

    builder = SubTraceBuilder(DB_FILEPATH)
    builder.build_subtrace(from_time, to_time)



if __name__ == "__main__":
    main()

