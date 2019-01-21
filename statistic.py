import networkx as nx
from local.ethereum_database import EthereumDatabase
from graph import DiGraphBuilder
from datetime_utils import time_to_str
from datetime import datetime,timedelta
import sys, hashlib

DB_FILEPATH = "/Users/Still/Desktop/w/db/bigquery_ethereum-t.sqlite3"
STATISTIC_ANALYSIS_FILEPATH = "logs/statistic_analysis"

def sort_by_trace_address(subtrace):
        return subtrace[2]

class Statistic(object):
    def __init__(self, db_filepath=DB_FILEPATH):
        self.local = EthereumDatabase(db_filepath)
        self.builder = DiGraphBuilder(DB_FILEPATH)

    def query_traces_bytime(self, from_time, to_time):
        return self.local.cur.execute("select rowid,transaction_hash,from_address,to_address,input,trace_type,trace_address from traces where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time":from_time, "to_time":to_time})

    def query_subtraces_count_bytx(self, transaction_hash):
        return self.local.cur.execute("select count(*) from subtraces indexed by subtraces_transaction_hash_index where transaction_hash = :tx_hash", {'tx_hash':transaction_hash})

    

    def hash_subtraces(self, subtraces):
        subtraces.sort(key=sort_by_trace_address)
        address_map = {}
        symbolic_subtraces = []
        for subtrace in subtraces:
            symbolic_subtrace = []
            for i in range(0,2):
                if subtrace[i] in address_map.keys():
                    symbolic_subtrace.append(address_map[subtrace[i]])
                else:
                    symbol = len(address_map.keys())
                    address_map[subtrace[i]] = symbol
                    symbolic_subtrace.append(symbol)
            symbolic_subtrace.append(subtrace[3])
            symbolic_subtraces.append(symbolic_subtrace)
        m = hashlib.sha256(str(symbolic_subtraces).encode('utf-8'))
        return '0x' + m.hexdigest()

    def hash_traces_bytime(self, from_time, to_time):
        tx2hash = {}
        traces = self.query_traces_bytime(from_time, to_time).fetchall()
        print(len(traces), "traces")
        for trace in traces:
            tx_hash = trace['transaction_hash']
            if tx_hash not in tx2hash.keys():
                tx2hash[tx_hash] = {}
                subtraces_count = self.query_subtraces_count_bytx(tx_hash).fetchone()['count(*)']
                tx2hash[tx_hash]['subtraces_count'] = subtraces_count
                tx2hash[tx_hash]['countnow'] = 0
                tx2hash[tx_hash]['subtraces'] = []

            if trace['trace_type'] == 'call':
                trace_input = trace['input']
                if len(trace_input) > 9:
                    attr = trace_input[:10]
                else:
                    attr = 'fallback'
            else:
                 attr = trace['trace_type']
            if trace['trace_address'] == None:
                trace_address = ''
            tx2hash[tx_hash]['subtraces'].append((trace['from_address'], trace['to_address'], trace_address, attr))
            tx2hash[tx_hash]['countnow'] += 1

            if tx2hash[tx_hash]['countnow'] == tx2hash[tx_hash]['subtraces_count']:
                tx2hash[tx_hash]['subtraces_hash'] = self.hash_subtraces(tx2hash[tx_hash]['subtraces'])
                tx2hash[tx_hash]['subtraces'] = None
        print(len(tx2hash.keys()), "transactions")
        return tx2hash

    def hash_analysis(self, from_time, to_time):
        tx2hash = self.hash_traces_bytime(from_time, to_time)
        hash2tx = {}
        for tx in tx2hash.keys():
            subtraces_hash = tx2hash[tx]['subtraces_hash']
            if subtraces_hash in hash2tx.keys():
                hash2tx[subtraces_hash].append(tx)
            else:
                hash2tx[subtraces_hash] = [tx]
        print(len(hash2tx.keys()), "trace hash")
        tx_company = {}
        for subtrace_hash in hash2tx.keys():
            company = len(hash2tx[subtrace_hash])
            for tx in hash2tx[subtrace_hash]:
                tx_company[tx] = company

        with open(STATISTIC_ANALYSIS_FILEPATH, "w") as f:
            for tx in tx_company.keys():
                if tx_company[tx] < 10:
                    
                    f.write(tx + " " + str(tx_company[tx]) + "\n")
        import IPython;IPython.embed()

def main():
    analyzer = Statistic(DB_FILEPATH)

    from_time = datetime(2018, 10, 5, 6, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 40, 0)
    # to_time = from_time + timedelta(hours=1)
    while from_time < datetime(2018, 10, 7, 0, 0, 0):
        print("Statistic analysis from ", time_to_str(from_time), " to ", time_to_str(to_time))
        analyzer.hash_analysis(from_time, to_time)

        from_time = to_time
        to_time = from_time + timedelta(hours=1)

if __name__ == "__main__":
    main()