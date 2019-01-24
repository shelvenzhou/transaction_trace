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
            for i in range(1,3):
                if subtrace[i] in address_map.keys():
                    symbolic_subtrace.append(address_map[subtrace[i]])
                else:
                    symbol = len(address_map.keys())
                    address_map[subtrace[i]] = symbol
                    symbolic_subtrace.append(symbol)
            symbolic_subtrace.append(subtrace[4])
            symbolic_subtraces.append(symbolic_subtrace)
        m = hashlib.sha256(str(symbolic_subtraces).encode('utf-8'))
        return '0x' + m.hexdigest()

    def build_trace_graph(self, from_time, to_time):
        tx2hash = {}
        trace_graph = nx.DiGraph()
        traces = self.query_traces_bytime(from_time, to_time).fetchall()
        print(len(traces), "traces")
        count = 0
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
            else:
                trace_address = trace['trace_address']
            tx2hash[tx_hash]['subtraces'].append((trace['rowid'], trace['from_address'], trace['to_address'], trace_address, attr))
            tx2hash[tx_hash]['countnow'] += 1

            if tx2hash[tx_hash]['countnow'] == tx2hash[tx_hash]['subtraces_count']:
                tx2hash[tx_hash]['subtraces_hash'] = self.hash_subtraces(tx2hash[tx_hash]['subtraces'])
                for subtrace in tx2hash[tx_hash]['subtraces']:
                    rowid = subtrace[0]
                    from_address = subtrace[1]
                    to_address = subtrace[2]
                    subtraces_hash = tx2hash[tx_hash]['subtraces_hash']
                    trace_graph.add_edge(from_address, to_address)
                    if subtraces_hash not in trace_graph[from_address][to_address]:
                        trace_graph[from_address][to_address][subtraces_hash] = []
                    trace_graph[from_address][to_address][subtraces_hash].append(rowid)

                tx2hash[tx_hash]['subtraces'] = None

            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()

        print(len(tx2hash.keys()), "transactions")
        return trace_graph

def main():
    analyzer = Statistic(DB_FILEPATH)

    from_time = datetime(2018, 10, 5, 6, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 40, 0)
    # to_time = from_time + timedelta(hours=1)
    while from_time < datetime(2018, 10, 7, 0, 0, 0):
        print("Statistic analysis from", time_to_str(from_time), "to", time_to_str(to_time))
        trace_graph = analyzer.build_trace_graph(from_time, to_time)
        import IPython;IPython.embed()
        from_time = to_time
        to_time = from_time + timedelta(hours=1)

if __name__ == "__main__":
    main()