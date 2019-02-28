import networkx as nx
from local.ethereum_database import EthereumDatabase
from local.statistic_database import StatisticDatabase
from datetime_utils import time_to_str, date_to_str, month_to_str
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta
import sqlite3
import sys
import hashlib
import gc

DB_PATH = "/Users/Still/Desktop/w/db/"
STATISTIC_ANALYSIS_FILEPATH = "logs/statistic_analysis"


def sort_by_trace_address(subtrace):
    return subtrace[3]


class Statistic(object):
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.raw = None
        self.db = None

    def load_database(self, db_date):
        self.raw = EthereumDatabase(
            f"{self.db_path}/raw/bigquery_ethereum_{date_to_str(db_date)}.sqlite3"
        )
        self.db = StatisticDatabase(
            f"{self.db_path}/statistic/statistic_{month_to_str(db_date)}.sqlite3"
        )

    def get_nodes_bytime(self, from_time, to_time):
        nodes = {}
        date = from_time.date()
        while date <= to_time.date():
            self.load_database(date)
            result = self.db.read_from_database(table="nodes", columns="*")
            for one in result:
                if one[0] not in nodes:
                    nodes[one[0]] = {}
                if one[1] not in nodes[one[0]]:
                    nodes[one[0]][one[1]] = one[2]
                else:
                    nodes[one[0]][one[1]] += one[2]
            date += relativedelta(months=1)
        return nodes

    def hash_subtraces(self, subtraces):
        subtraces.sort(key=sort_by_trace_address)
        address_map = {}
        symbolic_subtraces = []
        for subtrace in subtraces:
            symbolic_subtrace = []
            for i in range(1, 3):
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

    def build_trace_graph(self, graph=None, tx2hash=None):
        if graph == None:
            trace_graph = nx.DiGraph()
        else:
            trace_graph = graph
        if tx2hash == None:
            tx2hash = {}
        traces = self.raw.read_from_database(
            table="traces",
            columns=
            "transaction_hash,from_address,to_address,input,trace_type,trace_address"
        )
        count = 0
        for trace in traces:
            tx_hash = trace['transaction_hash']
            if tx_hash not in tx2hash.keys():
                tx2hash[tx_hash] = {}
                subtraces_count = self.raw.read_from_database(
                    table="subtraces",
                    columns="count(*)",
                    index="INDEXED BY subtraces_transaction_hash_index",
                    clause="where transaction_hash = :tx_hash",
                    vals={
                        'tx_hash': tx_hash
                    }).fetchone()['count(*)']

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
            tx2hash[tx_hash]['subtraces'].append(
                (trace['transaction_hash'], trace['from_address'],
                 trace['to_address'], trace_address, attr))
            tx2hash[tx_hash]['countnow'] += 1

            if tx2hash[tx_hash]['countnow'] == tx2hash[tx_hash][
                    'subtraces_count']:
                subtraces_hash = self.hash_subtraces(
                    tx2hash[tx_hash]['subtraces'])
                for subtrace in tx2hash[tx_hash]['subtraces']:
                    from_address = subtrace[1]
                    to_address = subtrace[2]
                    trace_graph.add_edge(from_address, to_address)
                    for addr in (from_address, to_address):
                        if subtraces_hash not in trace_graph.node[addr]:
                            trace_graph.node[addr][subtraces_hash] = []
                        if tx_hash not in trace_graph.node[addr][
                                subtraces_hash]:
                            trace_graph.node[addr][subtraces_hash].append(
                                tx_hash)

                tx2hash[tx_hash] = subtraces_hash

            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()

        print(len(tx2hash.keys()), "transactions")
        return (trace_graph, tx2hash)

    def build_trace_graph_on_multidb(self, from_time, to_time):
        date = from_time.date()
        trace_graph = nx.DiGraph()
        tx2hash = {}
        while date <= to_time.date():
            print(date_to_str(date))
            self.load_database(date)
            (trace_graph, tx2hash) = self.build_trace_graph(
                graph=trace_graph, tx2hash=tx2hash)
            date += timedelta(days=1)
        return (trace_graph, tx2hash)

    def extract_from_graph(self, trace_graph):
        tx_attr = {}
        node_attr = {}
        nodes = trace_graph.nodes(data=True)
        for node in nodes:
            node_addr = node[0]
            if node_addr not in node_attr:
                node_attr[node_addr] = {}
            hash_count = {}
            for h in node[1]:
                hash_count[h] = len(node[1][h])
            for h in node[1]:
                if h not in node_attr[node_addr]:
                    node_attr[node_addr][h] = hash_count[h]
                else:
                    node_attr[node_addr][h] += hash_count[h]
                for tx in node[1][h]:
                    if tx not in tx_attr:
                        tx_attr[tx] = {}
                    tx_attr[tx][node_addr] = None

        return (tx_attr, node_attr)

    def analyze(self, from_time, to_time):
        print("Analyze txs from", month_to_str(from_time.date()), "to",
              month_to_str(to_time.date()))
        nodes = self.get_nodes_bytime(from_time, to_time)
        max_hash = {}
        for node_addr in nodes:
            max_count = 0
            for h in nodes[node_addr]:
                if nodes[node_addr][h] > max_count:
                    max_count = nodes[node_addr][h]
            max_hash[node_addr] = max_count

        mix = []
        fun = {}
        date = from_time.date()
        while date <= to_time.date():
            self.load_database(date)
            txs = self.db.read_from_database(table="transactions", columns="*")
            print(month_to_str(date))
            count = 0
            for tx in txs:
                tx_hash = tx[0]
                nodes_address = eval(tx[1])
                trace_hash = tx[2]
                tx_attr = {}
                mix_hash = hashlib.sha256(
                    (tx[2] + tx[1]).encode('utf-8')).hexdigest()
                if mix_hash in mix:
                    continue
                else:
                    mix.append(mix_hash)
                for node in nodes_address:
                    if node == None:
                        continue
                    tx_attr[node] = max_hash[node] / nodes[node][trace_hash]
                if self.isfun(tx_attr):
                    fun[tx_hash] = tx_attr

                count += 1
                sys.stdout.write(str(count) + '\r')
                sys.stdout.flush()
            print(count, "transactions")
            del txs
            gc.collect()
            date += relativedelta(months=1)

        return (fun, nodes)

    def isfun(self, tx_attr):
        for h in tx_attr:
            if tx_attr[h] > 30:
                return True
        return False

    def process_raw_data(self, from_time, to_time):
        print("Process data from", date_to_str(from_time.date()), "to",
              date_to_str(to_time.date()))
        date = from_time.date()
        while date <= to_time.date():
            print(date_to_str(date))
            self.load_database(date)
            try:
                self.db.database_create()
            except:
                print("datebase already exists")
            (trace_graph, tx2hash) = self.build_trace_graph()
            (tx_attr, node_attr) = self.extract_from_graph(trace_graph)
            self.db.database_insert(tx_attr, node_attr, tx2hash)
            self.db.database_commit()
            print("statistic data inserted:", len(tx_attr.keys()),
                  "transcations,", len(node_attr.keys()), "nodes")
            del trace_graph, tx_attr, node_attr, tx2hash
            gc.collect()
            date += timedelta(days=1)


def main(argv):
    analyzer = Statistic(DB_PATH)
    from_time = datetime(2018, 10, 7, 0, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 0, 0)
    # analyzer.process_raw_data(from_time, to_time)
    (fun, nodes) = analyzer.analyze(from_time, to_time)

    import IPython
    IPython.embed()


if __name__ == "__main__":
    main(sys.argv)
