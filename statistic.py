import networkx as nx
from local.ethereum_database import EthereumDatabase
from graph import DiGraphBuilder
from datetime_utils import time_to_str,date_to_str,month_to_str
from datetime import datetime,timedelta,date
from dateutil.relativedelta import relativedelta
import sqlite3
import sys,hashlib,gc
import pickle

DB_PATH = "/Users/Still/Desktop/w/db/"
STATISTIC_ANALYSIS_FILEPATH = "logs/statistic_analysis"

def sort_by_trace_address(subtrace):
        return subtrace[3]

class StatisticDatabase(object):

    def __init__(self, db_filepath):
        self.db_filepath = db_filepath
        self.conn = sqlite3.connect(
            self.db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
        self.cur = self.conn.cursor()

    def __del__(self):
        self.conn.close()

    def database_create(self):
        self.cur.execute("""
            CREATE TABLE transactions(
                transaction_hash TEXT PRIMARY KEY,
                nodes_address TEXT,
                trace_hash TEXT
            )
        """)

        self.cur.execute("""
            CREATE TABLE nodes(
                node_address TEXT,
                hash TEXT,
                count INT,
                PRIMARY KEY(node_address, hash)
            )
        """)

    def database_index_create(self):
        self.cur.execute("""
            CREATE INDEX transaction_hash_index on transactions(transaction_hash)
        """)

        self.cur.execute("""
            CREATE INDEX node_address_index on nodes(node_address)
        """)

    def database_commit(self):
        self.conn.commit()

    def database_insert(self, tx_attr, node_attr, hash2tx):
        for tx in tx_attr:
            nodes_address = list(tx_attr[tx].keys())
            self.cur.execute("""
                INSERT INTO transactions(transaction_hash, nodes_address)
                VALUES(?, ?);
            """, (tx, str(nodes_address)))

        for h in hash2tx:
            for tx in hash2tx[h]:
                self.cur.execute("""
                    UPDATE transactions SET trace_hash = :trace_hash WHERE transaction_hash = :tx_hash
                """, {"trace_hash": h, "tx_hash": tx})

        for node in node_attr:
            for h in node_attr[node]:
                re = self.cur.execute("""
                    SELECT count from nodes WHERE node_address = :node AND hash = :hash
                """, {"node": node, "hash": h}).fetchall()
                if len(re) == 0:
                    self.cur.execute("""
                        INSERT INTO nodes(node_address, hash, count)
                        VALUES(?, ?, ?)
                    """, (node, h, node_attr[node][h]))
                else:
                    self.cur.execute("""
                        UPDATE nodes SET count = :count WHERE node_address = :node AND hash = :hash
                    """, {"count": re[0][0]+node_attr[node][h], "node": node, "hash": h})


class Statistic(object):
    def __init__(self, db_date, db_path=DB_PATH):
        self.db_path = db_path
        self.raw = EthereumDatabase(f"{db_path}/raw/bigquery_ethereum_{date_to_str(db_date)}.sqlite3")
        self.db = StatisticDatabase(f"{db_path}/statistic/statistic_{month_to_str(db_date)}.sqlite3")
        
    def query_traces_bytime(self, from_time, to_time):
        if from_time == None:
            return self.raw.cur.execute("select transaction_hash,from_address,to_address,input,trace_type,trace_address from traces")
        else:
            return self.raw.cur.execute("select transaction_hash,from_address,to_address,input,trace_type,trace_address from traces where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time":from_time, "to_time":to_time})

    def query_subtraces_count_bytx(self, transaction_hash):
        return self.raw.cur.execute("select count(*) from subtraces indexed by subtraces_transaction_hash_index where transaction_hash = :tx_hash", {'tx_hash':transaction_hash})

    def query_txs_for_analysis(self):
        return self.db.cur.execute("select * from transactions")

    def query_hash_count_on_node(self, tx, node, trace_hash, from_time, to_time):
        count = 0
        date = from_time.date()
        while date <= to_time.date():
            database = StatisticDatabase(f"{self.db_path}/statistic/statistic_{month_to_str(date)}.sqlite3")
            re = database.cur.execute("select count from nodes where node_address = :node and hash = :hash", {"node": node, "hash": trace_hash}).fetchall()
            if len(re) > 0:
                count += re[0][0]
            date += relativedelta(months=1)
        return count

    def query_max_count_on_node(self, node, from_time, to_time):
        node_hashes = {}
        date = from_time.date()
        while date <= to_time.date():
            database = StatisticDatabase(f"{self.db_path}/statistic/statistic_{month_to_str(date)}.sqlite3")
            re = database.cur.execute("select hash, count from nodes where node_address = :node", {"node": node}).fetchall()
            for one in re:
                if one[0] in node_hashes:
                    node_hashes[one[0]] += one[1]
                else:
                    node_hashes[one[0]] = one[1]
            date += relativedelta(months=1)
        max_count = 0 
        for h in node_hashes:
            if node_hashes[h] > max_count:
                max_count = node_hashes[h]
        return max_count

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

    def build_trace_graph(self, graph=None, from_time=None, to_time=None):
        if graph == None:
            trace_graph = nx.DiGraph()
        else:
            trace_graph = graph
        traces = self.query_traces_bytime(from_time, to_time).fetchall()
        print(len(traces), "traces")
        tx2hash = {}
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
            tx2hash[tx_hash]['subtraces'].append((trace['transaction_hash'], trace['from_address'], trace['to_address'], trace_address, attr))
            tx2hash[tx_hash]['countnow'] += 1

            if tx2hash[tx_hash]['countnow'] == tx2hash[tx_hash]['subtraces_count']:
                subtraces_hash = self.hash_subtraces(tx2hash[tx_hash]['subtraces'])
                for subtrace in tx2hash[tx_hash]['subtraces']:
                    from_address = subtrace[1]
                    to_address = subtrace[2]
                    trace_graph.add_edge(from_address, to_address)
                    for addr in (from_address, to_address):
                        if subtraces_hash not in trace_graph.node[addr]:
                            trace_graph.node[addr][subtraces_hash] = []
                        if tx_hash not in trace_graph.node[addr][subtraces_hash]:
                            trace_graph.node[addr][subtraces_hash].append(tx_hash)

                tx2hash[tx_hash] = subtraces_hash

            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()

        print(len(tx2hash.keys()), "transactions")
        return trace_graph

    def build_trace_graph_on_multidb(self, from_time, to_time):
        date = from_time.date()
        trace_graph = nx.DiGraph()
        while date <= to_time.date():
            print(date_to_str(date))
            self.raw = EthereumDatabase(f"{self.db_path}/raw/bigquery_ethereum_{date_to_str(date)}.sqlite3")
            trace_graph = self.build_trace_graph(graph=trace_graph)
            date += timedelta(days=1)
        return trace_graph

    def extract_from_graph(self, trace_graph):
        tx_attr = {}
        node_attr = {}
        hash2tx = {}
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
                if h not in hash2tx:
                    hash2tx[h] = []
                for tx in node[1][h]:
                    if tx not in tx_attr:
                        tx_attr[tx] = {}
                    tx_attr[tx][node_addr] = None
                    hash2tx[h].append(tx)

        return (tx_attr, node_attr, hash2tx)

    def analyze(self, tx_attr, node_attr, tx2hash):
        max_hash = {}
        for node_addr in node_attr:
            max_count = 0
            for h in node_attr[node_addr]:
                if node_attr[node_addr][h] > max_count:
                    max_count = node_attr[node_addr][h]
            max_hash[node_addr] = max_count
        
        for tx in tx_attr:
            for node_addr in tx_attr[tx]:
                h = tx2hash[tx]
                import IPython;IPython.embed()
                tx_attr[tx][node_addr] = max_hash[node_addr]/node_attr[node_addr][h]

        import IPython;IPython.embed()

    def analyze_txs(self, from_time, to_time):
        print("Analyze txs from", month_to_str(from_time.date()), "to", month_to_str(to_time.date()))
        fun = {}
        max_hash = {}
        date = from_time.date()
        while date <= to_time.date():
            self.db = StatisticDatabase(f"{self.db_path}/statistic/statistic_{month_to_str(date)}.sqlite3")
            txs = self.query_txs_for_analysis().fetchall()
            print(month_to_str(date), len(txs), "transsactions")
            count = 0
            for tx in txs:
                tx_hash = tx[0]
                nodes_address = eval(tx[1])
                trace_hash = tx[2]
                tx_attr = {}
                for node in nodes_address:
                    if node == None:
                        continue
                    hash_count = self.query_hash_count_on_node(tx_hash, node, trace_hash, from_time, to_time)
                    if node not in max_hash:
                        max_hash[node] = self.query_max_count_on_node(node, from_time, to_time)
                    tx_attr[node] = max_hash[node]/hash_count
                if self.isfun(tx_attr):
                    fun[tx_hash] = tx_attr

                count += 1
                sys.stdout.write(str(count) + '\r')
                sys.stdout.flush()
            del txs
            gc.collect()
            date += relativedelta(months=1)
        return fun

    def isfun(self, tx_attr):
        for h in tx_attr:
            if tx_attr[h] > 10:
                retufrn True
        return False

    def process_raw_data(self, from_time, to_time):
        print("Process data from", date_to_str(from_time.date()), "to", date_to_str(to_time.date()))
        date = from_time.date()
        while date <= to_time.date():
            print(date_to_str(date))
            self.raw = EthereumDatabase(f"{self.db_path}/raw/bigquery_ethereum_{date_to_str(date)}.sqlite3")
            self.db = StatisticDatabase(f"{self.db_path}/statistic/statistic_{month_to_str(date)}.sqlite3")
            try:
                self.db.database_create()
            except:
                print("datebase already exists")
            trace_graph = self.build_trace_graph()
            (tx_attr, node_attr, hash2tx) = self.extract_from_graph(trace_graph)
            self.db.database_insert(tx_attr, node_attr, hash2tx)
            self.db.database_commit()
            print("statistic data inserted:", len(tx_attr.keys()), "transcations,", len(node_attr.keys()), "nodes,", len(hash2tx.keys()), "hashes")
            del trace_graph, tx_attr, node_attr, hash2tx
            gc.collect()
            date += timedelta(days=1)
        

def main(argv):
    from_time = datetime(2018, 10, 7, 0, 0, 0)
    date = from_time.date()
    analyzer = Statistic(date, DB_PATH)

    to_time = datetime(2018, 10, 7, 0, 0, 0)
    # analyzer.process_raw_data(from_time, to_time)
    fun = analyzer.analyze_txs(from_time, to_time)

    import IPython;IPython.embed()

if __name__ == "__main__":
    main(sys.argv)