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
        nodes_attr = {}
        date = from_time.date()
        while date <= to_time.date():
            self.load_database(date)
            result = self.db.read_from_database(table="nodes", columns="*")
            for one in result:
                node_address = one[0]
                subtrace_hash = one[1]
                count = one[2]
                if node_address not in nodes:
                    nodes[node_address] = {}
                    nodes_attr[node_address] = {"heat": 0, "max": 0}
                if subtrace_hash not in nodes[node_address]:
                    count_new = count
                else:
                    count_new = nodes[node_address][subtrace_hash] + count
                nodes[node_address][subtrace_hash] = count_new
                nodes_attr[node_address]["heat"] += count
                if count_new > nodes_attr[node_address]["max"]:
                    nodes_attr[node_address]["max"] = count_new
            date += relativedelta(months=1)
        return (nodes, nodes_attr)

    def hash_subtraces(self, subtraces):
        address_map = {}
        symbolic_subtraces = []
        for subtrace in subtraces:
            symbolic_subtrace = []
            for i in range(0, 2):
                if subtrace[i] in address_map.keys():
                    symbolic_subtrace.append(address_map[subtrace[i]])
                else:
                    symbol = len(address_map.keys())
                    address_map[subtrace[i]] = symbol
                    symbolic_subtrace.append(symbol)
            symbolic_subtrace.append(subtrace[2])
            symbolic_subtraces.append(symbolic_subtrace)
        m = hashlib.sha256(str(symbolic_subtraces).encode('utf-8'))
        return '0x' + m.hexdigest()

    def build_call_tree(self):
        tx_trees = {}
        subtraces = self.raw.read_from_database(table="subtraces", columns="*")
        for subtrace in subtraces:
            tx_hash = subtrace["transaction_hash"]
            trace_id = subtrace["id"]
            parent_trace_id = subtrace["parent_trace_id"]
            if tx_hash not in tx_trees:
                tx_trees[tx_hash] = {}
            if parent_trace_id == None:
                tx_trees[tx_hash][-1] = trace_id
            else:
                if parent_trace_id not in tx_trees[tx_hash]:
                    tx_trees[tx_hash][parent_trace_id] = []
                tx_trees[tx_hash][parent_trace_id].append(trace_id)
        return tx_trees

    def traversal_with_dfs(self, tree):
        paths = []
        path = []
        dfs_stack = []
        back_step = []
        root_id = tree[-1]
        dfs_stack.append(root_id)
        back_step.append(1)
        while len(dfs_stack) > 0:
            trace_id = dfs_stack.pop()
            path.append(trace_id)
            if trace_id not in tree:
                paths.append(tuple(path))
                back = back_step.pop()
                while back > 0:
                    path.pop()
                    back -= 1
                continue
            childs_id = tree[trace_id]
            if len(childs_id) == 1:
                dfs_stack.append(childs_id[0])
                back_step[-1] += 1
            else:
                for child in childs_id:
                    dfs_stack.append(child)
                    back_step.append(1)
        return paths

    def build_trace_graph(self, graph=None):
        if graph == None:
            trace_graph = nx.DiGraph()
        else:
            trace_graph = graph

        tx_trees = self.build_call_tree()
        tx2paths = {}
        for tx_hash in tx_trees:
            tx2paths[tx_hash] = self.traversal_with_dfs(tx_trees[tx_hash])

        traces = self.raw.read_from_database(
            table="traces",
            columns="rowid, from_address, to_address, input, trace_type")

        id2trace = {}
        count = 0
        for trace in traces:
            trace_id = trace["rowid"]
            id2trace[trace_id] = {}
            id2trace[trace_id]["from_address"] = trace["from_address"]
            id2trace[trace_id]["to_address"] = trace["to_address"]
            if trace['trace_type'] == 'call':
                trace_input = trace['input']
                if len(trace_input) > 9:
                    attr = trace_input[:10]
                else:
                    attr = 'fallback'
            else:
                attr = trace['trace_type']
            id2trace[trace_id]["attr"] = attr
            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()
        print(count, "traces")

        print("starting to hash subtraces...")
        print(len(tx2paths), "transactions")
        tx2hashs = {}
        count = 0
        for tx_hash in tx2paths:
            for path in tx2paths[tx_hash]:
                subtraces = []
                for trace_id in path:
                    from_address = id2trace[trace_id]["from_address"]
                    to_address = id2trace[trace_id]["to_address"]
                    subtraces.append((from_address, to_address,
                                      id2trace[trace_id]["attr"]))
                subtrace_hash = self.hash_subtraces(subtraces)
                if tx_hash not in tx2hashs:
                    tx2hashs[tx_hash] = {}
                if subtrace_hash not in tx2hashs[tx_hash]:
                    tx2hashs[tx_hash][subtrace_hash] = set()
                tx2hashs[tx_hash][subtrace_hash].add(str(subtraces))
            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()
        del tx_trees, tx2paths, id2trace

        print("Appending data to graph...")
        count = 0
        for tx_hash in tx2hashs:
            for subtrace_hash in tx2hashs[tx_hash]:
                nodes_list = []
                for ssubtraces in tx2hashs[tx_hash][subtrace_hash]:
                    nodes = set()
                    subtraces = eval(ssubtraces)
                    for subtrace in subtraces:
                        from_address = subtrace[0]
                        to_address = subtrace[1]
                        nodes.add(from_address)
                        nodes.add(to_address)
                        trace_graph.add_edge(from_address, to_address)
                        for addr in (from_address, to_address):
                            if subtrace_hash not in trace_graph.node[addr]:
                                trace_graph.node[addr][subtrace_hash] = []
                            if tx_hash not in trace_graph.node[addr][
                                    subtrace_hash]:
                                trace_graph.node[addr][subtrace_hash].append(
                                    tx_hash)
                    nodes_list.append(list(nodes))
                tx2hashs[tx_hash][subtrace_hash] = nodes_list
            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()

        return (trace_graph, tx2hashs)

    def build_trace_graph_on_multidb(self, from_time, to_time):
        date = from_time.date()
        trace_graph = nx.DiGraph()
        tx2hash = {}
        while date <= to_time.date():
            print(date_to_str(date))
            self.load_database(date)
            (trace_graph, tx2hash) = self.build_trace_graph(graph=trace_graph)
            date += timedelta(days=1)
        return (trace_graph, tx2hash)

    def extract_from_graph(self, trace_graph):
        node2hashs = {}
        nodes = trace_graph.nodes(data=True)
        for node in nodes:
            node_addr = node[0]
            if node_addr not in node2hashs:
                node2hashs[node_addr] = {}
            hash_count = {}
            for h in node[1]:
                hash_count[h] = len(node[1][h])
            for h in node[1]:
                if h not in node2hashs[node_addr]:
                    node2hashs[node_addr][h] = hash_count[h]
                else:
                    node2hashs[node_addr][h] += hash_count[h]

        return node2hashs

    def analyze(self, from_time, to_time):
        print("Analyze txs from", month_to_str(from_time.date()), "to",
              month_to_str(to_time.date()))
        (nodes, nodes_attr) = self.get_nodes_bytime(from_time, to_time)

        mix = set()
        fun = {}
        date = from_time.date()
        while date <= to_time.date():
            self.load_database(date)
            txs = self.db.read_from_database(table="transactions", columns="*")
            print(month_to_str(date))
            count = 0
            for tx in txs:
                tx_hash = tx[0]
                subtrace_hash = tx[1]
                node_addresses = eval(tx[2])
                if tx_hash in fun:
                    continue
                for addresses in node_addresses:
                    mix_hash = subtrace_hash + str(addresses)
                    if mix_hash in mix:
                        break
                    else:
                        mix.add(mix_hash)
                    node_heat = []
                    addresses.pop(0)
                    for node_address in addresses:
                        node_heat.append((node_address,
                                          nodes_attr[node_address]["heat"]))
                    node_heat.sort(key=lambda one: one[1], reverse=True)
                    tx_attr = {}
                    for node in node_heat:
                        node_address = node[0]
                        if node_address == None:
                            continue
                        tx_attr[node_address] = nodes_attr[node_address][
                            "max"] / nodes[node_address][subtrace_hash]
                    if self.isfun(tx_attr):
                        fun[tx_hash] = tx_attr
                        break

                count += 1
                sys.stdout.write(str(count) + '\r')
                sys.stdout.flush()

            del txs, mix
            gc.collect()
            date += relativedelta(months=1)

        return (fun, nodes)

    def isfun(self, tx_attr):
        heat_point = 0.2
        heat_top = 500
        heat_floor = 10
        rare_point = 20

        node_addrs = list(tx_attr.keys())
        if tx_attr[node_addrs[0]] < heat_top or tx_attr[node_addrs[-1]] > heat_floor:
            return False
        for node_addr in node_addrs[:int(len(node_addrs) * heat_point) + 1]:
            if tx_attr[node_addr] > rare_point:
                return True
        return False

    def database_insert(self, tx2hashs, node2hashs):
        for tx_hash in tx2hashs:
            for h in tx2hashs[tx_hash]:
                self.db.write_into_database(
                    table="transactions",
                    vals=(tx_hash, h, str(tx2hashs[tx_hash][h])),
                    placeholder="?, ?, ?",
                    columns="transaction_hash, subtrace_hash, node_addresses")

        for node in node2hashs:
            for h in node2hashs[node]:
                re = self.db.read_from_database(
                    table="nodes",
                    columns="count",
                    clause=
                    "WHERE node_address = :node AND subtrace_hash = :hash",
                    vals={
                        "node": node,
                        "hash": h
                    }).fetchall()
                if len(re) == 0:
                    self.db.write_into_database(
                        table="nodes",
                        vals=(node, h, node2hashs[node][h]),
                        placeholder="?, ?, ?",
                        columns="node_address, subtrace_hash, count")
                else:
                    self.db.update_on_database(
                        table="nodes",
                        assign="count = :count",
                        clause=
                        "WHERE node_address = :node AND subtrace_hash = :hash",
                        vals={
                            "count": re[0][0] + node2hashs[node][h],
                            "node": node,
                            "hash": h
                        })

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
            (trace_graph, tx2hashs) = self.build_trace_graph()
            node2hashs = self.extract_from_graph(trace_graph)
            self.database_insert(tx2hashs, node2hashs)
            self.db.database_commit()
            print("statistic data inserted:", len(tx2hashs.keys()),
                  "transcations,", len(node2hashs.keys()), "nodes")
            del trace_graph, node2hashs, tx2hashs
            gc.collect()
            month = month_to_str(date)
            date += timedelta(days=1)
            if month != month_to_str(date):
                print("creating index...")
                self.db.database_index_create()


def main(argv):
    analyzer = Statistic(DB_PATH)
    from_time = datetime(2018, 10, 7, 0, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 0, 0)
    analyzer.process_raw_data(from_time, to_time)
    (fun, nodes) = analyzer.analyze(from_time, to_time)

    import IPython
    IPython.embed()


if __name__ == "__main__":
    main(sys.argv)
