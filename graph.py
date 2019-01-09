import networkx as nx
from local.ethereum_database import EthereumDatabase
from datetime_utils import time_to_str
from datetime import datetime,timedelta
import sys

DB_FILEPATH = "/Users/Still/Desktop/w/db/bigquery_ethereum-t.sqlite3"

class DiGraphBuilder(object):
    def __init__(self, db_filepath=DB_FILEPATH):
        self.local = EthereumDatabase(db_filepath)

    def query_subtraces(self):
        return self.local.cur.execute("select * from subtraces")

    def query_trace_byid(self, traceid):
        return self.local.cur.execute("select transaction_hash,from_address,to_address,input,trace_type,gas_used from traces where rowid = :trace_id", {'trace_id':traceid})

    def query_traces_bytime(self, from_time, to_time):
        return self.local.cur.execute("select rowid,transaction_hash,from_address,to_address,input from traces indexed by transaction_hash_index where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time":from_time, "to_time":to_time})

    def query_subtraces_bytx(self, transaction_hash):
        return self.local.cur.execute("select * from subtraces where transaction_hash = :tx_hash", {'tx_hash':transaction_hash})

    def query_txs_bytime(self, from_time, to_time):
        return self.local.cur.execute("select distinct transaction_hash from traces indexed by transaction_hash_index where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time":from_time, "to_time":to_time})

    def build_digraph_on_traces(self, from_time, to_time):
        
        trace_dg = nx.DiGraph()
        traces = self.query_traces_bytime(from_time, to_time)
        for trace in traces:
            tx_hash = trace['transaction_hash']
            from_address = trace['from_address']
            to_address = trace['to_address']
            trace_input = trace['input']
            method_hash = trace_input[:10]
            trace_dg.add_edge(from_address, to_address)
            if method_hash in trace_dg[from_address][to_address]:
                method_attr = trace_dg[from_address][to_address][method_hash]
            else:
                trace_dg[from_address][to_address][method_hash] = {}
                method_attr = trace_dg[from_address][to_address][method_hash]
            
            if tx_hash in method_attr.keys():
                method_attr[tx_hash] += 1
            else:
                method_attr[tx_hash] = 1

        return trace_dg

    def build_digraph_on_subtraces_bytime(self, from_time, to_time):

        subtrace_graphs = []
        txs = self.query_txs_bytime(from_time, to_time).fetchall()
        print(f"{len(txs)} transactions")
        tx_count = 0
        for tx in txs:
            trace_graph = self.build_digraph_on_subtraces_bytx(tx['transaction_hash'])
            if trace_graph == None:
                continue
            subtrace_graphs.append(trace_graph)
            tx_count += 1
            sys.stdout.write(str(tx_count) + '\r')
            sys.stdout.flush()

        return subtrace_graphs

    def build_digraph_on_subtraces_bytx(self, transaction_hash):
        subtraces = self.query_subtraces_bytx(transaction_hash).fetchall()
        if len(subtraces) < 2:
            return None
        trace_dg = nx.DiGraph(transaction_hash=transaction_hash)
        # import IPython;IPython.embed()
        for subtrace in subtraces:
            trace_id = subtrace['id']
            parent_trace_id = subtrace['parent_trace_id']
            trace = self.query_trace_byid(trace_id).fetchone()
            from_address = trace['from_address']
            to_address = trace['to_address']
            trace_type = trace['trace_type']
            gas_used = trace['gas_used']
            trace_dg.add_edge(from_address, to_address)
            if 'id' not in trace_dg[from_address][to_address]:
                trace_dg[from_address][to_address]['id'] = []
                trace_dg[from_address][to_address]['parent_trace_id'] = []
                trace_dg[from_address][to_address]['trace_type'] = []
                trace_dg[from_address][to_address]['gas_used'] = []

            trace_dg[from_address][to_address]['id'].append(trace_id)
            trace_dg[from_address][to_address]['parent_trace_id'].append(parent_trace_id)
            trace_dg[from_address][to_address]['trace_type'].append(trace_type)
            trace_dg[from_address][to_address]['gas_used'].append(gas_used)

        return trace_dg

class GraphAnalyzer(object):
    def __init__(self, db):
        self.local = db

    def query_input_byid(self, traceid):
        return self.local.cur.execute("select input from traces where rowid = :trace_id", {'trace_id':traceid})

    def analyze_subtraces(self, subtrace_graph):
        fun = False
        cycles = list(nx.simple_cycles(subtrace_graph))
        reentrancy = self.check_reentrancy(subtrace_graph, cycles)
        callinjection = self.check_callinjection(subtrace_graph, cycles)
        fun = reentrancy > -1 or callinjection
        if reentrancy > 0 or callinjection:
            f = open("logs/subtrace_analysis", "a+")
            m = subtrace_graph.graph['transaction_hash']
            print(m)
            f.write(m + "\n")
            if reentrancy > 0:
                m = "Reentrancy Attack Found!"
                print(m)
                f.write(m + "\n")
            if callinjection:
                m = "Call Injection Attack Mipht Found!"
                print(m)
                f.write(m + "\n")
            m = "########################################"
            print(m)
            f.write(m + "\n")
            f.close()

        return fun

    def check_callinjection(self, graph, cycles):
        callinjection = False
        for cycle in cycles:
            if callinjection:
                break
            if len(cycle) == 1:
                edges = self.get_edges_from_cycle(cycle)
                data = graph.get_edge_data(*edges[0])
                for index in range(0, len(data['id'])):
                    id = data['id'][index]
                    parent_trace_id = data['parent_trace_id'][index]
                    if parent_trace_id == None:
                        continue
                    trace_input = self.query_input_byid(id).fetchone()['input']          
                    parent_trace_input = self.query_input_byid(parent_trace_id).fetchone()['input']
                    if len(trace_input) > 10 and len(parent_trace_input) > 10:
                        method_hash = trace_input[2:10]
                        if method_hash in parent_trace_input:
                            callinjection = True
                            print("--------------------")
                            print(cycle[0])
                            print("trace id: ", id, "parent trace id: ", parent_trace_id)
                            print("--------------------")
                            break

        return callinjection

    def check_reentrancy(self, graph, cycles):
        reentrancy = -1
        if len(cycles) == 0:
            return reentrancy
        graph.graph['cycles'] = []

        for cycle in cycles:
            count = self.check_reentrancy_bycycle(graph, cycle)
            if count > 0:
                graph.graph['cycles'].append(cycle)
                reentrancy = 0
                if count > 5:
                    reentrancy = 1
                    print("--------------------")
                    # print(graph.graph['transaction_hash'])
                    print(f"trace cycle found, number of turns: ", count)
                    for node in cycle:
                        print(node, "->")
                    print("--------------------")
        
        return reentrancy

    def check_reentrancy_bycycle(self, graph, cycle):
        edges = self.get_edges_from_cycle(cycle)
        index = len(edges)-1
        trace_id = []
        while index > -2:
            data = graph.get_edge_data(*edges[index])
            if len(trace_id) == 0:
                trace_id = data['parent_trace_id']
            else:
                parent_id = []
                for id in trace_id:
                    if id in data['id']:
                        parent_id.append(data['parent_trace_id'][data['id'].index(id)])
                trace_id = parent_id
                if len(trace_id) == 0:
                    break
            index -= 1
        return len(trace_id)

    def get_edges_from_cycle(self, cycle):
        edges = []
        index = 1
        while index < len(cycle):
            edges.append((cycle[index-1], cycle[index]))
            index += 1
        edges.append((cycle[index-1], cycle[0]))
        return edges


def main():
    builder = DiGraphBuilder(DB_FILEPATH)
    analyzer = GraphAnalyzer(builder.local)

    from_time = datetime(2018, 8, 1, 9, 0, 0)
    to_time = datetime(2018, 12, 25, 0, 0, 0)
    # to_time = from_time + timedelta(hours=1)
    while from_time < datetime(2018, 12, 25, 0, 0, 0):
        print("building subtrace graphs from", time_to_str(from_time), "to", time_to_str(to_time))
        graphs = builder.build_digraph_on_subtraces_bytime(from_time, to_time)
        print(f"analyzing {len(graphs)} graphs...")
        fun = False
        count = 0
        for trace_graph in graphs:
            fun = fun or analyzer.analyze_subtraces(trace_graph)
            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()
        if not fun:
            print("no attack found")

        from_time = to_time
        to_time = from_time + timedelta(hours=1)

    import IPython;IPython.embed()


if __name__ == "__main__":
    main()


    
    