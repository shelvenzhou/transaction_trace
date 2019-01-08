import networkx as nx
from local.ethereum_database import EthereumDatabase
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
        return self.local.cur.execute("select rowid,transaction_hash,from_address,to_address,input from traces where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time":from_time, "to_time":to_time})

    def query_subtraces_bytx(self, transaction_hash):
        return self.local.cur.execute("select * from subtraces where transaction_hash = :tx_hash", {'tx_hash':transaction_hash})

    def query_txs_bytime(self, from_time, to_time):
        return self.local.cur.execute("select distinct transaction_hash from traces where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time":from_time, "to_time":to_time})

    def build_digraph_on_traces(self, from_time, to_time):
        
        trace_dg = nx.DiGraph()
        traces = self.query_traces_bytime(from_time, to_time)
        for trace in traces:
            # trace_id = row['id']
            # parent_trace_id = row['parent_trace_id']
    
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

        subtrace_graghs = []
        txs = self.query_txs_bytime(from_time, to_time).fetchall()
        print(f'building graphs for {len(txs)} transactions...')
        tx_count = 0
        for tx in txs:
            trace_gragh = self.build_digraph_on_subtraces_bytx(tx['transaction_hash'])
            if trace_gragh == None:
                continue
            subtrace_graghs.append(trace_gragh)
            tx_count += 1
            sys.stdout.write(str(tx_count) + '\r')
            sys.stdout.flush()

        return subtrace_graghs

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
    def __init__(self):
        pass

    def analyze_subtraces(self, subtrace_graph):
        fun = False

        cycles = list(nx.simple_cycles(subtrace_graph))
        reentrancy = self.check_reentrancy(subtrace_graph, cycles)
        callinjection = self.check_callinjection(subtrace_graph, cycles)
        if reentrancy > -1 or callinjection:
            fun = True
            print(subtrace_graph.graph['transaction_hash'])
            if reentrancy:
                print("Reentrancy Attack Found!")
            if callinjection:
                print("Call Injection Attack Might Found!")
            print("########################################")

        return fun

    def check_callinjection(self, graph, cycles):
        callinjection = False
        for cycle in cycles:
            if len(cycle) == 1:
                callinjection = True
        return callinjection

    def check_reentrancy(self, graph, cycles):
        reentrancy = -1
        if len(cycles) == 0:
            return reentrancy
        graph.graph['cycles'] = []

        for cycle in cycles:
            count = self.check_reentrancy_bycycle(graph, cycle)
            if count > 0:
                print("--------------------")
                print(graph.graph['transaction_hash'])
                print(f"trace cycle found, number of turns: ", count)
                graph.graph['cycles'].append(cycle)
                reentrancy = 0
                if count > 5:
                    reentrancy = 1
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
    from_time = datetime(2018, 10, 5, 6, 0, 0)
    to_time = datetime(2018, 10, 8, 7, 0, 0)

    builder = DiGraphBuilder(DB_FILEPATH)
    analyzer = GraphAnalyzer()
    # graphs = builder.build_digraph_on_subtraces_bytime(from_time, to_time)
    graphs = []
    txs = builder.query_txs_bytime(from_time, to_time).fetchall()
    print(f'building graphs and analyzing for {len(txs)} transactions...')
    count = 0
    for tx in txs:
        sys.stdout.write(str(count) + '\r')
        sys.stdout.flush()

        count += 1
        trace_gragh = builder.build_digraph_on_subtraces_bytx(tx['transaction_hash'])
        if trace_gragh == None:
            continue
        if analyzer.analyze_subtraces(trace_gragh):
            graphs.append(trace_gragh)
            print(f"{len(graphs)} fun, {len(txs)-count} txs left... ")

    # trace_gragh = builder.build_digraph_on_subtraces_bytx("0x21e9d20b57f6ae60dac23466c8395d47f42dc24628e5a31f224567a2b4effa88")
    # ret = analyzer.analyze_subtraces(trace_gragh)
    import IPython;IPython.embed()


if __name__ == "__main__":
    main()


    
    