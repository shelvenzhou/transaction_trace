import networkx as nx
from local.ethereum_database import EthereumDatabase
from datetime_utils import time_to_str
from datetime import datetime, timedelta
import sys

DB_FILEPATH = "/Users/Still/Desktop/w/db/bigquery_ethereum-t.sqlite3"
SUBTRACE_ANALYSIS_FILEPATH = "logs/subtrace_analysis"


class GraphAnalyzer:
    def __init__(self, db):
        self.local = db

    def print_and_write(self, file, msg):
        print(msg)
        file.write(msg + "\n")

    def query_input_byid(self, traceid):
        return self.local.cur.execute("select input from traces where rowid = :trace_id", {'trace_id': traceid})

    def analyze_subtraces(self, subtrace_graph):
        fun = False
        cycles = list(nx.simple_cycles(subtrace_graph))
        reentrancy = self.check_reentrancy(subtrace_graph, cycles)
        callinjection = self.check_callinjection(subtrace_graph, cycles)
        fun = reentrancy > 0 or callinjection
        if reentrancy > 0 or callinjection:
            f = open(SUBTRACE_ANALYSIS_FILEPATH, "a+")
            m = subtrace_graph.graph['transaction_hash']
            print(m)
            f.write(m + "\n")
            if reentrancy > 0:
                m = "Reentrancy Attack Found!"
                self.print_and_write(f, m)
            if callinjection:
                m = "Call Injection Attack Might Found!"
                self.print_and_write(f, m)
            m = "########################################\n"
            self.print_and_write(f, m)
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
                    gas_used = data['gas_used'][index]
                    if parent_trace_id == None or gas_used == None:
                        continue
                    trace_input = self.query_input_byid(id).fetchone()['input']
                    parent_trace_input = self.query_input_byid(
                        parent_trace_id).fetchone()['input']
                    if len(trace_input) > 10 and len(parent_trace_input) > 10 and gas_used > 0:
                        method_hash = trace_input[2:10]
                        if method_hash in parent_trace_input:
                            callinjection = True
                            f = open(SUBTRACE_ANALYSIS_FILEPATH, "a+")
                            m = "--------------------"
                            self.print_and_write(f, m)
                            m = cycle[0]
                            self.print_and_write(f, m)
                            m = "trace id: " + \
                                str(id) + " parent trace id: " + \
                                str(parent_trace_id)
                            self.print_and_write(f, m)
                            m = "--------------------"
                            self.print_and_write(f, m)
                            f.close()
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
                    f = open(SUBTRACE_ANALYSIS_FILEPATH, "a+")
                    m = "--------------------"
                    self.print_and_write(f, m)
                    m = "trace cycle found, number of turns: " + str(count)
                    self.print_and_write(f, m)
                    for node in cycle:
                        m = node + "->"
                        self.print_and_write(f, m)
                    m = "--------------------"
                    self.print_and_write(f, m)
                    f.close()

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
                        parent_id.append(
                            data['parent_trace_id'][data['id'].index(id)])
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

    # from_time = datetime(2018, 8, 1, 8, 0, 0)
    from_time = datetime(2018, 8, 1, 9, 0, 0)
    to_time = datetime(2018, 12, 25, 0, 0, 0)
    # to_time = from_time + timedelta(hours=1)
    while from_time < datetime(2018, 12, 25, 0, 0, 0):
        print("building subtrace graphs from", time_to_str(
            from_time), "to", time_to_str(to_time))
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

    import IPython
    IPython.embed()


if __name__ == "__main__":
    main()
