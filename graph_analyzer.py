import networkx as nx
from local.ethereum_database import EthereumDatabase
from graph_builder import DiGraphBuilder
from datetime_utils import time_to_str, date_to_str
from datetime import datetime, timedelta
import sys

DB_PATH = "/Users/Still/Desktop/w/db/"
SUBTRACE_ANALYSIS_FILEPATH = "logs/graph_analysis"


class GraphAnalyzer(object):
    def __init__(self, graph_builder: DiGraphBuilder):
        self.local = None
        self.builder = graph_builder

    def load_database(self, db_path, date):
        self.local = EthereumDatabase(
            f"{db_path}raw/bigquery_ethereum_{date_to_str(date)}.sqlite3")
        self.builder.laod_database(db_path, date)

    def print_and_write(self, file, msg):
        print(msg)
        file.write(msg + "\n")

    def analyze_subtrace_graph(self, subtrace_graph):
        fun = False
        cycles = list(nx.simple_cycles(subtrace_graph))
        reentrancy = self.check_reentrancy(subtrace_graph, cycles)
        callinjection = self.check_callinjection(subtrace_graph, cycles)
        fun = reentrancy > 0 or callinjection
        if reentrancy > 0 or callinjection:
            f = open(SUBTRACE_ANALYSIS_FILEPATH, "a+")
            m = subtrace_graph.graph['transaction_hash']
            self.print_and_write(f, m)
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
                    trace_id = data['id'][index]
                    parent_trace_id = data['parent_trace_id'][index]
                    gas_used = data['gas_used'][index]
                    attr = data['attr'][index]
                    if parent_trace_id == None or gas_used == None or len(
                            attr) != 10:
                        continue
                    parent_trace_input = self.local.read_from_database(
                        table="traces",
                        columns="input",
                        clause="where rowid = :trace_id",
                        vals={
                            'trace_id': parent_trace_id
                        }).fetchone()["input"]
                    if len(parent_trace_input) > 10 and gas_used > 0:
                        method_hash = attr[2:]
                        if method_hash in parent_trace_input:
                            callinjection = True
                            f = open(SUBTRACE_ANALYSIS_FILEPATH, "a+")
                            m = "--------------------"
                            self.print_and_write(f, m)
                            m = cycle[0]
                            self.print_and_write(f, m)
                            m = "trace id: " + str(
                                trace_id) + " parent trace id: " + str(
                                    parent_trace_id)
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
        index = len(edges) - 1
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
            edges.append((cycle[index - 1], cycle[index]))
            index += 1
        edges.append((cycle[index - 1], cycle[0]))
        return edges


def main():
    builder = DiGraphBuilder()
    analyzer = GraphAnalyzer(builder)

    from_time = datetime(2018, 10, 7, 0, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 0, 0)

    print("building subtrace graphs from", time_to_str(from_time), "to",
          time_to_str(to_time))
    date = from_time.date()
    while date <= to_time.date():
        print(date_to_str(date))
        analyzer.load_database(DB_PATH, date)
        graphs = builder.build_digraph_on_subtraces()
        print(f"analyzing {len(graphs)} graphs...")
        fun = False
        count = 0
        for trace_graph in graphs:
            analyzer.analyze_subtrace_graph(trace_graph)
            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()

        del graphs
        date += timedelta(days=1)

    import IPython
    IPython.embed()


if __name__ == "__main__":
    main()