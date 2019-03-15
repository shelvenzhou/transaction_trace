import networkx as nx
from local.ethereum_database import EthereumDatabase
from graph_builder import DiGraphBuilder
from datetime_utils import time_to_str, date_to_str, month_to_str
from datetime import datetime, timedelta
import sys

DB_PATH = "/Users/Still/Desktop/w/db/"
ANALYSIS_LOG_PATH = "logs/"


class GraphAnalyzer(object):
    def __init__(self, graph_builder: DiGraphBuilder):
        self.local = None
        self.log_file = None
        self.builder = graph_builder

    def load_database(self, db_path, date):
        self.log_file = open(f"{ANALYSIS_LOG_PATH}graph_analysis_{month_to_str(date)}", "a+")
        self.local = EthereumDatabase(
            f"{db_path}raw/bigquery_ethereum_{date_to_str(date)}.sqlite3")
        self.builder.load_database(db_path, date)

    def print_and_write(self, msg):
        print(msg)
        self.log_file.write(msg + "\n")

    def analyze_subtrace_graph(self, subtrace_graph):
        cycles = list(nx.simple_cycles(subtrace_graph))
        reentrancy = self.check_reentrancy(subtrace_graph, cycles)
        callinjection = self.check_callinjection(subtrace_graph, cycles)
        bonus_hunting = self.check_bonus_hunitng(subtrace_graph)
        if reentrancy > 0 or callinjection or bonus_hunting:
            m = "tx_hash: " + subtrace_graph.graph['transaction_hash'] + "\n"
            self.print_and_write(m)


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
                            m = "Call Injection"
                            self.print_and_write(m)
                            m = cycle[0]
                            self.print_and_write(m)
                            m = "trace id: " + str(
                                trace_id) + " parent trace id: " + str(
                                    parent_trace_id)
                            self.print_and_write(m)
                            break

        return callinjection

    def check_reentrancy(self, graph, cycles):
        reentrancy = -1
        if len(cycles) == 0:
            return reentrancy

        for cycle in cycles:
            (edge_count, count) = self.check_reentrancy_bycycle(graph, cycle)
            if edge_count < 2:
                reentrancy = 0
            else:
                if count > 5:
                    reentrancy = 1
                    m = "Reentrancy"
                    self.print_and_write(m)
                    m = "trace cycle found, number of turns: " + str(count)
                    self.print_and_write(m)
                    for node in cycle:
                        m = node + "->"
                        self.print_and_write(m)
                    break
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
        return (len(edges), len(trace_id))

    def check_bonus_hunitng(self, graph):
        hunting_times = 0
        edges = list(graph.edges())
        for e in edges:
            data = graph.get_edge_data(*e)
            if "create" in data['attr']:
                out_edges = graph.out_edges(e[1])
                for out_edge in out_edges:
                    out_edge_data = graph.get_edge_data(*out_edge)
                    if "suicide" in out_edge_data['attr']:
                        hunting_times += 1
                        break
        if hunting_times > 5:
            m = "Bonus Hunting"
            self.print_and_write(m)
            m = f"hunting times: {hunting_times}"
            self.print_and_write(m)
            return True
        return False


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
        analyzer.load_database(DB_PATH, date)
        analyzer.print_and_write(date_to_str(date) + '\n')
        graphs = builder.build_digraph_on_subtraces()
        print(f"analyzing {len(graphs)} graphs...")
        count = 0
        for trace_graph in graphs:
            analyzer.analyze_subtrace_graph(trace_graph)
            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()

        del graphs
        analyzer.log_file.close()
        date += timedelta(days=1)

    import IPython
    IPython.embed()


if __name__ == "__main__":
    main()