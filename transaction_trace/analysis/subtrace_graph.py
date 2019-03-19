import logging
import os
import time
from collections import defaultdict

import networkx as nx

from ..local.ethereum_database import EthereumDatabase

l = logging.getLogger("transaction-trace.analysis.SubtraceGraph")


class SubtraceGraph:
    def __init__(self, db_conn):
        self._db_conn = db_conn

    def _subtrace_graph_by_tx(self, tx_hash, subtraces, traces):
        subtrace_graph = nx.DiGraph(transaction_hash=tx_hash)
        for subtrace in subtraces:
            trace_id = subtrace["trace_id"]
            parent_trace_id = subtrace["parent_trace_id"]

            trace = traces[trace_id]
            from_address = trace["from_address"]
            to_address = trace["to_address"]
            trace_type = trace["trace_type"]
            gas_used = trace["gas_used"]
            trace_input = trace["input"]

            # this can only be `call`, `create` or `suicide`
            # when trace_type is `call`, record callee"s signature
            if trace_type == "call":
                if len(trace_input) > 9:
                    callee = trace_input[:10]
                else:
                    callee = "fallback"
            else:
                callee = trace_type

            subtrace_graph.add_edge(from_address, to_address)
            if "call_trace" not in subtrace_graph[from_address][to_address]:
                subtrace_graph[from_address][to_address]["call_trace"] = list()

            subtrace_graph[from_address][to_address]["call_trace"].append({
                "trace_id": trace_id,
                "parent_trace_id": parent_trace_id,
                "trace_type": trace_type,
                "gas_used": gas_used,
                "callee": callee,
            })

        if subtrace_graph.number_of_edges() < 2:  # ignore contracts which are never used
            return None

        return subtrace_graph

    def subtrace_graphs_by_tx(self):
        l.info("Prepare data for graph construction: %s", self._db_conn)

        traces = defaultdict(dict)
        for row in self._db_conn.read_traces(with_rowid=True):
            tx_hash = row["transaction_hash"]
            rowid = row["rowid"]
            traces[tx_hash][rowid] = row

        subtraces = defaultdict(list)
        for row in self._db_conn.read_subtraces():
            tx_hash = row["transaction_hash"]
            subtraces[tx_hash].append(row)

        l.info("Begin graph construction")
        for tx_hash in traces:
            l.debug("Constructing graph for tx %s", tx_hash)
            subtrace_graph = self._subtrace_graph_by_tx(
                tx_hash, subtraces[tx_hash], traces[tx_hash])

            if subtrace_graph == None:
                continue

            yield subtrace_graph, traces


class SubtraceGraphAnalyzer:
    def __init__(self, subtrace_graph, log_folder):
        self.subtrace_graph = subtrace_graph

        log_filepath = os.path.join(
            log_folder, "subtrace-graph-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S')))
        self.log_file = open(log_filepath, "w+")

    def __del__(self):
        self.log_file.close()

    def record_abnormal_detail(self, abnormal_type, detail):
        print("[%s]: %s" % (abnormal_type, detail), file=self.log_file)

    def get_edges_from_cycle(self, cycle):
        edges = list()
        for index in range(1, len(cycle)):
            edges.append((cycle[index - 1], cycle[index]))
        edges.append((cycle[index - 1], cycle[0]))
        return edges

    def find_call_injection(self, graph, traces, cycles):
        ABNORMAL_TYPE = "CallInjection"

        l.debug("Searching for Call Injection")

        tx_hash = graph.graph["transaction_hash"]
        for cycle in cycles:
            # call injection has to call another method in the same contract
            # which forms self-loop in our graph
            if len(cycle) != 1:
                continue

            data = graph.get_edge_data(cycle[0], cycle[0])
            for call_trace in data["call_trace"]:
                trace_id = call_trace["trace_id"]
                parent_trace_id = call_trace["parent_trace_id"]
                gas_used = call_trace["gas_used"]
                callee = call_trace["callee"]

                if parent_trace_id == None or gas_used == None or not callee.startswith("0x"):
                    continue

                parent_trace_input = traces[tx_hash][parent_trace_id]["input"]
                if len(parent_trace_input) > 10 and gas_used > 0:
                    method_hash = callee[2:]
                    if method_hash in parent_trace_input[10:]:
                        l.info("Call injection found for %s with entry %s",
                               tx_hash, cycle[0])
                        self.record_abnormal_detail(
                            ABNORMAL_TYPE, "tx: %s entry: %s" % (tx_hash, cycle[0]))

    def _find_reentrancy_by_cycle(self, graph, cycle):
        edges = self.get_edges_from_cycle(cycle)
        index = len(edges) - 1
        trace_id = list()
        while index > -2:
            data = graph.get_edge_data(*edges[index])
            if len(trace_id) == 0:
                trace_id = data["parent_trace_id"]
            else:
                parent_id = list()
                for id in trace_id:
                    if id in data["id"]:
                        parent_id.append(
                            data["parent_trace_id"][data["id"].index(id)])
                trace_id = parent_id
                if len(trace_id) == 0:
                    break
            index -= 1
        return (len(edges), len(trace_id))

    def find_reentrancy(self, graph, cycles):
        ABNORMAL_TYPE = "Reentrancy"

        l.debug("Searching for Reentrancy")

        if len(cycles) == 0:
            return

        tx_hash = graph.graph["transaction_hash"]
        for cycle in cycles:
            (edge_count, count) = self._find_reentrancy_by_cycle(graph, cycle)
            if edge_count < 2:
                continue
            elif count > 5:
                l.info("Reentrancy found for %s with loop count %d", tx_hash, count)
                self.record_abnormal_detail(
                    ABNORMAL_TYPE, "tx: %s loop count: %d loop nodes: %s" % (tx_hash, count, cycle))

    def find_bonus_hunitng(self, graph):
        ABNORMAL_TYPE = "BonusHunting"

        hunting_times = 0
        edges = list(graph.edges())
        for e in edges:
            data = graph.get_edge_data(*e)
            if "create" in data["callee"]:
                out_edges = graph.out_edges(e[1])
                for out_edge in out_edges:
                    out_edge_data = graph.get_edge_data(*out_edge)
                    if "suicide" in out_edge_data["callee"]:
                        hunting_times += 1
                        break
        if hunting_times > 5:
            m = "Bonus Hunting"
            self.print_and_write(m)
            m = f"hunting times: {hunting_times}"
            self.print_and_write(m)
            return True
        return False

    def find_honeypot(self, graph):
        raise NotImplementedError("To be implemented")

    def find_mishandled_exception(self, graph):
        raise NotImplementedError("To be implemented")

    def find_missing_libraries(self, graph):
        raise NotImplementedError("To be implemented")

    def find_all_abnormal_behaviors(self):
        for subtrace_graph, traces in self.subtrace_graph.subtrace_graphs_by_tx():
            l.debug("Searching for cycles in graph")
            cycles = list(nx.simple_cycles(subtrace_graph))

            # reentrancy = self.find_reentrancy(subtrace_graph, cycles)
            call_injection = self.find_call_injection(
                subtrace_graph, traces, cycles)
            # bonus_hunting = self.find_bonus_hunitng(subtrace_graph)
