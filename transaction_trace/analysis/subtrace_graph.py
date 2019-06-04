import binascii
import logging
from collections import defaultdict

import networkx as nx
from web3 import Web3

from ..local import EthereumDatabase
from .trace_util import TraceUtil
from .trace_analysis import TraceAnalysis
from ..datetime_utils import time_to_str

l = logging.getLogger("transaction-trace.analysis.SubtraceGraph")


class SubtraceGraph:
    def __init__(self, db_conn):
        self._db_conn = db_conn

    def _subtrace_graph_by_tx(self, tx_hash, subtraces, traces):
        subtrace_graph = nx.DiGraph(
            transaction_hash=tx_hash, date=self._db_conn.date, time="", caller="0x")
        for trace_id in subtraces:
            parent_trace_id = subtraces[trace_id]
            if parent_trace_id == None:
                subtrace_graph.graph["caller"] = traces[trace_id]["from_address"]

            trace = traces[trace_id]
            if trace["status"] == 0:
                continue
            from_address = trace["from_address"]
            to_address = trace["to_address"]
            trace_type = trace["trace_type"]
            trace_input = trace["input"]
            time = trace["block_timestamp"]
            if subtrace_graph.graph["time"] == "":
                subtrace_graph.graph["time"] = time_to_str(time)

            # this can only be `call`, `create` or `suicide`
            # when trace_type is `call`, record callee"s signature
            callee = TraceUtil.get_callee(trace_type, trace_input)

            subtrace_graph.add_edge(from_address, to_address)
            if "call_traces" not in subtrace_graph[from_address][to_address]:
                subtrace_graph[from_address][to_address]["call_traces"] = list()

            subtrace_graph[from_address][to_address]["call_traces"].append({
                "trace_id": trace_id,
                "parent_trace_id": parent_trace_id,
                "trace_type": trace_type,
                "callee": callee,
                "gas_used": trace["gas_used"],
                "trace_address": trace["trace_address"],
            })

        if subtrace_graph.number_of_edges() < 2:  # ignore contracts which are never used
            return None

        return subtrace_graph

    def subtrace_graphs_by_tx(self):
        l.info("Prepare data: %s", self._db_conn)

        traces = defaultdict(dict)
        for row in self._db_conn.read_traces(with_rowid=True):
            tx_hash = row["transaction_hash"]
            rowid = row["rowid"]
            traces[tx_hash][rowid] = row

        subtraces = defaultdict(dict)
        for row in self._db_conn.read_subtraces():
            tx_hash = row["transaction_hash"]
            trace_id = row["trace_id"]
            parent_trace_id = row["parent_trace_id"]
            subtraces[tx_hash][trace_id] = parent_trace_id

        l.info("Begin graph construction")
        for tx_hash in traces:
            l.debug("Constructing graph for tx %s", tx_hash)
            subtrace_graph = self._subtrace_graph_by_tx(
                tx_hash, subtraces[tx_hash], traces[tx_hash])

            if subtrace_graph == None:
                continue

            yield subtrace_graph, traces, subtraces


class SubtraceGraphAnalyzer(TraceAnalysis):
    def __init__(self, subtrace_graph, log_file):
        super(SubtraceGraphAnalyzer, self).__init__(log_file)
        self.subtrace_graph = subtrace_graph
        self.analysis_cache = dict()

    def get_edges_from_cycle(self, cycle):
        edges = list()
        for index in range(0, len(cycle)-1):
            edges.append((cycle[index], cycle[index+1]))
        edges.append((cycle[-1], cycle[0]))
        return edges

    def count_subtrace_cycle(self, graph, cycle):
        def extract_trace_info(graph, u, v):
            data = graph.get_edge_data(u, v)
            for call_trace in data["call_traces"]:
                trace_id = call_trace["trace_id"]
                parent_trace_id = call_trace["parent_trace_id"]
                yield parent_trace_id, trace_id

        call_tree = nx.DiGraph()
        for i in range(0, len(cycle)-1):
            for parent_trace_id, trace_id in extract_trace_info(
                    graph, cycle[i], cycle[i+1]):
                if parent_trace_id is not None:
                    call_tree.add_edge(
                        parent_trace_id, trace_id, addr_from=cycle[i], addr_to=cycle[i+1])
        for parent_trace_id, trace_id in extract_trace_info(graph, cycle[-1], cycle[0]):
            if parent_trace_id is not None:
                call_tree.add_edge(parent_trace_id, trace_id,
                                   addr_from=cycle[-1], addr_to=cycle[0])

        cycle_count = defaultdict(int)
        max_cycle_count = -1
        for leaf in (x for x in call_tree.nodes() if call_tree.out_degree(x) == 0):
            pred = list(call_tree.predecessors(leaf))[0]
            loop_start = call_tree[pred][leaf]["addr_to"]

            itr = pred
            while call_tree.in_degree(itr) > 0:
                pred = list(call_tree.predecessors(itr))[0]
                if call_tree[pred][itr]["addr_from"] == loop_start:
                    cycle_count[leaf] += 1
                itr = pred

            if cycle_count[leaf] > max_cycle_count:
                max_cycle_count = cycle_count[leaf]

        return cycle_count, max_cycle_count

    def find_reentrancy(self, graph, cycles, eth=None):
        ABNORMAL_TYPE = "Reentrancy"

        l.debug("Searching for Reentrancy")

        if len(cycles) == 0:
            return

        f = False
        tx_hash = graph.graph["transaction_hash"]
        for cycle in cycles:
            if len(cycle) < 2:
                continue

            _, cycle_count = self.count_subtrace_cycle(graph, cycle)
            if cycle_count > 5:
                l.info("Reentrancy found for %s with cycle count %d",
                       tx_hash, cycle_count)
                detail = {
                    "date": graph.graph["date"],
                    "abnormal_type": ABNORMAL_TYPE,
                    "tx_hash": tx_hash,
                    "cycle_count": cycle_count,
                    "cycle_nodes": cycle
                }
                self.record_abnormal_detail(detail)
                f = True
        if f and eth != None:
            eth_transfer = defaultdict(lambda: defaultdict(int))
            for trace in self.analysis_cache["traces"][tx_hash].values():
                value = trace["value"]
                from_address = trace["from_address"]
                to_address = trace["to_address"]
                if value > 0:
                    eth_transfer[from_address][to_address] += float(
                        Web3.fromWei(value, "ether"))
            eth_nodes = defaultdict(int)
            for from_address in eth_transfer:
                for to_address in eth_transfer[from_address]:
                    value = eth_transfer[from_address][to_address]
                    eth_nodes[from_address] -= value
                    eth_nodes[to_address] += value
            eth[tx_hash] = eth_nodes

            lost = 0
            for node in eth[tx_hash]:
                if eth[tx_hash][node] < lost:
                    lost = eth[tx_hash][node]
            l.info("Reentrancy eth lost for %s: %d", tx_hash, lost)
            detail = {
                "date": graph.graph["date"],
                "abnormal_type": ABNORMAL_TYPE,
                "tx_hash": tx_hash,
                "eth_lost": lost
            }
            self.record_abnormal_detail(detail)

    def find_bonus_hunitng(self, graph):
        ABNORMAL_TYPE = "BonusHunting"

        tx_hash = graph.graph["transaction_hash"]

        hunting_times = 0
        for edge in graph.edges():
            data = graph.get_edge_data(*edge)
            if "create" in [call_trace["callee"] for call_trace in data["call_traces"]]:
                profit = False
                suicide = False
                out_edges = graph.out_edges(edge[1])
                for out_edge in out_edges:
                    out_edge_data = graph.get_edge_data(*out_edge)
                    for call_trace in out_edge_data["call_traces"]:
                        if call_trace["callee"] == "suicide":
                            suicide =True
                        elif call_trace["callee"] == "0xa9059cbb" and int(self.analysis_cache["traces"][tx_hash][call_trace["trace_id"]]["input"][74:], base=16) > 0:
                            profit = True
                    if profit and suicide:
                        hunting_times += 1
                        break
        if hunting_times > 5:
            l.info("Bonus hunting found for %s with hunting times %d",
                   tx_hash, hunting_times)
            detail = {
                "date": graph.graph["date"],
                "abnormal_type": ABNORMAL_TYPE,
                "tx_hash": tx_hash,
                "hunting_times": hunting_times
            }
            self.record_abnormal_detail(detail)

    def find_all_abnormal_behaviors(self, eth_lost=None):
        for subtrace_graph, traces, subtraces in self.subtrace_graph.subtrace_graphs_by_tx():
            l.debug("Searching for cycles in graph")
            cycles = list(nx.simple_cycles(subtrace_graph))

            if "traces" not in self.analysis_cache:
                self.analysis_cache["traces"] = traces
            if "subtraces" not in self.analysis_cache:
                self.analysis_cache["subtraces"] = subtraces

            self.find_reentrancy(subtrace_graph, cycles, eth_lost)
            self.find_bonus_hunitng(subtrace_graph)
