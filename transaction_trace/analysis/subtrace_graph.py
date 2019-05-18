import binascii
import logging
from collections import defaultdict

import networkx as nx
from web3 import Web3

from ..local import EthereumDatabase
from .trace_util import TraceUtil

l = logging.getLogger("transaction-trace.analysis.SubtraceGraph")


class SubtraceGraph:
    def __init__(self, db_conn):
        self._db_conn = db_conn

    def _subtrace_graph_by_tx(self, tx_hash, subtraces, traces):
        subtrace_graph = nx.DiGraph(
            transaction_hash=tx_hash, date=self._db_conn.date)
        for trace_id in subtraces:
            parent_trace_id = subtraces[trace_id]

            trace = traces[trace_id]
            if trace["status"] == 0:
                continue
            from_address = trace["from_address"]
            to_address = trace["to_address"]
            trace_type = trace["trace_type"]
            trace_input = trace["input"]

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


key_funcs = {
    "owner": {
        "0x13af4035": ("setOwner(address)", 34),
        "0xe46dcfeb": ("initWallet(address[],uint256,uint256)", 290),
        "0xf2fde38b": ("transferOwnership(address)", 34),
        "0xf1739cae": ("transferProxyOwnership(address)", 34),
        "0xa6f9dae1": ("changeOwner(address)", 34),
        "0x2af4c31e": ("changeOwnership(address)", 34),
        "0x7065cb48": ("addOwner(address)", 34),
        "0xc57c5f60": ("initMultiowned(address[],uint256)", 290),
        "0x1b580620": ("setOwner1(address)", 34),
        "0x5825884f": ("setOwner2(address)", 34),
        "0xa39a45b7": ("replaceOwner(address)", 34),
        "0xe20056e6": ("replaceOwner(address,address)", 98),
        "0x0952c504": ("requestOwnershipTransfer(address)", 34),
        "0x2877a49c": ("AddOwnership(address)", 34),
        "0x4f60f334": ("multiAccessAddOwner(address)", 34),
        "0x880cdc31": ("updateOwner(address)", 34),
        "0x85952454": ("newOwner(address)", 34),
    },
    "token": {
        "0xa9059cbb": ("transfer(address,uint256)", 34),
        "0x23b872dd": ("transferFrom(address,address,uint256)", 98),
        "0x095ea7b3": ("approve(address,uint256)", 34),
        "0x42842e0e": ("safeTransferFrom(address,address,uint256)", 98),
        "0xb88d4fde": ("safeTransferFrom(address,address,uint256,bytes)", 98),
        "0x40c10f19": ("mint(address,uint256)", 34),
        "0xb5e73249": ("mint(address,uint256,bool,uint32)", 34),
        "0xf0dda65c": ("mintTokens(address,uint256)", 34),
        "0x79c65068": ("mintToken(address,uint256)", 34),
        "0x449a52f8": ("mintTo(address,uint256)", 34),
        "0x2f81bc71": ("multiMint(address[],uint256[])", 226)
    }
}


class SubtraceGraphAnalyzer:
    def __init__(self, subtrace_graph, log_file):
        self.subtrace_graph = subtrace_graph
        self.log_file = log_file

        self.analysis_cache = dict()
        self.analysis_cache["key_funcs"] = dict()
        for func_type in key_funcs:
            for func_hash in key_funcs[func_type]:
                func_name = key_funcs[func_type][func_hash][0]
                benefit_pos = key_funcs[func_type][func_hash][1]
                func_hex = binascii.b2a_hex(func_name.encode("utf-8")).decode()
                self.analysis_cache["key_funcs"][func_hash] = (
                    func_name, func_hex, benefit_pos)

    def record_abnormal_detail(self, detail):
        print(detail, file=self.log_file)

    def get_edges_from_cycle(self, cycle):
        edges = list()
        for index in range(0, len(cycle)-1):
            edges.append((cycle[index], cycle[index+1]))
        edges.append((cycle[-1], cycle[0]))
        return edges

    def find_call_injection(self, graph, cycles, key_func: bool = True):
        ABNORMAL_TYPE = "CallInjection"

        l.debug("Searching for Call Injection")

        tx_hash = graph.graph["transaction_hash"]
        detail_list = set()
        for cycle in cycles:
            # call injection has to call another method in the same contract
            # which forms self-loop in our graph
            if len(cycle) != 1:
                continue

            data = graph.get_edge_data(cycle[0], cycle[0])
            for call_trace in data["call_traces"]:
                trace_id = call_trace["trace_id"]
                parent_trace_id = call_trace["parent_trace_id"]
                gas_used = call_trace["gas_used"]
                callee = call_trace["callee"]
                caller_address = self.analysis_cache["traces"][tx_hash][parent_trace_id]["from_address"]
                call_type = self.analysis_cache["traces"][tx_hash][trace_id]["call_type"]
                if call_type == "delegatecall":
                    continue

                if parent_trace_id == None or gas_used == None or not callee.startswith("0x"):
                    continue
                callee = TraceUtil.get_callee(
                    self.analysis_cache["traces"][tx_hash][trace_id]["trace_type"], self.analysis_cache["traces"][tx_hash][trace_id]["input"])
                parent_trace_input = self.analysis_cache["traces"][tx_hash][parent_trace_id]["input"][10:]
                injection = list(self._find_call_injection(
                    tx_hash, trace_id, parent_trace_input, callee, key_func))

                if len(injection) > 0:
                    l.info(
                        "Call injection found for %s with entry %s behavior: %s",
                        tx_hash, cycle[0], injection)
                    detail = {
                        "date": graph.graph["date"],
                        "abnormal_type": ABNORMAL_TYPE,
                        "tx_hash": tx_hash,
                        "entry": cycle[0],
                        "caller": caller_address,
                        "call_type": call_type,
                        "func": callee,
                        "parent_func": TraceUtil.get_callee(self.analysis_cache["traces"][tx_hash][parent_trace_id]["trace_type"], parent_trace_input),
                        "behavior": injection
                    }
                    detail_list.add(str(detail))

        # check call injection on delegate call
        for trace_id in self.analysis_cache["subtraces"][tx_hash]:
            parent_trace_id = self.analysis_cache["subtraces"][tx_hash][trace_id]
            trace_type = self.analysis_cache["traces"][tx_hash][trace_id]["trace_type"]
            call_type = self.analysis_cache["traces"][tx_hash][trace_id]["call_type"]
            status = self.analysis_cache["traces"][tx_hash][trace_id]["status"]
            from_address = self.analysis_cache["traces"][tx_hash][trace_id]["from_address"]
            to_address = self.analysis_cache["traces"][tx_hash][trace_id]["to_address"]
            if status == 1 and trace_type == "call" and (call_type == "delegatecall" and from_address != to_address or call_type == "callcode"):
                callee = TraceUtil.get_callee(
                    trace_type, self.analysis_cache["traces"][tx_hash][trace_id]["input"])
                while parent_trace_id != None:
                    parent_trace_type = self.analysis_cache["traces"][tx_hash][parent_trace_id]["trace_type"]
                    parent_call_type = self.analysis_cache["traces"][tx_hash][parent_trace_id]["call_type"]
                    if parent_trace_type == "call" and (parent_call_type == "delegatecall" or parent_call_type == "callcode"):
                        parent_trace_id = self.analysis_cache["subtraces"][tx_hash][parent_trace_id]
                    else:
                        break

                callee = TraceUtil.get_callee(
                    self.analysis_cache["traces"][tx_hash][trace_id]["trace_type"], self.analysis_cache["traces"][tx_hash][trace_id]["input"])
                parent_trace_input = self.analysis_cache["traces"][tx_hash][parent_trace_id]["input"]
                injection = list(self._find_call_injection(
                    tx_hash, trace_id, parent_trace_input, callee, key_func))

                if len(injection) > 0:
                    entry = self.analysis_cache["traces"][tx_hash][parent_trace_id]["to_address"]
                    caller_address = self.analysis_cache["traces"][tx_hash][parent_trace_id]["from_address"]
                    l.info(
                        "Call injection found for %s with entry %s behavior: %s",
                        tx_hash, entry, injection)
                    detail = {
                        "date": graph.graph["date"],
                        "abnormal_type": ABNORMAL_TYPE,
                        "tx_hash": tx_hash,
                        "entry": entry,
                        "caller": caller_address,
                        "call_type": call_type,
                        "func": callee,
                        "parent_func": TraceUtil.get_callee(parent_trace_type, parent_trace_input),
                        "behavior": injection
                    }
                    detail_list.add(str(detail))

        for detail in detail_list:
            self.record_abnormal_detail(detail)

    def _find_call_injection(self, tx_hash, trace_id, parent_trace_input, callee, key_func: bool):
        injection = set()
        if len(parent_trace_input) > 10:
            if callee[2:] in parent_trace_input or callee in self.analysis_cache["key_funcs"] and self.analysis_cache["key_funcs"][callee][1] in parent_trace_input:
                if not key_func:
                    injection.add(None)
                else:
                    stack = list()
                    stack.append(trace_id)
                    while len(stack) > 0:
                        s_trace_id = stack.pop()
                        trace_input = self.analysis_cache["traces"][tx_hash][s_trace_id]["input"]
                        trace_type = self.analysis_cache["traces"][tx_hash][s_trace_id]["trace_type"]
                        to_address = self.analysis_cache["traces"][tx_hash][s_trace_id]["to_address"]
                        ancestors = None
                        if trace_type == "suicide":
                            ancestors = TraceUtil.get_all_ancestors(
                                self.analysis_cache["traces"][tx_hash], self.analysis_cache["subtraces"][tx_hash], trace_id)
                            if to_address in ancestors:
                                injection.add("suicide")
                        elif trace_type == "call" and len(trace_input) > 9 and trace_input[:10] in self.analysis_cache["key_funcs"]:
                            ancestors = TraceUtil.get_all_ancestors(
                                self.analysis_cache["traces"][tx_hash], self.analysis_cache["subtraces"][tx_hash], trace_id)
                            benefit_pos = self.analysis_cache["key_funcs"][trace_input[:10]][2]
                            benefit_node = "0x" + \
                                trace_input[benefit_pos: benefit_pos + 40]
                            if benefit_node in ancestors:
                                injection.add(
                                    self.analysis_cache["key_funcs"][trace_input[:10]][0])
                        trace_value = Web3.fromWei(
                            self.analysis_cache["traces"][tx_hash][s_trace_id]["value"], "ether")
                        if trace_value > 0:
                            if ancestors == None:
                                ancestors = TraceUtil.get_all_ancestors(
                                    self.analysis_cache["traces"][tx_hash], self.analysis_cache["subtraces"][tx_hash], trace_id)
                            if to_address in ancestors:
                                injection.add("ethTransfer")
                        if s_trace_id in self.analysis_cache["tx_trees"][tx_hash]:
                            children = self.analysis_cache["tx_trees"][tx_hash][s_trace_id]
                            stack.extend(children)
        return injection

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
                out_edges = graph.out_edges(edge[1])
                for out_edge in out_edges:
                    out_edge_data = graph.get_edge_data(*out_edge)
                    if "suicide" in [call_trace["callee"] for call_trace in out_edge_data["call_traces"]]:
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
            if "tx_trees" not in self.analysis_cache:
                self.analysis_cache["tx_trees"] = TraceUtil.build_call_tree(
                    subtraces)

            self.find_reentrancy(subtrace_graph, cycles, eth_lost)
            self.find_call_injection(subtrace_graph, cycles, False)
            self.find_bonus_hunitng(subtrace_graph)
