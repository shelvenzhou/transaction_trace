import logging
from collections import defaultdict

import networkx as nx

from ..local.ethereum_database import EthereumDatabase, SimpleAnalysisDatabase

l = logging.getLogger("transaction-trace.analysis.SubtraceGraph")


class SubtraceGraph:
    def __init__(self, db_conn):
        self._db_conn = db_conn

    def _subtrace_graph_by_tx(self, tx_hash, subtraces, traces):
        subtrace_graph = nx.DiGraph(transaction_hash=tx_hash, date=self._db_conn.date())
        for subtrace in subtraces:
            trace_id = subtrace["trace_id"]
            parent_trace_id = subtrace["parent_trace_id"]

            trace = traces[trace_id]
            from_address = trace["from_address"]
            to_address = trace["to_address"]
            trace_type = trace["trace_type"]
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
            if "call_traces" not in subtrace_graph[from_address][to_address]:
                subtrace_graph[from_address][to_address]["call_traces"] = list(
                )

            subtrace_graph[from_address][to_address]["call_traces"].append({
                "trace_id":
                trace_id,
                "parent_trace_id":
                parent_trace_id,
                "trace_type":
                trace_type,
                "callee":
                callee,
                "gas_used":
                trace["gas_used"],
                "trace_address":
                trace["trace_address"],
            })

        if subtrace_graph.number_of_edges(
        ) < 2:  # ignore contracts which are never used
            return None

        return subtrace_graph

    def subtrace_graphs_by_tx(self):
        l.info("Prepare data: %s", self._db_conn)

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

            yield subtrace_graph, traces, subtraces


class SubtraceGraphAnalyzer:
    def __init__(self, subtrace_graph, db_folder, log_file):
        self.subtrace_graph = subtrace_graph
        self.log_file = log_file
        self.analysis_db = SimpleAnalysisDatabase(
            f"{db_folder}/bigquery_ethereum_analysis.sqlite3")
        self.analysis_cache = dict()

    def record_abnormal_detail(self, date, abnormal_type, detail):
        print("[%s][%s]: %s" % (date, abnormal_type, detail), file=self.log_file)

    def get_edges_from_cycle(self, cycle):
        edges = list()
        for index in range(0, len(cycle) - 1):
            edges.append((cycle[index], cycle[index + 1]))
        edges.append((cycle[-1], cycle[0]))
        return edges

    def find_call_injection(self, graph, cycles):
        ABNORMAL_TYPE = "CallInjection"

        l.debug("Searching for Call Injection")

        if "key_func" not in self.analysis_cache:
            funcs = self.analysis_db.read(
                table="func2hash",
                columns="func_name, func_hash",
                conditions="WHERE func_type = 'owner'")
            func_dict = dict()
            for func in funcs:
                func_dict[func[1]] = func[0]
            self.analysis_cache["key_func"] = func_dict
            
        tx_hash = graph.graph["transaction_hash"]
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

                if parent_trace_id == None or gas_used == None or not callee.startswith(
                        "0x"):
                    continue

                parent_trace_input = self.analysis_cache["traces"][tx_hash][
                    parent_trace_id]["input"]
                if len(parent_trace_input) > 10 and gas_used > 0:
                    method_hash = callee
                    if method_hash[2:] in parent_trace_input[
                            10:]:
                        injection_type = None
                        if method_hash in self.analysis_cache["key_func"]:
                            func_name = self.analysis_cache["key_func"][method_hash]
                            injection_type = f"func: {func_name}"
                        if trace_id in self.analysis_cache["tx_trees"][tx_hash]:
                            childs_traces_id = self.analysis_cache["tx_trees"][tx_hash][trace_id]
                            for child in childs_traces_id:
                                eth_value = self.analysis_cache["traces"][tx_hash][child]["value"]
                                if eth_value > 0:
                                    injection_type = f"eth transfer: {eth_value}"
                                    break

                        if injection_type != None:
                            l.info("Call injection found for %s with entry %s, %s",
                                tx_hash, cycle[0], injection_type)
                            self.record_abnormal_detail(
                                graph.graph["date"],
                                ABNORMAL_TYPE,
                                "tx: %s entry: %s %s" % (tx_hash, cycle[0], injection_type))

    def count_subtrace_cycle(self, graph, cycle):
        def extract_trace_info(graph, u, v):
            data = graph.get_edge_data(u, v)
            for call_trace in data["call_traces"]:
                trace_id = call_trace["trace_id"]
                parent_trace_id = call_trace["parent_trace_id"]
                yield parent_trace_id, trace_id

        call_tree = nx.DiGraph()
        for i in range(0, len(cycle) - 1):
            for parent_trace_id, trace_id in extract_trace_info(
                    graph, cycle[i], cycle[i + 1]):
                if parent_trace_id is not None:
                    call_tree.add_edge(
                        parent_trace_id,
                        trace_id,
                        addr_from=cycle[i],
                        addr_to=cycle[i + 1])
        for parent_trace_id, trace_id in extract_trace_info(
                graph, cycle[-1], cycle[0]):
            if parent_trace_id is not None:
                call_tree.add_edge(
                    parent_trace_id,
                    trace_id,
                    addr_from=cycle[-1],
                    addr_to=cycle[0])

        cycle_count = defaultdict(int)
        max_cycle_count = -1
        for leaf in (x for x in call_tree.nodes()
                     if call_tree.out_degree(x) == 0):
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

    def find_reentrancy(self, graph, cycles):
        ABNORMAL_TYPE = "Reentrancy"

        l.debug("Searching for Reentrancy")

        if len(cycles) == 0:
            return

        tx_hash = graph.graph["transaction_hash"]
        for cycle in cycles:
            if len(cycle) < 2:
                continue

            _, cycle_count = self.count_subtrace_cycle(graph, cycle)
            if cycle_count > 5:
                l.info("Reentrancy found for %s with cycle count %d", tx_hash,
                       cycle_count)
                self.record_abnormal_detail(
                    graph.graph["date"],
                    ABNORMAL_TYPE, "tx: %s cycle count: %d cycle nodes: %s" %
                    (tx_hash, cycle_count, cycle))

    def find_bonus_hunitng(self, graph):
        ABNORMAL_TYPE = "BonusHunting"

        tx_hash = graph.graph["transaction_hash"]

        hunting_times = 0
        for edge in graph.edges():
            data = graph.get_edge_data(*edge)
            if "create" in [
                    call_trace["callee"] for call_trace in data["call_traces"]
            ]:
                out_edges = graph.out_edges(edge[1])
                for out_edge in out_edges:
                    out_edge_data = graph.get_edge_data(*out_edge)
                    if "suicide" in [
                            call_trace["callee"]
                            for call_trace in out_edge_data["call_traces"]
                    ]:
                        hunting_times += 1
                        break
        if hunting_times > 5:
            l.info("Bonus hunting found for %s with hunting times %d", tx_hash,
                   hunting_times)
            self.record_abnormal_detail(
                graph.graph["date"],
                ABNORMAL_TYPE,
                "tx: %s hunting times: %d" % (tx_hash, hunting_times))

    def find_honeypot(self, graph):
        raise NotImplementedError("To be implemented")

    def find_mishandled_exception(self, graph):
        raise NotImplementedError("To be implemented")

    def find_missing_libraries(self, graph):
        raise NotImplementedError("To be implemented")

    def build_call_tree(self, subtraces):
        tx_trees = {}
        for tx_hash in subtraces:
            for subtrace in subtraces[tx_hash]:
                trace_id = subtrace["trace_id"]
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

    def find_all_abnormal_behaviors(self):
        for subtrace_graph, traces, subtraces in self.subtrace_graph.subtrace_graphs_by_tx(
        ):
            l.debug("Searching for cycles in graph")
            cycles = list(nx.simple_cycles(subtrace_graph))

            if "traces" not in self.analysis_cache:
                self.analysis_cache["traces"] = traces
            if "tx_trees" not in self.analysis_cache:
                self.analysis_cache["tx_trees"] = self.build_call_tree(
                    subtraces)

            self.find_reentrancy(subtrace_graph, cycles)
            self.find_call_injection(subtrace_graph, cycles)
            self.find_bonus_hunitng(subtrace_graph)
