from collections import defaultdict

import networkx as nx

from ..intermediate_representations import ActionTree, ResultGraph
from ..results import AttackCandidate, ResultType
from .checker import Checker, CheckerType


class ReentrancyChecker(Checker):

    def __init__(self, threshold):
        super(ReentrancyChecker, self).__init__("reentrancy")
        self.threshold = threshold

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def count_iter_num(self, graph, cycle):
        edges = ActionTree.get_edges_from_cycle(cycle)
        walk = {'max_height': 0, 'trace_id': 0, 'edge': ()}
        call_traces = dict()

        for e in edges:
            for call_trace in graph.edges[e]['call_traces']:
                call_traces[call_trace['trace_id']] = {
                    'height': call_trace['height'],
                    'parent_trace_id': call_trace['parent_trace_id'],
                    'edge': e
                }
                if call_trace['height'] > walk['max_height']:
                    walk['max_height'] = call_trace['height']
                    walk['trace_id'] = call_trace['trace_id']
                    walk['edge'] = e

        turns_count = 0
        walked_edges = set()
        while walk['trace_id'] in call_traces:
            e = call_traces[walk['trace_id']]['edge']

            walked_edges.add(e)
            if len(walked_edges) == len(edges):
                turns_count += 1
                walked_edges.clear()

            walk['edge'] = e
            walk['trace_id'] = call_traces[walk['trace_id']]['parent_trace_id']

        entry = "%s:%s" % (walk['trace_id'], walk['edge'][0])
        return entry, turns_count

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        at = action_tree.t
        rg = result_graph.g

        if len(at.edges()) < 2 * self.threshold:
            return

        # build call graph to find cycles
        g = nx.DiGraph()
        for e in at.edges():
            from_address = ActionTree.extract_address_from_node(e[0])
            to_address = ActionTree.extract_address_from_node(e[1])
            trace = at.edges[e]

            g.add_edge(from_address, to_address)
            if "call_traces" not in g[from_address][to_address]:
                g[from_address][to_address]["call_traces"] = list()

            g[from_address][to_address]["call_traces"].append({
                "trace_id": ActionTree.extract_trace_id_from_node(e[1]),
                "parent_trace_id": ActionTree.extract_trace_id_from_node(e[0]),
                "height": len(trace["trace_address"]) if trace["trace_address"] != None else 0,
            })

        candidates = list()
        # search for reentrancy candidates cycle by cycle
        cycles = list(nx.simple_cycles(g))
        if len(cycles) == 0:
            return

        for cycle in cycles:
            if len(cycle) < 2:
                continue
            entry, iter_num = self.count_iter_num(g, cycle)
            if iter_num > self.threshold:
                candidates.append((entry, cycle, iter_num))

        intentions = list()
        sensitive_nodes = set()
        # search partial-result-graph for each candidate
        for (entry, cycle, iter_num) in candidates:
            prg = ResultGraph.build_partial_result_graph(result_graph.t, entry)

            intention = dict()
            for e in prg.edges():
                result = dict()
                for result_type in prg.edges[e]:
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt == ResultType.OWNER_CHANGE:
                        continue
                    elif rt == ResultType.ETHER_TRANSFER:
                        if prg.edges[e][result_type] > self.minimum_profit_amount[result_type]:
                            result[result_type] = prg.edges[e][result_type]
                    elif rt == ResultType.TOKEN_TRANSFER:
                        if prg.edges[e][result_type] > self.minimum_profit_amount[ResultType.TOKEN_TRANSFER]:
                            result[result_type] = prg.edges[e][result_type]
                if len(result) > 0:
                    intention[e] = result
                    sensitive_nodes.add(e[1])

            if len(intention) > 0:
                intentions.append({
                    "entry": entry,
                    "cycle": cycle,
                    "iter_num": iter_num,
                    "intention": intention
                })

        if len(intentions) > 0:
            tx.is_attack = True

            # compute whole transaction economic lost
            profits = dict()
            for node in rg.nodes():
                if node not in sensitive_nodes:
                    continue
                profit = dict()
                for result_type in rg.nodes[node]:
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt == ResultType.OWNER_CHANGE:
                        continue
                    elif rt == ResultType.ETHER_TRANSFER:
                        if rg.nodes[node][result_type] > self.minimum_profit_amount[result_type]:
                            profit[result_type] = rg.nodes[node][result_type]
                    elif rt == ResultType.TOKEN_TRANSFER_EVENT:
                        if rg.nodes[node][result_type] > self.minimum_profit_amount[ResultType.TOKEN_TRANSFER_EVENT]:
                            profit[result_type] = rg.nodes[node][result_type]
                if len(profit) > 0:
                    profits[node] = profit

            candidate = AttackCandidate(
                self.name,
                {
                    "transaction": tx.tx_hash,
                    "attacks": intentions,
                },
                profits,
            )
            if len(action_tree.errs) > 0:
                candidate.add_failed_reason("reverted trace in tx")
                tx.failed_attacks.append(candidate)
            else:
                tx.attack_candidates.append(candidate)
