from .checker import Checker, CheckerType
from ..intermediate_representations.action_tree import extract_address_from_node, extract_trace_id_from_node, get_edges_from_cycle
from ..intermediate_representations.result_graph import ResultGraph, ResultType

import networkx as nx


class ReentrancyChecker(Checker):

    def __init__(self, threshold):
        super(ReentrancyChecker, self).__init__("reentrancy")
        self.threshold = threshold

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def count_cycle_turns(self, graph, cycle):
        edges = get_edges_from_cycle(cycle)
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
            if e in walked_edges:
                turns_count += 1
                walked_edges.clear()

            walked_edges.add(e)
            walk['edge'] = e
            walk['trace_id'] = call_traces[walk['trace_id']]['parent_trace_id']

        entry = "%s:%s" % (walk['trace_id'], walk['edge'][0])
        return entry, turns_count

    def check_transaction(self, action_tree, result_graph):
        edges = action_tree.t.edges()
        if len(edges) < 2 * self.threshold:
            return

        # build call graph to find cycles
        g = nx.DiGraph()
        for e in edges:
            from_address = extract_address_from_node(e[0])
            to_address = extract_address_from_node(e[1])
            trace = action_tree.t.edges[e]

            g.add_edge(from_address, to_address)
            if "call_traces" not in g[from_address][to_address]:
                g[from_address][to_address]["call_traces"] = list()

            g[from_address][to_address]["call_traces"].append({
                "trace_id": extract_trace_id_from_node(e[1]),
                "parent_trace_id": extract_trace_id_from_node(e[0]),
                "height": len(trace["trace_address"]) if trace["trace_address"] != None else 0,
            })

        candidates = list()
        # search for reentrancy candidates cycle by cycle
        cycles = list(nx.simple_cycles(g))
        if len(cycles) < 1:
            return

        for cycle in cycles:
            if len(cycle) < 2:
                continue
            entry, turns_count = self.count_cycle_turns(g, cycle)
            if turns_count > self.threshold:
                candidates.append((entry, turns_count))

        tx = action_tree.tx
        # search partial-result-graph for each candidate
        for (entry, turns_count) in candidates:
            prg = ResultGraph.build_partial_result_graph(action_tree, entry)

            results = list()
            for node in prg.g.nodes():
                for result_type in prg.g.nodes[node]:
                    if result_type == ResultType.OWNER_CHANGE:
                        continue
                    elif prg.g.nodes[node][result_type] > self.minimum_profit_amount:
                        results.append({
                            "profit_node": node,
                            "result_type": result_type,
                            "amount": prg.g.nodes[node][result_type]
                        })

            if len(results) > 0:
                tx.is_attack = True

                # compute whole transaction economic lost
                rg = ResultGraph.build_result_graph(action_tree)
                lost = list()
                for node in rg.g.nodes():
                    for result_type in rg.g.nodes[node]:
                        if result_type == ResultType.OWNER_CHANGE:
                            continue
                        elif rg.g.nodes[node][result_type] < -self.minimum_profit_amount:
                            lost.append({
                                "node": node,
                                "result_type": result_type,
                                "amount": rg.g.nodes[node][result_type]
                            })

                tx.attack_details.append({
                    "checker": self.name,
                    "entry": entry,
                    "results": results,
                    "lost": lost
                })
