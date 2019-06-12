import logging

import networkx as nx
from networkx.algorithms.traversal import dfs_edges

from ..knowledge import SensitiveAPIs
from . import ResultType
from .transaction import Transaction

l = logging.getLogger("transaction-trace.analysis.intermediate_representations.ResultGraph")


class SensitiveResult:

    def __init__(self, result_type, details):
        self.result_type = result_type
        self.details = details


class ResultGraph:

    def __init__(self, tx, graph):
        self.tx = tx
        self.g = graph

    @staticmethod
    def build_partial_result_graph(action_tree, entry):
        graph = nx.DiGraph()
        for e in dfs_edges(action_tree.t, entry):
            trace = action_tree.t.edges[e]

            if trace['status'] == 0:  # error trace will not cause any results
                # TODO: check the intention of the failed traces
                continue

            if trace['value'] > 0:  # check ether transfer
                result_type = ResultType.ETHER_TRANSFER
                src = trace['from_address']
                dst = trace['to_address']
                amount = trace['value']

                graph.add_edge(src, dst)
                if result_type not in graph[src][dst]:
                    if amount is None:
                        import IPython; IPython.embed()
                    graph[src][dst][result_type] = amount
                else:
                    graph[src][dst][result_type] += amount

            elif SensitiveAPIs.sensitive_function_call(trace['input']):
                # check input data for token transfer and owner change
                for result_type, src, dst, amount in SensitiveAPIs.get_result_details(trace):
                    if result_type is None:
                        continue
                    elif result_type == ResultType.TOKEN_TRANSFER:
                        graph.add_edge(src, dst)
                        if result_type not in graph[src][dst]:
                            graph[src][dst][result_type] = amount
                        else:
                            graph[src][dst][result_type] += amount
                    else:  # ResultType.OWNER_CHANGE
                        graph.add_edge(src, dst)
                        graph[src][dst][result_type] = None

        return ResultGraph(action_tree.tx, graph)

    @staticmethod
    def build_result_graph(action_tree):
        root = [n for n, d in action_tree.t.in_degree() if d == 0]
        # assert len(root) == 1, "more than one root in action tree of %s" % action_tree.tx.tx_hash
        if len(root) > 1:
            l.warning("more than one root in action tree of %s", action_tree.tx.tx_hash)
            import IPython
            IPython.embed()

        return ResultGraph.build_partial_result_graph(action_tree, root[0])
