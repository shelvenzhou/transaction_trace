import logging

import networkx as nx
from networkx.algorithms.traversal import dfs_edges

from ..knowledge import SensitiveAPIs
from . import ResultType
from .action_tree import extract_address_from_node
from .transaction import Transaction

l = logging.getLogger("transaction-trace.analysis.intermediate_representations.ResultGraph")


class SensitiveResult:

    def __init__(self, result_type, details):
        self.result_type = result_type
        self.details = details


def invalid_contract_address(addr):
    return addr.startswith("0x0000000000000000000000000000000000")


class ResultGraph:

    def __init__(self, tx, tree, graph):
        self.tx = tx
        self.t = tree
        self.g = graph

    @staticmethod
    def build_result_tree(action_tree):
        tree = nx.DiGraph()

        for e in action_tree.t.edges():
            tree.add_edge(*e)
            trace = action_tree.t.edges[e]

            if trace['status'] == 0:  # error trace will not cause any results
                # TODO: check the intention of the failed traces
                continue

            if trace['value'] > 0:  # check ether transfer
                result_type = ResultType.ETHER_TRANSFER
                amount = trace['value']
                tree.edges[e][result_type] = amount
            elif SensitiveAPIs.sensitive_function_call(trace['input']):
                # check input data for token transfer and owner change
                for result_type, src, dst, amount in SensitiveAPIs.get_result_details(trace):
                    if result_type is None:
                        continue
                    else:
                        tree.edges[e][result_type] = (src, dst, amount)

        return tree

    @staticmethod
    def build_partial_result_graph(result_tree, entry, direct_trace=False):
        graph = nx.DiGraph()

        if direct_trace:
            edges = result_tree.out_edges(entry)
        else:
            edges = dfs_edges(result_tree, entry)

        for e in edges:
            for result_type in result_tree.edges[e]:
                if result_type == ResultType.ETHER_TRANSFER:
                    src = extract_address_from_node(e[0])
                    dst = extract_address_from_node(e[1])
                    if src == dst:
                        continue
                    amount = result_tree.edges[e][result_type]
                    graph.add_edge(src, dst)

                    if result_type not in graph[src][dst]:
                        graph[src][dst][result_type] = amount
                    else:
                        graph[src][dst][result_type] += amount

                    if result_type not in graph.nodes[src]:
                        graph.nodes[src][result_type] = -amount
                    else:
                        graph.nodes[src][result_type] -= amount

                    if result_type not in graph.nodes[dst]:
                        graph.nodes[dst][result_type] = amount
                    else:
                        graph.nodes[dst][result_type] += amount


                elif result_type == ResultType.TOKEN_TRANSFER:
                    token_address = extract_address_from_node(e[1])

                    (src, dst, amount) = result_tree.edges[e][result_type]
                    if src == dst:
                        continue
                    graph.add_edge(src, dst)

                    if result_type not in graph[src][dst]:
                        graph[src][dst][result_type] = {token_address: amount}
                    elif token_address not in graph[src][dst][result_type]:
                        graph[src][dst][result_type][token_address] = amount
                    else:
                        graph[src][dst][result_type][token_address] += amount

                    if result_type not in graph.nodes[src]:
                        graph.nodes[src][result_type] = {token_address: -amount}
                    elif token_address not in graph.nodes[src][result_type]:
                        graph.nodes[src][result_type][token_address] = -amount
                    else:
                        graph.nodes[src][result_type][token_address] -= amount

                    if result_type not in graph.nodes[dst]:
                        graph.nodes[dst][result_type] = {token_address: amount}
                    elif token_address not in graph.nodes[dst][result_type]:
                        graph.nodes[dst][result_type][token_address] = amount
                    else:
                        graph.nodes[dst][result_type][token_address] += amount

                else:  # ResultType.OWNER_CHANGE
                    (src, dst, _) = result_tree.edges[e][result_type]

                    graph.add_edge(src, dst)
                    graph[src][dst][result_type] = None
                    graph.nodes[dst][result_type] = None

        return graph

    @staticmethod
    def build_result_graph(action_tree):
        root = [n for n, d in action_tree.t.in_degree() if d == 0]
        if len(root) > 1:
            l.warning("more than one root in action tree of %s", action_tree.tx.tx_hash)
            import IPython
            IPython.embed()

        result_tree = ResultGraph.build_result_tree(action_tree)
        graph = ResultGraph.build_partial_result_graph(result_tree, root[0])
        return ResultGraph(action_tree.tx, result_tree, graph)
