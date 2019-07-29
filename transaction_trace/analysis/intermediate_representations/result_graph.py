import logging

import IPython
import networkx as nx
from networkx.algorithms.traversal import dfs_edges

from ..knowledge import SensitiveAPIs
from ..results import ResultType
from .action_tree import ActionTree
from .transaction import Transaction

l = logging.getLogger(
    "transaction-trace.analysis.intermediate_representations.ResultGraph")


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
    def extract_token_address(token_result_type):
        return token_result_type.split(':')[1]

    @staticmethod
    def extract_result_type(result_type):
        return result_type.split(':')[0]

    @staticmethod
    def append_result_to_graph(src, dst, amount, result_type, graph):
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

    @staticmethod
    def build_result_tree(action_tree):
        tree = nx.DiGraph()

        for e in action_tree.t.edges():
            tree.add_edge(*e)
            trace = action_tree.t.edges[e]

            if trace['status'] == 0:  # error trace will not cause any results
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
                    if result_type not in tree.edges[e]:
                        tree.edges[e][result_type] = list()
                    tree.edges[e][result_type].append((src, dst, amount))

        return tree

    @staticmethod
    def build_partial_result_graph(result_tree, entry, direct_edges=None):
        graph = nx.DiGraph()

        edges = direct_edges if direct_edges is not None else dfs_edges(result_tree, entry)
        for e in edges:
            for result_type in result_tree.edges[e]:
                if result_type == ResultType.ETHER_TRANSFER:
                    src = ActionTree.extract_address_from_node(e[0])
                    dst = ActionTree.extract_address_from_node(e[1])
                    if src == dst:
                        continue
                    amount = result_tree.edges[e][result_type]

                    ResultGraph.append_result_to_graph(
                        src, dst, amount, result_type, graph)

                elif result_type == ResultType.TOKEN_TRANSFER:
                    token_address = ActionTree.extract_address_from_node(e[1])
                    for (src, dst, amount) in result_tree.edges[e][result_type]:
                        if src == dst:
                            continue
                        graph.add_edge(src, dst)

                        token_result_type = f"{result_type}:{token_address}"
                        ResultGraph.append_result_to_graph(
                            src, dst, amount, token_result_type, graph)

                else:  # ResultType.OWNER_CHANGE
                    for (src, dst, amount) in result_tree.edges[e][result_type]:
                        graph.add_edge(src, dst)
                        graph[src][dst][result_type] = None
                        graph.nodes[dst][result_type] = None

        return graph

    @staticmethod
    def build_result_graph(action_tree, token_transfers=None):
        root = [n for n, d in action_tree.t.in_degree() if d == 0]
        if len(root) > 1:
            l.warning("more than one root in action tree of %s",
                      action_tree.tx.tx_hash)
            IPython.embed()

        result_tree = ResultGraph.build_result_tree(action_tree)
        graph = ResultGraph.build_partial_result_graph(result_tree, root[0])

        if token_transfers != None:
            for row in token_transfers:
                token_result_type = f"{ResultType.TOKEN_TRANSFER_EVENT}:{row['token_address']}"
                ResultGraph.append_result_to_graph(
                    row['from_address'], row['to_address'], int(row['value']), token_result_type, graph)

        return ResultGraph(action_tree.tx, result_tree, graph)
