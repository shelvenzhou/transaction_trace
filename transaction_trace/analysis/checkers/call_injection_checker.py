from .checker import Checker, CheckerType
from ..intermediate_representations.action_tree import extract_address_from_node, get_ancestors_from_tree
from ..intermediate_representations.result_graph import ResultGraph, ResultType
from ..knowledge import SensitiveAPIs, extract_function_signature

from collections import defaultdict


class CallInjectionChecker(Checker):

    def __init__(self):
        super(CallInjectionChecker, self).__init__("call-injection")

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        candidates = list()
        # search for call-injection candidates edge by edge
        edges = action_tree.t.edges()
        if len(edges) < 2:
            return
        for e in edges:
            from_address = extract_address_from_node(e[0])
            to_address = extract_address_from_node(e[1])
            trace = action_tree.t.edges[e]
            # call-injection only happens when the trace type is "call"
            if trace['trace_type'] != "call":
                continue

            self_loop = input_control = False
            # check self-loop
            if from_address == to_address:
                self_loop = True
            # check input-control
            if self_loop:
                parent_edge = list(action_tree.t.in_edges(e[0]))[0]
                parent_trace = action_tree.t.edges[parent_edge]

                callee = extract_function_signature(trace['input'])

                parent_trace_input = parent_trace['input']

                # TODO: not consider fallback function in "call" may cause FN, but also reduce FP on same func-name
                if len(parent_trace_input) > 10:
                    if callee[2:] in (parent_trace_input if trace['call_type'] == "delegatecall" else parent_trace_input[10:]):
                        input_control = True
                    else:
                        encoded_functions = SensitiveAPIs.encoded_functions()
                        for t in encoded_functions:
                            if callee in encoded_functions[t]:
                                encoded_callee = encoded_functions[t][callee]
                                if encoded_callee in parent_trace_input[10:]:
                                    input_control = True

            if self_loop and input_control:
                candidates.append((e, parent_edge))

        tx = action_tree.tx
        attacks = list()
        sensitive_nodes = set()
        # search partial-result-graph for each candidate
        for (e, parent_edge) in candidates:
            ancestors = get_ancestors_from_tree(action_tree.t, e[0])
            call_type = action_tree.t.edges[e]['call_type']

            # only consider the direct trace result graph when "delegatecall"
            direct_trace = True if call_type == "delegatecall" else False
            prg = ResultGraph.build_partial_result_graph(
                result_graph.t, e[0], direct_trace)

            results = dict()
            for e in prg.edges():
                if e[1] not in ancestors:
                    continue
                result = dict()
                for result_type in prg.edges[e]:
                    if result_type == ResultType.OWNER_CHANGE:
                        result[result_type] = None
                    elif result_type == ResultType.ETHER_TRANSFER:
                        if prg.edges[e][result_type] > self.minimum_profit_amount[result_type]:
                            result[result_type] = prg.edges[e][result_type]
                    elif result_type == ResultType.TOKEN_TRANSFER:
                        for token in prg.edges[e][result_type]:
                            if prg.edges[e][result_type][token] > self.minimum_profit_amount[result_type]:
                                if ResultType.TOKEN_TRANSFER not in result:
                                    result[ResultType.TOKEN_TRANSFER] = list()
                                result[result_type].append(
                                    (token, prg.edges[e][result_type][token]))
                    else:
                        continue
                if len(result) > 0:
                    results[e] = result
                    sensitive_nodes.add(e[1])

            if len(results) > 0:
                attacks.append({
                    "edge": parent_edge,
                    'results': results
                })

        if len(attacks) > 0:
            # compute whole transaction economic lost
            rg = result_graph
            profits = dict()
            for node in rg.g.nodes():
                if node not in sensitive_nodes:
                    continue
                profit = dict()
                for result_type in rg.g.nodes[node]:
                    if result_type == ResultType.OWNER_CHANGE:
                        profit[result_type] = None
                    elif result_type == ResultType.ETHER_TRANSFER:
                        if rg.g.nodes[node][result_type] > self.minimum_profit_amount[result_type]:
                            profit[result_type] = rg.g.nodes[node][result_type]
                    else:
                        for token in rg.g.nodes[node][result_type]:
                            if rg.g.nodes[node][result_type][token] > self.minimum_profit_amount[result_type]:
                                if result_type not in profit:
                                    profit[result_type] = list()
                                profit[result_type].append(
                                    (token, rg.g.nodes[node][result_type][token]))
                if len(profit) > 0:
                    profits[node] = profit

            if len(profit) > 0:
                tx.is_attack = True
                tx.attack_details.append({
                    "checker": self.name,
                    "attacks": attacks,
                    "profit": profits
                })
