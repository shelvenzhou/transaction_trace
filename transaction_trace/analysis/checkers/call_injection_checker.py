from ..intermediate_representations import (ActionTree, ResultGraph,
                                            ResultType,
                                            extract_address_from_node)
from ..knowledge import SensitiveAPIs, extract_function_signature
from .checker import Checker, CheckerType


class CallInjectionChecker(Checker):

    def __init__(self):
        super(CallInjectionChecker, self).__init__("call-injection")

    @property
    def checker_type(self):
        return CheckerType.TRANSACTION_CENTRIC

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        at = action_tree.t
        rg = result_graph.g

        candidates = list()

        if len(at.edges()) < 2:
            return

        for e in at.edges():
            from_address = extract_address_from_node(e[0])
            to_address = extract_address_from_node(e[1])
            trace = at.edges[e]

            # call-injection only happens when the trace type is "call"
            if trace['trace_type'] != "call":
                continue

            self_loop = input_control = False
            # check self-loop
            if from_address == to_address:
                self_loop = True
            # check input-control
            if self_loop:
                # call injection is infeasible for delegatecall
                if trace['call_type'] == "delegatecall":
                    continue

                if len(at.in_edges(e[0])) == 0:
                    continue
                parent_edge = list(at.in_edges(e[0]))[0]
                parent_trace = at.edges[parent_edge]

                called_func = extract_function_signature(trace['input'])
                parent_input = parent_trace['input']
                # TODO: not consider fallback function in "call" may cause FN, but also reduce FP on same func-name
                if len(parent_input) > 10:
                    if called_func[2:] in (parent_input if trace['call_type'] == "delegatecall" else parent_input[10:]):
                        input_control = True
                    else:
                        encoded_functions = SensitiveAPIs.encoded_functions()
                        for t in encoded_functions:
                            if callee in encoded_functions[t]:
                                encoded_callee = encoded_functions[t][callee]
                                if encoded_callee in parent_trace_input[10:]:
                                    input_control = True

                if input_control:
                    candidates.append((e, parent_edge))

        attacks = list()
        sensitive_nodes = set()
        # search partial-result-graph for each candidate
        for (e, parent_edge) in candidates:
            ancestors = ActionTree.get_ancestors_from_tree(action_tree.t, e[0])
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
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt == ResultType.OWNER_CHANGE:
                        result[result_type] = None
                    elif rt == ResultType.ETHER_TRANSFER:
                        if prg.edges[e][result_type] > self.minimum_profit_amount[rt]:
                            result[result_type] = prg.edges[e][result_type]
                    elif rt == ResultType.TOKEN_TRANSFER:
                        if prg.edges[e][result_type] > self.minimum_profit_amount[rt]:
                            result[result_type] = prg.edges[e][result_type]
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
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt == ResultType.OWNER_CHANGE:
                        profit[result_type] = None
                    elif rt == ResultType.ETHER_TRANSFER:
                        if rg.g.nodes[node][result_type] > self.minimum_profit_amount[rt]:
                            profit[result_type] = rg.g.nodes[node][result_type]
                    elif rt == ResultType.TOKEN_TRANSFER_EVENT:
                        if rg.g.nodes[node][result_type] > self.minimum_profit_amount[ResultType.TOKEN_TRANSFER]:
                            profit[result_type] = rg.g.nodes[node][result_type]
                if len(profit) > 0:
                    profits[node] = profit

            if len(profit) > 0:
                tx.is_attack = True
                tx.attack_details.append({
                    "checker": self.name,
                    "attacks": attacks,
                    "profit": profits
                })
