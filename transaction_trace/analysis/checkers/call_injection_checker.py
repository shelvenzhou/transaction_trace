from .checker import Checker, CheckerType
from ..intermediate_representations.action_tree import extract_address_from_node, get_ancestors_from_tree
from ..intermediate_representations.result_graph import ResultGraph, ResultType
from ..knowledge import SensitiveAPIs, extract_function_signature


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
                candidates.append(e)

        tx = action_tree.tx
        # search partial-result-graph for each candidate
        for e in candidates:
            ancestors = get_ancestors_from_tree(action_tree.t, e[0])
            call_type = action_tree.t.edges[e]['call_type']

            # only consider the direct trace result graph when "delegatecall"
            direct_trace = True if call_type == "delegatecall" else False
            prg = ResultGraph.build_partial_result_graph(
                result_graph.t, e[0], direct_trace)

            results = list()
            for node in prg.nodes():
                if node not in ancestors:
                    continue
                for result_type in prg.nodes[node]:
                    if result_type == ResultType.OWNER_CHANGE:
                        results.append({
                            "profit_node": node,
                            "result_type": result_type,
                        })
                    elif prg.nodes[node][result_type] > 0:
                        results.append({
                            "profit_node": node,
                            "result_type": result_type,
                            "amount": prg.nodes[node][result_type]
                        })

            if len(results) > 0:
                tx.is_attack = True
                tx.attack_details.append({
                    "checker": self.name,
                    "edge": e,
                    "results": results
                })
