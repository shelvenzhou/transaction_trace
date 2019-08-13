from ...basic_utils import DatetimeUtils
from ..intermediate_representations import ActionTree, ResultGraph
from ..knowledge import SensitiveAPIs, extract_function_signature
from ..results import AttackCandidate, ResultType
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

        if len(at.edges()) < 2:
            return

        candidates = list()
        for e in at.edges():
            from_address = ActionTree.extract_address_from_node(e[0])
            to_address = ActionTree.extract_address_from_node(e[1])
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
                    if called_func[2:] in parent_input[10:]:
                        input_control = True
                    else:
                        encoded_functions = SensitiveAPIs.encoded_functions()
                        for t in encoded_functions:
                            if called_func in encoded_functions[t]:
                                encoded_callee = encoded_functions[t][called_func]
                                if encoded_callee in parent_input[10:]:
                                    input_control = True

                if input_control:
                    candidates.append((e, parent_edge))

        attacks = list()
        sensitive_nodes = set()
        # search partial-result-graph for each candidate
        for (e, parent_edge) in candidates:
            ancestors = ActionTree.get_ancestors_from_tree(at, e[0])
            call_type = at.edges[e]['call_type']

            prg = ResultGraph.build_partial_result_graph(result_graph.t, e[0])
            intentions = {
                "ancestor_profits": dict(),
                "other_profits": dict(),
            }
            for e in prg.edges():
                intention = dict()
                for result_type in prg.edges[e]:
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt == ResultType.OWNER_CHANGE:
                        intention[result_type] = None
                    elif rt == ResultType.ETHER_TRANSFER:
                        if prg.edges[e][result_type] > self.minimum_profit_amount[rt]:
                            intention[result_type] = prg.edges[e][result_type]
                    elif rt == ResultType.TOKEN_TRANSFER:
                        if prg.edges[e][result_type] > self.minimum_profit_amount[rt]:
                            intention[result_type] = prg.edges[e][result_type]
                    else:
                        continue
                if len(intention) > 0:
                    if e[1] in ancestors:
                        intentions["ancestor_profits"][str(e)] = intention
                    else:
                        intentions["other_profits"][str(e)] = intention
                    sensitive_nodes.add(e[1])

            if len(intentions["ancestor_profits"]) > 0 or len(intentions["other_profits"]) > 0:
                attacks.append({
                    "entry_edge": parent_edge,
                    'intentions': intentions
                })

        if len(attacks) > 0:
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
                        profit[result_type] = None
                    elif rt == ResultType.ETHER_TRANSFER:
                        if rg.nodes[node][result_type] > self.minimum_profit_amount[rt]:
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
                    "tx_caller": tx.caller,
                    "tx_time": DatetimeUtils.time_to_str(tx.block_timestamp),
                    "attacks": attacks,
                },
                profits,
            )
            if len(action_tree.errs) > 0:
                errs = set()
                for err in action_tree.errs:
                    if err["error"] not in errs:
                        candidate.add_failed_reason(err["error"])
                    errs.add(err["error"])
                tx.failed_attacks.append(candidate)
            else:
                tx.attack_candidates.append(candidate)
