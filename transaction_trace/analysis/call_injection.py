import binascii
import logging
import pickle
from collections import defaultdict
import networkx as nx

from .trace_util import TraceUtil
from ..local import EthereumDatabase
from ..datetime_utils import time_to_str

l = logging.getLogger("transaction-trace.analysis.CallInjection")

key_functions = {
    "owner": {
        "0x13af4035": ("setOwner(address)", 34),
        "0xe46dcfeb": ("initWallet(address[],uint256,uint256)", 290),
        "0xf2fde38b": ("transferOwnership(address)", 34),
        "0xa6f9dae1": ("changeOwner(address)", 34),
        "0x7065cb48": ("addOwner(address)", 34)
    },
    "token": {
        "0xa9059cbb": ("transfer(address,uint256)", 34),
        "0x23b872dd": ("transferFrom(address,address,uint256)", 98),
        "0x40c10f19": ("mint(address,uint256)", 34),
        "0xb5e73249": ("mint(address,uint256,bool,uint32)", 34),
        "0xf0dda65c": ("mintTokens(address,uint256)", 34),
        "0x79c65068": ("mintToken(address,uint256)", 34),
        "0x449a52f8": ("mintTo(address,uint256)", 34),
        "0x2f81bc71": ("multiMint(address[],uint256[])", 226)
    }
}


class CallInjection:
    def __init__(self, log_file):
        self.log_file = log_file

        self.analysis_cache = dict()
        self.key_funcs = dict()
        self.backward_watch_list = defaultdict(dict)
        self.forward_watch_list = dict()
        for func_type in key_functions:
            for func_hash in key_functions[func_type]:
                func_name = key_functions[func_type][func_hash][0]
                benefit_pos = key_functions[func_type][func_hash][1]
                func_hex = binascii.b2a_hex(
                    func_name.encode("utf-8")).decode()
                self.key_funcs[func_hash] = (
                    func_name, func_hex, benefit_pos)

    def setup(self, subtrace_graph):
        self.subtrace_graph = subtrace_graph

    def record_abnormal_detail(self, detail):
        print(detail, file=self.log_file)

    def filter_by_profitability(self, db_folder, input_log_file, from_time, to_time):
        l.info("Extract watchList from input log file")
        f = open(input_log_file)
        lines = f.readlines()
        rows = list()
        for line in lines:
            rows.append(eval(line.strip("\n")))

        for row in rows:
            if 'watchList' in row['behavior']:
                forward_watch = str(
                    (row['caller'], row['parent_func'], row['entry']))
                if forward_watch in self.forward_watch_list and self.forward_watch_list[forward_watch] < row['time']:
                    continue
                self.forward_watch_list[forward_watch] = row['time']
            self.backward_watch_list[row['caller']
                                     ][row['entry']] = "2015-08-07 00:00:00"

        traces_db = EthereumDatabase(db_folder)
        token_transfer_db = EthereumDatabase(
            f"{db_folder}/../ethereum_token_transfers", "token_transfers")
        for traces_conn in traces_db.get_connections(from_time, to_time):
            token_transfer_con = token_transfer_db.get_connection(
                traces_conn.date)
            l.info("Prepare data: %s", traces_conn)

            traces = defaultdict(dict)
            for row in traces_conn.read("traces", "rowid, transaction_hash, from_address, to_address, value, block_timestamp"):
                tx_hash = row["transaction_hash"]
                rowid = row["rowid"]
                traces[tx_hash][rowid] = row

            subtraces = defaultdict(dict)
            for row in traces_conn.read_subtraces():
                tx_hash = row["transaction_hash"]
                trace_id = row["trace_id"]
                parent_trace_id = row["parent_trace_id"]
                subtraces[tx_hash][trace_id] = parent_trace_id

            token_transfers = defaultdict(list)
            for row in token_transfer_con.read("token_transfers", "*"):
                tx_hash = row["transaction_hash"]
                token_transfers[tx_hash].append(row)

            for tx_hash in subtraces:
                caller = "0x"
                time = ""
                eth_transfers = defaultdict(int)
                callee = defaultdict(list)
                for trace_id in subtraces[tx_hash]:
                    trace = traces[tx_hash][trace_id]
                    if subtraces[tx_hash][trace_id] == None:
                        caller = trace["from_address"]
                        time = time_to_str(trace["block_timestamp"])
                        if caller not in self.backward_watch_list:
                            break
                    callee[trace["to_address"]].append(trace_id)
                    if trace["value"] > 0:
                        eth_transfers[trace["from_address"]] -= trace["value"]
                        eth_transfers[trace["to_address"]] += trace["value"]

                if caller in self.backward_watch_list:
                    for entry in callee:
                        if entry in self.backward_watch_list[caller] and time > self.backward_watch_list[caller][entry]:
                            out = False
                            for trace_id in callee[entry]:
                                if out:
                                    break
                                ancestors = TraceUtil.get_all_ancestors(
                                    traces[tx_hash], subtraces[tx_hash], trace_id)
                                for addr in eth_transfers:
                                    if eth_transfers[addr] < 0 and addr in ancestors:
                                        self.backward_watch_list[caller][entry] = time
                                        out = True
                                        break
                                for row in token_transfers[tx_hash]:
                                    if row["from_address"] in ancestors:
                                        self.backward_watch_list[caller][entry] = time
                                        out = True
                                        break

        with open("/home/xiangjie/logs/pickles/watchList", "wb") as f:
            pickle.dump({"forward_watch_list": self.forward_watch_list,
                         "backward_watch_list": self.backward_watch_list}, f)
        # filter FPs according to watchList
        l.info("Filter FPs according to watchList")
        detail_list = list()
        for row in rows:
            forward_watch = str(
                (row['caller'], row['parent_func'], row['entry']))
            if len(row['behavior']) == 1 and 'watchList' in row['behavior']:
                continue
            elif row['caller'] in self.backward_watch_list and row['entry'] in self.backward_watch_list[row['caller']] and row['time'] <= self.backward_watch_list[row['caller']][row['entry']]:
                continue
            elif forward_watch in self.forward_watch_list and row['time'] >= self.forward_watch_list[forward_watch]:
                continue
            else:
                if 'watchList' in row['behavior']:
                    row['behavior'].remove('watchList')
                detail_list.append(row)

        for detail in detail_list:
            self.record_abnormal_detail(str(detail))

    def analyze(self):
        self.analysis_cache.clear()
        for subtrace_graph, traces, subtraces in self.subtrace_graph.subtrace_graphs_by_tx():
            l.debug("Searching for cycles in graph")
            cycles = list(nx.simple_cycles(subtrace_graph))

            if "traces" not in self.analysis_cache:
                self.analysis_cache["traces"] = traces
            if "subtraces" not in self.analysis_cache:
                self.analysis_cache["subtraces"] = subtraces
            if "tx_trees" not in self.analysis_cache:
                self.analysis_cache["tx_trees"] = TraceUtil.build_call_tree(
                    subtraces)

            self.find_call_injection(subtrace_graph, cycles)

    def find_call_injection(self, graph, cycles, key_func: bool = True):
        ABNORMAL_TYPE = "CallInjection"

        l.debug("Searching for Call Injection")

        tx_hash = graph.graph["transaction_hash"]
        caller = graph.graph["caller"]
        detail_list = set()
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
                call_type = self.analysis_cache["traces"][tx_hash][trace_id]["call_type"]
                if call_type == "delegatecall":
                    continue

                if parent_trace_id == None or gas_used == None or not callee.startswith("0x"):
                    continue
                callee = TraceUtil.get_callee(
                    self.analysis_cache["traces"][tx_hash][trace_id]["trace_type"], self.analysis_cache["traces"][tx_hash][trace_id]["input"])
                parent_trace_input = self.analysis_cache["traces"][tx_hash][parent_trace_id]["input"][10:]
                injection = list(self._find_call_injection(
                    tx_hash, trace_id, parent_trace_id, parent_trace_input, callee, key_func))

                if len(injection) > 0:
                    l.info(
                        "Call injection found for %s with entry %s behavior: %s",
                        tx_hash, cycle[0], injection)
                    detail = {
                        "time": graph.graph["time"],
                        "abnormal_type": ABNORMAL_TYPE,
                        "tx_hash": tx_hash,
                        "entry": cycle[0],
                        "caller": caller,
                        "call_type": call_type,
                        "func": callee,
                        "parent_func": TraceUtil.get_callee(self.analysis_cache["traces"][tx_hash][parent_trace_id]["trace_type"], parent_trace_input),
                        "behavior": injection
                    }
                    detail_list.add(str(detail))

        # check call injection on delegate call
        for trace_id in self.analysis_cache["subtraces"][tx_hash]:
            parent_trace_id = self.analysis_cache["subtraces"][tx_hash][trace_id]
            trace_type = self.analysis_cache["traces"][tx_hash][trace_id]["trace_type"]
            call_type = self.analysis_cache["traces"][tx_hash][trace_id]["call_type"]
            status = self.analysis_cache["traces"][tx_hash][trace_id]["status"]
            from_address = self.analysis_cache["traces"][tx_hash][trace_id]["from_address"]
            to_address = self.analysis_cache["traces"][tx_hash][trace_id]["to_address"]
            if status == 1 and trace_type == "call" and (call_type == "delegatecall" and from_address != to_address or call_type == "callcode"):
                callee = TraceUtil.get_callee(
                    trace_type, self.analysis_cache["traces"][tx_hash][trace_id]["input"])
                while parent_trace_id != None:
                    parent_trace_type = self.analysis_cache["traces"][tx_hash][parent_trace_id]["trace_type"]
                    parent_call_type = self.analysis_cache["traces"][tx_hash][parent_trace_id]["call_type"]
                    if parent_trace_type == "call" and (parent_call_type == "delegatecall" or parent_call_type == "callcode"):
                        parent_trace_id = self.analysis_cache["subtraces"][tx_hash][parent_trace_id]
                    else:
                        break

                callee = TraceUtil.get_callee(
                    self.analysis_cache["traces"][tx_hash][trace_id]["trace_type"], self.analysis_cache["traces"][tx_hash][trace_id]["input"])
                parent_trace_input = self.analysis_cache["traces"][tx_hash][parent_trace_id]["input"]
                injection = list(self._find_call_injection(
                    tx_hash, trace_id, parent_trace_id, parent_trace_input, callee, key_func))

                if len(injection) > 0:
                    entry = self.analysis_cache["traces"][tx_hash][parent_trace_id]["to_address"]
                    l.info(
                        "Call injection found for %s with entry %s behavior: %s",
                        tx_hash, entry, injection)
                    detail = {
                        "time": graph.graph["time"],
                        "abnormal_type": ABNORMAL_TYPE,
                        "tx_hash": tx_hash,
                        "entry": entry,
                        "caller": caller,
                        "call_type": call_type,
                        "func": callee,
                        "parent_func": TraceUtil.get_callee(parent_trace_type, parent_trace_input),
                        "behavior": injection
                    }
                    detail_list.add(str(detail))

        for detail in detail_list:
            self.record_abnormal_detail(detail)

    def _find_call_injection(self, tx_hash, trace_id, parent_trace_id, parent_trace_input, callee, key_func: bool):
        injection = set()
        if len(parent_trace_input) > 10:
            if callee[2:] in parent_trace_input or callee in self.key_funcs and self.key_funcs[callee][1] in parent_trace_input:
                if not key_func:
                    injection.add(None)
                else:
                    stack = list()
                    stack.append(trace_id)
                    while len(stack) > 0:
                        s_trace_id = stack.pop()
                        trace_input = self.analysis_cache["traces"][tx_hash][s_trace_id]["input"]
                        trace_type = self.analysis_cache["traces"][tx_hash][s_trace_id]["trace_type"]
                        from_address = self.analysis_cache["traces"][tx_hash][s_trace_id]["from_address"]
                        to_address = self.analysis_cache["traces"][tx_hash][s_trace_id]["to_address"]
                        ancestors = None
                        if trace_type == "suicide":
                            ancestors = TraceUtil.get_all_ancestors(
                                self.analysis_cache["traces"][tx_hash], self.analysis_cache["subtraces"][tx_hash], parent_trace_id)
                            if to_address in ancestors:
                                injection.add("suicide")
                        elif trace_type == "call" and len(trace_input) > 9 and trace_input[:10] in self.key_funcs:
                            ancestors = TraceUtil.get_all_ancestors(
                                self.analysis_cache["traces"][tx_hash], self.analysis_cache["subtraces"][tx_hash], parent_trace_id)
                            benefit_pos = self.key_funcs[trace_input[:10]][2]
                            benefit_node = "0x" + \
                                trace_input[benefit_pos: benefit_pos + 40]
                            if benefit_node in ancestors:
                                injection.add(
                                    self.key_funcs[trace_input[:10]][0])
                            lost_node = "0x"
                            if trace_input[:10] == "0xa9059cbb":
                                lost_node = from_address
                            elif trace_input[:10] == "0x23b872dd":
                                lost_node = trace_input[34: 74]
                            if lost_node in ancestors:
                                injection.add("watchList")
                        trace_value = self.analysis_cache["traces"][tx_hash][s_trace_id]["value"]
                        if trace_value > 0:
                            if ancestors == None:
                                ancestors = TraceUtil.get_all_ancestors(
                                    self.analysis_cache["traces"][tx_hash], self.analysis_cache["subtraces"][tx_hash], parent_trace_id)
                            if to_address in ancestors:
                                injection.add("ethTransfer")
                            if from_address in ancestors:
                                injection.add("watchList")
                        if s_trace_id in self.analysis_cache["tx_trees"][tx_hash]:
                            children = self.analysis_cache["tx_trees"][tx_hash][s_trace_id]
                            stack.extend(children)
        return injection
