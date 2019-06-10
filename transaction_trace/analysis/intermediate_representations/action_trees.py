from collections import defaultdict

import networkx as nx

from .transaction import Transaction


class ActionTree:

    def __init__(self, tx, tree, errs):
        self.tx = tx
        self.tree = tree
        self.errs = errs


def encode_node(trace_id, address):
    return str(trace_id) + ":" + address


def extract_address_from_node(node):
    return node.split(":")[1]


class ActionTrees:

    def __init__(self, database):
        self.database = database

    def action_tree_by_tx(self):

        def build_action_tree(traces, subtraces):
            tx = None
            tree = nx.DiGraph()
            errs = dict()
            for trace_id, parent_trace_id in subtraces.items():
                trace = traces[trace_id]

                if parent_trace_id is None:  # root trace
                    tx = Transaction(trace['transaction_hash'],
                                     trace['block_number'],
                                     trace['transaction_index'],
                                     trace['block_timestamp'],
                                     trace['block_hash'],
                                     trace['from_address'])
                    parent_trace_id = "root"

                from_node = encode_node(parent_trace_id, trace['from_address'])
                to_node = encode_node(trace_id, trace['to_address'])

                if trace['status'] == 0:
                    errs[from_node] = trace['error']

                tree.add_edge(from_node, to_node, **dict(trace))

            return ActionTree(tx, tree, errs)

        for conn in self.database.get_all_connnections():
            traces = defaultdict(dict)
            for row in conn.read_traces(with_rowid=True):
                tx_hash = row['transaction_hash']
                rowid = row['rowid']
                traces[tx_hash][rowid] = row

            subtraces = defaultdict(dict)
            for row in conn.read_subtraces():
                tx_hash = row['transaction_hash']
                trace_id = row['trace_id']
                parent_trace_id = row['parent_trace_id']
                subtraces[tx_hash][trace_id] = parent_trace_id

            for tx_hash in traces:
                yield build_action_tree(traces[tx_hash], subtraces[tx_hash])
