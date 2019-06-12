import networkx as nx

from .transaction import Transaction


def encode_node(trace_id, address):
    return str(trace_id) + ":" + address


def extract_address_from_node(node):
    return node.split(":")[1]


class ActionTree:

    def __init__(self, tx, tree, errs):
        self.tx = tx
        self.t = tree
        self.errs = errs

    def __repr__(self):
        return "action tree of transaction %s" % self.tx.tx_hash

    @property
    def is_attack(self):
        return self.tx.is_attack

    @staticmethod
    def build_action_tree(tx_hash, traces, subtraces):
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

            # filter the failed create
            if trace['status'] == 0 and trace['trace_type'] == 'create':
                return None

            # when A delegatecalls B, the msg.sender is still A
            # so it just like that A copys the code of B and calls its own code
            if trace['trace_type'] == 'call' and trace['call_type'] == 'delegatecall':
                from_node = encode_node(parent_trace_id, trace['from_address'])
                to_node = encode_node(trace_id, trace['from_address'])
            else:
                from_node = encode_node(parent_trace_id, trace['from_address'])
                to_node = encode_node(trace_id, trace['to_address'])

            if trace['status'] == 0:
                errs[from_node] = trace['error']

            tree.add_edge(from_node, to_node, **dict(trace))

        return ActionTree(tx, tree, errs)
