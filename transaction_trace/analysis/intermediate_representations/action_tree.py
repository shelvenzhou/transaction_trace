import networkx as nx

from .transaction import Transaction


class ActionTree:

    @staticmethod
    def get_edges_from_cycle(cycle):
        edges = []
        for i in range(1, len(cycle)):
            edges.append((cycle[i - 1], cycle[i]))
        edges.append((cycle[-1], cycle[0]))
        return edges

    @staticmethod
    def encode_node(trace_id, address):
        return str(trace_id) + ":" + address

    @staticmethod
    def extract_address_from_node(node):
        return node.split(":")[1]

    @staticmethod
    def extract_trace_id_from_node(node):
        return node.split(":")[0]

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
    def get_ancestors_from_tree(tree, entry):
        ancestors = set()
        while entry != None:
            parent_edges = list(tree.in_edges(entry))
            if len(parent_edges) == 0:
                entry = None
            else:
                entry = parent_edges[0][0]
                node = ActionTree.extract_address_from_node(entry)
                ancestors.add(node)
        return ancestors

    @staticmethod
    def build_action_tree(tx_hash, traces, subtraces):
        tx = None
        tree = nx.DiGraph()
        errs = list()
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
                from_node = ActionTree.encode_node(parent_trace_id, trace['from_address'])
                to_node = ActionTree.encode_node(trace_id, trace['from_address'])
            else:
                from_node = ActionTree.encode_node(parent_trace_id, trace['from_address'])
                to_node = ActionTree.encode_node(trace_id, trace['to_address'])

            if trace['status'] == 0:
                errs.append({
                    'from_address': trace['from_address'],
                    'to_address': trace['to_address'],
                    'trace_type': trace['trace_type'],
                    'call_type': trace['call_type'],
                    'input': trace['input'],
                    'error': trace['error'],
                })

            tree.add_edge(from_node, to_node, **dict(trace))

        return ActionTree(tx, tree, errs)
