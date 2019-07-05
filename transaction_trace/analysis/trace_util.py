from collections import defaultdict
from hashlib import sha256
from .intermediate_representations import extract_address_from_node


class TraceUtil:
    @staticmethod
    def get_callee(trace_type, trace_input):
        if trace_type == 'call':
            if len(trace_input) > 9:
                callee = trace_input[:10]
            else:
                callee = 'fallback'
        else:
            callee = trace_type
        return callee

    @staticmethod
    def build_call_tree(subtraces):
        tx_trees = defaultdict(dict)
        for tx_hash in subtraces:
            for trace_id in subtraces[tx_hash]:
                parent_trace_id = subtraces[tx_hash][trace_id]
                if parent_trace_id == None:
                    tx_trees[tx_hash][-1] = trace_id
                else:
                    if parent_trace_id not in tx_trees[tx_hash]:
                        tx_trees[tx_hash][parent_trace_id] = list()
                    tx_trees[tx_hash][parent_trace_id].append(trace_id)
        return tx_trees

    @staticmethod
    def get_all_ancestors(traces, subtraces, trace_id):
        ancestors = set()
        while trace_id != None:
            from_address = traces[trace_id]["from_address"]
            ancestors.add(from_address)
            parent_trace_id = subtraces[trace_id]
            trace_id = parent_trace_id

        return ancestors

    @staticmethod
    def get_all_ancestors_from_tree(tree, entry):
        ancestors = set()
        while entry != None:
            parent_edges = list(tree.in_edges(entry))
            if len(parent_edges) == 0:
                entry = None
            else:
                entry = parent_edges[0][0]
                node = extract_address_from_node(entry)
                ancestors.add(node)
        return ancestors

    @staticmethod
    def traversal_with_dfs(tree):
        paths = []
        path = []
        dfs_stack = []
        back_step = []
        root_id = tree[-1]
        dfs_stack.append(root_id)
        back_step.append(1)
        while len(dfs_stack) > 0:
            trace_id = dfs_stack.pop()
            path.append(trace_id)
            if trace_id not in tree:
                paths.append(tuple(path))
                back = back_step.pop()
                while back > 0:
                    path.pop()
                    back -= 1
                continue
            childs_id = tree[trace_id]
            back_step[-1] += 1
            for child in childs_id:
                dfs_stack.append(child)
                back_step.append(1)
            back_step.pop()
        return paths

    @staticmethod
    def hash_subtraces(subtraces):
        address_map = {}
        symbolic_subtraces = []
        for subtrace in subtraces:
            symbolic_subtrace = []
            for i in range(0, 2):
                if subtrace[i] in address_map.keys():
                    symbolic_subtrace.append(address_map[subtrace[i]])
                else:
                    symbol = len(address_map.keys())
                    address_map[subtrace[i]] = symbol
                    symbolic_subtrace.append(symbol)
            symbolic_subtrace.append(subtrace[2])
            symbolic_subtraces.append(symbolic_subtrace)
        m = sha256(str(symbolic_subtraces).encode('utf-8'))
        return '0x' + m.hexdigest()

    @staticmethod
    def generate_path_signature_for_tx(tx_hash, traces, tx_paths, specified_trace_id=None):
        path_sigs = set()
        for path in tx_paths[tx_hash]:
            if specified_trace_id == None or specified_trace_id in path:
                straces = []
                for trace_id in path:
                    from_address = traces[tx_hash][trace_id]["from_address"]
                    to_address = traces[tx_hash][trace_id]["to_address"]
                    callee = TraceUtil.get_callee(
                        traces[tx_hash][trace_id]['trace_type'], traces[tx_hash][trace_id]['input'])
                    straces.append((from_address, to_address, callee))
                subtrace_hash = TraceUtil.hash_subtraces(straces)
                path_sigs.add(subtrace_hash)
        return path_sigs
