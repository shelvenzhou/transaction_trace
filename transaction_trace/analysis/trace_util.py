from collections import defaultdict


class TraceUtil:
    @staticmethod
    def build_call_tree(subtraces):
        tx_trees = defaultdict(dict)
        for tx_hash in subtraces:
            for subtrace in subtraces[tx_hash]:
                trace_id = subtrace["trace_id"]
                parent_trace_id = subtrace["parent_trace_id"]
                if parent_trace_id == None:
                    tx_trees[tx_hash][-1] = trace_id
                else:
                    if parent_trace_id not in tx_trees[tx_hash]:
                        tx_trees[tx_hash][parent_trace_id] = list()
                    tx_trees[tx_hash][parent_trace_id].append(trace_id)
        return tx_trees

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
    def generate_path_signature_for_tx(tx_hash, traces, tx_paths, specified_trace_id=None):
        path_sigs = set()
        for path in tx_paths[tx_hash]:
            if specified_trace_id == None or specified_trace_id in path:
                subtraces = []
                for trace_id in path:
                    from_address = traces[tx_hash][trace_id]["from_address"]
                    to_address = traces[tx_hash][trace_id]["to_address"]
                    if traces[tx_hash][trace_id]['trace_type'] == 'call':
                        trace_input = traces[tx_hash][trace_id]['input']
                        if len(trace_input) > 9:
                            attr = trace_input[:10]
                        else:
                            attr = 'fallback'
                    else:
                        attr = traces[tx_hash][trace_id]['trace_type']
                    subtraces.append((from_address, to_address, attr))
                subtrace_hash = self.hash_subtraces(subtraces)
                path_sigs.add(subtrace_hash)
        return path_sigs
