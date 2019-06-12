import logging
import sys
from collections import defaultdict

from .intermediate_representations import ActionTree, ResultGraph
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.PreProcess")


class PreProcess(TraceAnalysis):
    def __init__(self, db_folder, log_file=sys.stdout):
        super(PreProcess, self).__init__(db_folder, log_file)

    def preprecess(self):
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
                tree = ActionTree.build_action_tree(tx_hash, traces[tx_hash], subtraces[tx_hash])
                if tree is not None:
                    graph = ResultGraph.build_result_graph(tree)

                    yield tree, graph
