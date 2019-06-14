import logging
import sys
from collections import defaultdict

from .intermediate_representations import ActionTree, ResultGraph
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.PreProcess")


class PreProcess(TraceAnalysis):
    def __init__(self, db_folder, log_file=sys.stdout):
        super(PreProcess, self).__init__(db_folder, log_file)

    def preprocess(self):
        for conn in self.database.get_all_connnections():
            l.info("construct for %s", conn)

            traces = defaultdict(dict)
            for row in conn.read_traces(with_rowid=True):
                if row['trace_type'] not in ('call', 'create', 'suicide'):
                    l.info("ignore trace of type %s", row['trace_type'])
                    continue
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
                l.debug("construct action tree for %s", tx_hash)
                tree = ActionTree.build_action_tree(tx_hash, traces[tx_hash], subtraces[tx_hash])
                if tree is not None:
                    l.debug("construct result graph for %s", tx_hash)
                    graph = ResultGraph.build_result_graph(tree)

                    yield tree, graph

                yield None, None
