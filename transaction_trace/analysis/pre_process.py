import logging
import sys
import os
from collections import defaultdict

from .intermediate_representations import ActionTree, ResultGraph
from .trace_analysis import TraceAnalysis
from ..local import DatabaseName

l = logging.getLogger("transaction-trace.analysis.PreProcess")


class PreProcess(TraceAnalysis):
    def __init__(self, db_folder, log_file=sys.stdout):
        super(PreProcess, self).__init__(db_folder, log_file)
        # super(PreProcess, self).__init__(db_folder, log_file, [
        #     DatabaseName.TRACE_DATABASE, DatabaseName.TOKEN_TRANSFER_DATABASE])

    def preprocess(self, txs):
        # token_transfers = defaultdict(list)
        # for conn in self.database[DatabaseName.TOKEN_TRANSFER_DATABASE].get_all_connnections():
        #     l.info("token transfers: %s", conn)
        #     for row in conn.read('token_transfers', '*'):
        #         tx_hash = row['transaction_hash']
        #         token_transfers[tx_hash].append(row)

        # for conn in self.database[DatabaseName.TRACE_DATABASE].get_all_connnections():
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
                if tx_hash not in txs:
                    continue
                l.debug("construct action tree for %s", tx_hash)
                tree = ActionTree.build_action_tree(
                    tx_hash, traces[tx_hash], subtraces[tx_hash])
                if tree is not None:
                    l.debug("construct result graph for %s", tx_hash)
                    graph = ResultGraph.build_result_graph(tree)

                    yield tree, graph

                yield None, None
