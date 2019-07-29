import logging
import os
import sys
from collections import defaultdict

from ..local import DatabaseName
from .intermediate_representations import ActionTree, ResultGraph
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.PreProcess")


def nested_dictionary():
    return defaultdict(nested_dictionary)


class PreProcess(TraceAnalysis):
    def __init__(self, db_folder):
        super(PreProcess, self).__init__(db_folder, [DatabaseName.TRACE_DATABASE, DatabaseName.TOKEN_TRANSFER_DATABASE])

    def preprocess(self):
        for conn in self.database[DatabaseName.TRACE_DATABASE].get_all_connnections():
            l.info("construct for %s", conn)

            token_conn = self.database[DatabaseName.TOKEN_TRANSFER_DATABASE].get_connection(conn.date)
            token_transfers = defaultdict(list)
            for row in token_conn.read('token_transfers', '*'):
                tx_hash = row['transaction_hash']
                token_transfers[tx_hash].append(row)

            tx_hashes = nested_dictionary()
            ordered_traces = nested_dictionary()
            for row in conn.read_traces(with_rowid=True):
                if row['trace_type'] not in ('call', 'create', 'suicide'):
                    l.debug("ignore trace of type %s", row['trace_type'])
                    continue

                block_number = row["block_number"]
                tx_index = row["transaction_index"]
                tx_hash = row["transaction_hash"]
                rowid = row['rowid']

                if block_number is None or tx_index is None:
                    continue

                ordered_traces[block_number][tx_index][rowid] = row
                tx_hashes[block_number][tx_index] = tx_hash

            subtraces = defaultdict(dict)
            for row in conn.read_subtraces():
                tx_hash = row['transaction_hash']
                trace_id = row['trace_id']
                parent_trace_id = row['parent_trace_id']
                subtraces[tx_hash][trace_id] = parent_trace_id

            for block_number in sorted(ordered_traces):
                for tx_index in sorted(ordered_traces[block_number]):
                    tx_hash = tx_hashes[block_number][tx_index]
                    l.debug("construct action tree for block %s index %s tx %s", block_number, tx_index, tx_hash)
                    tree = ActionTree.build_action_tree(
                        ordered_traces[block_number][tx_index], subtraces[tx_hash])
                    if tree is not None:
                        l.debug("construct result graph for %s", tx_hash)
                        graph = ResultGraph.build_result_graph(
                            tree, token_transfers[tx_hash] if tx_hash in token_transfers else None)

                        yield tree, graph
                    else:
                        l.debug("invalid action tree for %s", tx_hash)
                        yield None, None
