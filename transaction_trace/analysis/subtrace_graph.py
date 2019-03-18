import logging
from collections import defaultdict

import networkx as nx

from ..local.ethereum_database import EthereumDatabase

l = logging.getLogger("transaction-trace.analysis.SubtraceGraph")


class SubtraceGraph(object):
    def __init__(self, db_conn):
        self.db_conn = db_conn

    def _subtrace_graph_by_tx(self, tx_hash, subtraces, traces):
        subtrace_graph = nx.DiGraph(transaction_hash=tx_hash)
        for subtrace in subtraces:
            trace_id = subtrace['trace_id']
            parent_trace_id = subtrace['parent_trace_id']

            trace = traces[trace_id]
            from_address = trace['from_address']
            to_address = trace['to_address']
            trace_type = trace['trace_type']
            gas_used = trace['gas_used']
            trace_input = trace['input']

            # record callee signature
            if trace_type == 'call':
                if len(trace_input) > 9:
                    attr = trace_input[:10]
                else:
                    attr = 'fallback'
            else:
                attr = trace_type

            subtrace_graph.add_edge(from_address, to_address)
            if 'call_trace' not in subtrace_graph[from_address][to_address]:
                subtrace_graph[from_address][to_address]['call_trace'] = list()

            subtrace_graph[from_address][to_address]['call_trace'].append({
                'trace_id': trace_id,
                'parent_trace_id': parent_trace_id,
                'trace_type': trace_type,
                'gas_used': gas_used,
                'attr': attr,
            })

        if subtrace_graph.number_of_edges() < 2:  # ignore contracts which are never used
            return None

        return subtrace_graph

    def subtrace_graphs_by_tx(self):
        traces = defaultdict(dict)
        for row in self.db_conn.read_traces(with_rowid=True):
            tx_hash = row['transaction_hash']
            rowid = row['rowid']
            traces[tx_hash][rowid] = dict(row)

        subtraces = defaultdict(list)
        for row in self.db_conn.read_subtraces():
            tx_hash = row['transaction_hash']
            subtraces[tx_hash].append(dict(row))

        for tx_hash in traces:
            subtrace_graph = self._subtrace_graph_by_tx(
                tx_hash, subtraces[tx_hash], traces[tx_hash])

            if subtrace_graph == None:
                continue

            yield subtrace_graph
