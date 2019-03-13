import networkx as nx
from local.ethereum_database import EthereumDatabase
from datetime_utils import date_to_str
from datetime import datetime, timedelta
import sys


class DiGraphBuilder(object):
    def __init__(self):
        self.local = None

    def laod_database(self, db_path, date):
        self.local = EthereumDatabase(
            f"{db_path}raw/bigquery_ethereum_{date_to_str(date)}.sqlite3")

    def build_digraph_on_subtraces(self):

        traces = {}
        rows = self.local.read_from_database(
            table="traces",
            columns=
            "rowid, transaction_hash, from_address, to_address, input, trace_type, gas_used"
        )
        for row in rows:
            tx_hash = row['transaction_hash']
            rowid = row['rowid']
            if tx_hash not in traces:
                traces[tx_hash] = {}
            keys = list(row.keys())
            keys.remove('transaction_hash')
            keys.remove('rowid')
            trace = {}
            for k in keys:
                trace[k] = row[k]
            traces[tx_hash][rowid] = trace

        subtraces = {}
        rows = self.local.read_from_database(table="subtraces", columns="*")
        for row in rows:
            tx_hash = row['transaction_hash']
            if tx_hash not in subtraces:
                subtraces[tx_hash] = []
            subtrace = {}
            for k in row.keys():
                subtrace[k] = row[k]
            subtraces[tx_hash].append(subtrace)

        subtrace_graphs = []
        count = 0
        print("building graph...")
        for tx_hash in traces:
            trace_graph = self.build_digraph_on_subtraces_bytx(
                tx_hash, subtraces[tx_hash], traces[tx_hash])
            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()
            if trace_graph == None:
                continue
            subtrace_graphs.append(trace_graph)
        print(f"{count} transactions")

        return subtrace_graphs

    def build_digraph_on_subtraces_bytx(self, tx_hash, subtraces, traces):
        trace_dg = nx.DiGraph(transaction_hash=tx_hash)
        for subtrace in subtraces:
            trace_id = subtrace['id']
            parent_trace_id = subtrace['parent_trace_id']
            trace = traces[trace_id]
            from_address = trace['from_address']
            to_address = trace['to_address']
            trace_type = trace['trace_type']
            gas_used = trace['gas_used']
            trace_input = trace['input']
            if trace_type == 'call':
                if len(trace_input) > 9:
                    attr = trace_input[:10]
                else:
                    attr = 'fallback'
            else:
                attr = trace_type
            trace_dg.add_edge(from_address, to_address)
            if 'id' not in trace_dg[from_address][to_address]:
                trace_dg[from_address][to_address]['id'] = []
                trace_dg[from_address][to_address]['parent_trace_id'] = []
                trace_dg[from_address][to_address]['trace_type'] = []
                trace_dg[from_address][to_address]['gas_used'] = []
                trace_dg[from_address][to_address]['attr'] = []

            trace_dg[from_address][to_address]['id'].append(trace_id)
            trace_dg[from_address][to_address]['parent_trace_id'].append(
                parent_trace_id)
            trace_dg[from_address][to_address]['trace_type'].append(trace_type)
            trace_dg[from_address][to_address]['gas_used'].append(gas_used)
            trace_dg[from_address][to_address]['attr'].append(attr)


        if trace_dg.number_of_edges() < 2:
            return None
        return trace_dg