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

        subtrace_graphs = []
        txs = self.local.read_from_database(
            table="traces",
            columns="distinct transaction_hash",
            index="INDEXED BY transaction_hash_index")
        count = 0
        for tx in txs:
            trace_graph = self.build_digraph_on_subtraces_bytx(
                tx['transaction_hash'])

            count += 1
            sys.stdout.write(str(count) + '\r')
            sys.stdout.flush()
            if trace_graph == None:
                continue
            subtrace_graphs.append(trace_graph)
        print(f"{count} transactions")

        return subtrace_graphs

    def build_digraph_on_subtraces_bytx(self, transaction_hash):
        subtraces = self.local.read_from_database(
            table="subtraces",
            columns="*",
            index="INDEXED BY subtraces_transaction_hash_index",
            clause="where transaction_hash = :tx_hash",
            vals={'tx_hash': transaction_hash})
        trace_dg = nx.DiGraph(transaction_hash=transaction_hash)

        for subtrace in subtraces:
            trace_id = subtrace['id']
            parent_trace_id = subtrace['parent_trace_id']
            trace = self.local.read_from_database(
                table="traces",
                columns=
                "transaction_hash,from_address,to_address,input,trace_type,gas_used",
                clause="where rowid = :trace_id",
                vals={
                    'trace_id': trace_id
                }).fetchone()
            from_address = trace['from_address']
            to_address = trace['to_address']
            trace_type = trace['trace_type']
            gas_used = trace['gas_used']
            trace_dg.add_edge(from_address, to_address)
            if 'id' not in trace_dg[from_address][to_address]:
                trace_dg[from_address][to_address]['id'] = []
                trace_dg[from_address][to_address]['parent_trace_id'] = []
                trace_dg[from_address][to_address]['trace_type'] = []
                trace_dg[from_address][to_address]['gas_used'] = []

            trace_dg[from_address][to_address]['id'].append(trace_id)
            trace_dg[from_address][to_address]['parent_trace_id'].append(
                parent_trace_id)
            trace_dg[from_address][to_address]['trace_type'].append(trace_type)
            trace_dg[from_address][to_address]['gas_used'].append(gas_used)

        if trace_dg.number_of_edges() < 2:
            return None
        return trace_dg