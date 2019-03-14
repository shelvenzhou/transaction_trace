class DiGraphBuilder:
    def __init__(self, db_filepath=DB_FILEPATH):
        self.local = EthereumDatabase(db_filepath)

    def query_subtraces(self):
        return self.local.cur.execute("select * from subtraces")

    def query_trace_byid(self, traceid):
        return self.local.cur.execute("select transaction_hash,from_address,to_address,input,trace_type,gas_used from traces where rowid = :trace_id", {'trace_id': traceid})

    def query_traces_bytime(self, from_time, to_time):
        return self.local.cur.execute("select rowid,transaction_hash,from_address,to_address,input from traces where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time": from_time, "to_time": to_time})

    def query_subtraces_bytx(self, transaction_hash):
        return self.local.cur.execute("select * from subtraces where transaction_hash = :tx_hash", {'tx_hash': transaction_hash})

    def query_txs_bytime(self, from_time, to_time):
        return self.local.cur.execute("select distinct transaction_hash from traces where block_timestamp >= :from_time and block_timestamp < :to_time", {"from_time": from_time, "to_time": to_time})

    def build_digraph_on_traces(self, from_time, to_time):

        trace_dg = nx.DiGraph()
        traces = self.query_traces_bytime(from_time, to_time)
        for trace in traces:
            tx_hash = trace['transaction_hash']
            from_address = trace['from_address']
            to_address = trace['to_address']
            trace_input = trace['input']
            method_hash = trace_input[:10]
            trace_dg.add_edge(from_address, to_address)
            if method_hash in trace_dg[from_address][to_address]:
                method_attr = trace_dg[from_address][to_address][method_hash]
            else:
                trace_dg[from_address][to_address][method_hash] = {}
                method_attr = trace_dg[from_address][to_address][method_hash]

            if tx_hash in method_attr.keys():
                method_attr[tx_hash] += 1
            else:
                method_attr[tx_hash] = 1

        return trace_dg

    def build_digraph_on_subtraces_bytime(self, from_time, to_time):

        subtrace_graphs = []
        txs = self.query_txs_bytime(from_time, to_time).fetchall()
        print(f"{len(txs)} transactions")
        tx_count = 0
        for tx in txs:
            trace_graph = self.build_digraph_on_subtraces_bytx(
                tx['transaction_hash'])
            if trace_graph == None:
                continue
            subtrace_graphs.append(trace_graph)
            tx_count += 1
            sys.stdout.write(str(tx_count) + '\r')
            sys.stdout.flush()

        return subtrace_graphs

    def build_digraph_on_subtraces_bytx(self, transaction_hash):
        subtraces = self.query_subtraces_bytx(transaction_hash).fetchall()
        if len(subtraces) < 2:
            return None
        trace_dg = nx.DiGraph(transaction_hash=transaction_hash)
        # import IPython;IPython.embed()
        for subtrace in subtraces:
            trace_id = subtrace['id']
            parent_trace_id = subtrace['parent_trace_id']
            trace = self.query_trace_byid(trace_id).fetchone()
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

        return trace_dg
