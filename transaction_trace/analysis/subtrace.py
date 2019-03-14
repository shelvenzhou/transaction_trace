import logging
from collections import defaultdict
from ..datetime_utils import date_to_str, str_to_time, time_to_str
from ..local.ethereum_database import EthereumDatabase

l = logging.getLogger("transaction-trace.analysis.subtrace")


def nested_dictionary():
    return defaultdict(nested_dictionary)


class SubtraceBuilder:
    def __init__(self, db_folder):
        self.database = EthereumDatabase(db_folder)

    def _build_subtrace(self, db):
        call_traces = nested_dictionary()
        for row in db.read_traces(with_rowid=True):
            tx_hash = row['transaction_hash']
            trace_id = row['rowid']
            trace_address = row['trace_address']

            if trace_address is None:  # root node
                level = 0
                seq = 0
                parent_seq = -1
            else:
                trace_addrs = trace_address.split(",")
                level = len(trace_addrs)
                seq = int(trace_addrs[-1])
                parent_seq = 0 if level == 1 else int(trace_addrs[-2])

            call_traces[tx_hash][level][seq] = (trace_id, parent_seq)

        for tx_hash in call_traces:
            # hack for parent of root node
            call_traces[tx_hash][-1][-1] = (None, None)
            for level in call_traces[tx_hash]:
                if level < 0:
                    continue

                for seq in call_traces[tx_hash][level]:
                    trace_id, parent_seq = call_traces[tx_hash][level][seq]
                    db.insert_subtrace(
                        (tx_hash, trace_id, call_traces[tx_hash][level-1][parent_seq][0]))

    def build_subtrace(self, from_time, to_time):
        for db in self.database.get_connections(from_time, to_time):
            db.create_subtraces_table()
            db.clear_subtraces()

            self._build_subtrace(db)
            db.commit()

            db.index_subtraces()
