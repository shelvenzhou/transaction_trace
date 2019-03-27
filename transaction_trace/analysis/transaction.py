import logging
from collections import defaultdict
from sortedcontainers import SortedDict
from datetime import timedelta, timezone

from ..datetime_utils import str_to_date
from ..local import EthereumDatabase

l = logging.getLogger("transaction-trace.analysis.TransactionAnalyzer")


class TransactionAnalyzer:
    def __init__(self, db_folder, log_file):
        self.database = EthereumDatabase(db_folder)
        self.log_file = log_file

    def find_honeypot(self, from_time, to_time):
        class STATUS:
            CREATED = 0
            INITIALIZED = 1
            PROFITED = 2

        # contract addr -> HONEYPOT_STATUS
        tracked_honeypot = dict()
        # contracts failed to be initialized in 30min will not be tracked
        last_created = set()
        current_created = set()

        # use time window of 30min to avoiding taking too much memory
        WINDOW_LENGTH = timedelta(minutes=30)

        window_start = str_to_date(from_time) if isinstance(
            from_time, str) else from_time
        window_start = window_start.replace(tzinfo=timezone.utc)
        window_end = window_start + WINDOW_LENGTH

        for db_conn in self.database.get_connections(from_time, to_time):
            traces = defaultdict(dict)
            block_times = dict()

            l.info("Prepare data from %s", db_conn)
            for row in db_conn.read_traces(with_rowid=True):
                block_number = row["block_number"]
                tx_index = row["transaction_index"]
                block_time = row["block_timestamp"]

                if block_number not in block_times:
                    block_times[block_number] = block_time

                if tx_index not in traces[block_number]:
                    traces[block_number][tx_index] = list()
                traces[block_number][tx_index].append(dict(row))

            l.info("Begin analysis")

            for block_number in sorted(traces):
                block_txs = traces[block_number]

                if block_times[block_number] > window_end:
                    # window move
                    window_start = window_end
                    window_end = window_start + WINDOW_LENGTH

                    for contract in last_created:
                        tracked_honeypot.pop(contract, None)

                    last_created = current_created
                    current_created = set()

                for tx_index in sorted(block_txs):
                    tx_traces = block_txs[tx_index]

                    for trace in tx_traces:
                        tx_hash = trace["transaction_hash"]
                        to_addr = trace["to_address"]
                        from_addr = trace["from_address"]

                        if trace["trace_type"] == "create":
                            if to_addr is None: # failed create
                                break
                            current_created.add(to_addr)
                            tracked_honeypot[to_addr] = STATUS.CREATED
                            l.debug("TX %s creates %s", tx_hash, to_addr)
                            break

                        value = trace["value"]
                        if value > 0:
                            if to_addr in current_created or to_addr in last_created:
                                l.debug("TX %s transfers %d to %s",
                                       tx_hash, value, to_addr)

                                if to_addr in current_created:
                                    current_created.remove(to_addr)
                                if to_addr in current_created:
                                    last_created.remove(to_addr)

                                tracked_honeypot[to_addr] = STATUS.INITIALIZED
                                l.info("Potential honeypot initialized in %s", to_addr)

                            elif to_addr in tracked_honeypot:
                                if tracked_honeypot[to_addr] == STATUS.INITIALIZED:
                                    tracked_honeypot[to_addr] = STATUS.PROFITED
                                l.debug("[Honeypot] %s receives %d", to_addr, value)

                            elif from_addr in tracked_honeypot:
                                if tracked_honeypot[from_addr] == STATUS.INITIALIZED:
                                    l.info("[Honeypot] %s takes %d back", from_addr, value)
                                else:
                                    l.info("[Honeypot] %s takes %d back with profit", from_addr, value)
