import logging
from collections import defaultdict
from datetime import timedelta, timezone

from ..datetime_utils import str_to_date, time_to_str
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.Honeypot")


class Honeypot(TraceAnalysis):
    def __init__(self, db_folder, log_file):
        super(Honeypot, self).__init__(db_folder, log_file)

    def find_honeypot(self, from_time, to_time,
                      # 1 ETH <= bonus <= 10 ETH
                      least_bonus=1000000000000000000, most_bonus=10000000000000000000,
                      least_fee=100000000000000000  # Each guess takes at least 0.1 ETH
                      ):
        ABNORMAL_TYPE = "Honeypot"

        class STATUS:
            CREATED = 0
            INITIALIZED = 1
            PROFITED = 2
            WITHDRAWED = 3

        class Honeypot:
            def __init__(self, contract_addr, creater, create_time):
                self.contract_addr = contract_addr
                self.creater = creater
                self.create_time = create_time
                self.status = STATUS.CREATED

                self.profited = False
                self.profit = 0

                self.init_time = None
                self.bonus = 0

            def __repr__(self):
                if self.status == STATUS.CREATED:
                    return "honeypot %s created" % (self.contract_addr)
                elif self.status == STATUS.INITIALIZED:
                    return "honeypot %s initialzed with %d wei bonus at %s" % (
                        self.contract_addr,
                        self.bonus,
                        time_to_str(self.init_time)
                    )
                elif self.status == STATUS.PROFITED:
                    return "honeypot %s profited %d wei with %d wei bonus initialized at %s" % (
                        self.contract_addr,
                        self.profit,
                        self.bonus,
                        time_to_str(self.init_time)
                    )
                else:
                    r = "honeypot %s closed with %d wei bonus initialized at %s" % (
                        self.contract_addr,
                        self.bonus,
                        time_to_str(self.init_time)
                    )

                    if self.profited:
                        r += "with %d wei profit" % (self.profit)

                    return r

            def init(self, from_addr, value, init_time):
                if self.status != STATUS.CREATED:
                    return False

                if from_addr != self.creater:
                    return False

                if value < least_bonus or value > most_bonus:
                    return False

                self.status = STATUS.INITIALIZED
                self.init_time = init_time
                self.bonus = value

                return True

            def income(self, from_addr, value):
                if self.status != STATUS.INITIALIZED or self.status != STATUS.PROFITED:
                    return False

                if from_addr == self.creater:
                    return False

                if value < least_fee:
                    return False

                self.status = STATUS.PROFITED
                self.profited = True
                self.profit += value

                return True

            def withdraw(self, to_addr, value):
                if self.status != STATUS.INITIALIZED or self.status != STATUS.PROFITED:
                    return False

                if value != self.bonus + self.profit:
                    return False

                self.status = STATUS.WITHDRAWED

                return True

        # contract addr -> Honeypot
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
            error_txs = set()
            block_times = dict()

            l.info("Prepare data from %s", db_conn)
            for row in db_conn.read_traces(with_rowid=True):
                block_number = row["block_number"]
                tx_index = row["transaction_index"]
                block_time = row["block_timestamp"]

                if block_number is None or tx_index is None:
                    continue

                if block_number not in block_times:
                    block_times[block_number] = block_time

                if row["error"] is not None:
                    error_txs.add((block_number, tx_index))
                    traces[block_number].pop(tx_index, None)
                    continue
                if (block_number, tx_index) in error_txs:
                    continue

                if tx_index not in traces[block_number]:
                    traces[block_number][tx_index] = list()
                traces[block_number][tx_index].append(dict(row))

            l.info("Begin analysis")

            for block_number in sorted(traces):
                block_txs = traces[block_number]
                block_time = block_times[block_number]

                if block_time > window_end:
                    # window move
                    window_start = window_end
                    window_end = window_start + WINDOW_LENGTH

                    for contract in last_created:
                        tracked_honeypot.pop(contract)

                    last_created = current_created
                    current_created = set()

                for tx_index in sorted(block_txs):
                    tx_traces = block_txs[tx_index]

                    for trace in tx_traces:
                        tx_hash = trace["transaction_hash"]
                        to_addr = trace["to_address"]
                        from_addr = trace["from_address"]

                        if trace["trace_type"] == "create":
                            if to_addr is None:  # failed create
                                break
                            current_created.add(to_addr)
                            tracked_honeypot[to_addr] = Honeypot(
                                to_addr, from_addr, block_time)
                            l.debug("TX %s creates %s", tx_hash, to_addr)
                            break

                        value = trace["value"]
                        if to_addr in current_created or to_addr in last_created:
                            l.debug("TX %s transfers %d to %s to init honeypot",
                                    tx_hash, value, to_addr)

                            if to_addr in current_created:
                                current_created.remove(to_addr)
                            if to_addr in last_created:
                                last_created.remove(to_addr)

                            succ = tracked_honeypot[to_addr].init(
                                from_addr, value, block_time)
                            if succ:
                                l.debug(
                                    "potential honeypot initialized in %s", to_addr)
                            else:
                                tracked_honeypot.pop(to_addr)
                                l.debug(
                                    "illegal initialization for %s", to_addr)

                        elif to_addr in tracked_honeypot:
                            l.debug("%s receives %d", to_addr, value)

                            succ = tracked_honeypot[to_addr].income(
                                from_addr, value)
                            if not succ:
                                tracked_honeypot.pop(to_addr)

                        elif from_addr in tracked_honeypot:
                            succ = tracked_honeypot[from_addr].withdraw(
                                to_addr, value)

                            if not succ:
                                tracked_honeypot.pop(from_addr)
                                if from_addr in current_created:
                                    current_created.remove(from_addr)
                                if from_addr in last_created:
                                    last_created.remove(from_addr)

        for _, honeypot in tracked_honeypot.items():
            self.record_abnormal_detail(
                time_to_str(honeypot.create_time),
                ABNORMAL_TYPE,
                str(honeypot)
            )
