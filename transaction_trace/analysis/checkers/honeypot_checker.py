import logging
from collections import defaultdict
from datetime import timedelta, timezone

from ...basic_utils import DatetimeUtils
from ..intermediate_representations import ActionTree
from ..results import ResultType, AttackCandidate
from .checker import Checker, CheckerType

l = logging.getLogger("transaction-trace.analysis.checker.HoneypotChecker")


class HONEYPOT_STATUS:
    CREATED = "CREATED"
    INITIALIZED = "INITIALIZED"
    PROFITED = "PROFITED"
    WITHDRAWED = "WITHDRAWED"


class Honeypot:
    def __init__(self, contract_addr, creater, create_tx, create_time):
        self.contract_addr = contract_addr

        self.status = HONEYPOT_STATUS.CREATED

        self.creater = creater
        self.create_time = create_time
        self.create_tx = create_tx

        self.bonus = 0
        self.init_txs = list()

        self.profited = False
        self.profit = 0
        self.profit_txs = list()

        self.withdrawed = False
        self.withdraw_value = 0
        self.withdraw_to = None
        self.withdraw_txs = list()

    def init(self, init_tx, from_addr, value):
        if self.status != HONEYPOT_STATUS.CREATED and self.status != HONEYPOT_STATUS.INITIALIZED:
            return False
        if from_addr != self.creater:
            return False

        self.status = HONEYPOT_STATUS.INITIALIZED
        self.bonus += value
        self.init_txs.append(init_tx)
        return True

    def income(self, profit_tx, from_addr, value):
        if self.status != HONEYPOT_STATUS.INITIALIZED and self.status != HONEYPOT_STATUS.PROFITED:
            return False

        if from_addr == self.creater:
            self.bonus += value
            self.init_txs.append(profit_tx)
        else:
            self.status = HONEYPOT_STATUS.PROFITED
            self.profited = True
            self.profit += value
            self.profit_txs.append(profit_tx)
        return True

    def withdraw(self, withdraw_tx, to_addr, value):
        # if self.status != HONEYPOT_STATUS.INITIALIZED and self.status != HONEYPOT_STATUS.PROFITED and self.status != HONEYPOT_STATUS.WITHDRAWED:
            # return False
        # if value != self.bonus + self.profit:
        #     return False

        if self.withdrawed:
            if to_addr != self.withdraw_to:
                return False
        else:
            self.withdrawed = True
            self.withdraw_to = to_addr
        self.withdraw_value += value
        self.withdraw_txs.append(withdraw_tx)
        return True


class HoneypotChecker(Checker):

    def __init__(self, time_window=timedelta(hours=10)):
        super(HoneypotChecker, self).__init__("honeypot")

        # contract addr -> Honeypot
        self.tracked_honeypots = dict()
        # use a time window to reduce the contract to track
        self.time_window = time_window
        self.window_start = None
        self.window_end = None
        self.last_created = set()
        self.current_created = set()

    @property
    def checker_type(self):
        return CheckerType.CONTRACT_CENTRIC

    def _stop_track(self, contract):
        if contract in self.tracked_honeypots:
            self.tracked_honeypots.pop(contract)
        if contract in self.current_created:
            self.current_created.remove(contract)
        if contract in self.last_created:
            self.last_created.remove(contract)

    def check_transaction(self, action_tree, result_graph):
        tx = action_tree.tx
        at = action_tree.t


        if self.window_start is None:
            self.window_start = tx.block_timestamp.replace(tzinfo=timezone.utc)
            self.window_end = self.window_start + self.time_window

        tx_time = tx.block_timestamp.replace(tzinfo=timezone.utc)
        if tx_time > self.window_end:
            # time window moves
            self.window_start = self.window_end
            self.window_end = self.window_end = self.window_start + self.time_window

            for contract in self.last_created:
                self.tracked_honeypots.pop(contract)

            self.last_created = self.current_created
            self.current_created = set()

        for created_contract, details in action_tree.created_contracts.items():
            self.current_created.add(created_contract)
            self.tracked_honeypots[created_contract] = Honeypot(created_contract, details["creator"], tx.tx_hash, tx_time)

        for e in at.edges():
            from_address = ActionTree.extract_address_from_node(e[0])
            to_address = ActionTree.extract_address_from_node(e[1])
            trace = at.edges[e]

            if trace["status"] == 0 or trace["trace_type"] not in ("call", "suicide"):
                continue

            # if to_address == "0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f" or from_address == "0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f":
            #     import ipdb; ipdb.set_trace()

            value = trace["value"]
            if value == 0:
                    continue

            if to_address in self.current_created or to_address in self.last_created:
                succ = self.tracked_honeypots[to_address].init(tx.tx_hash, from_address, value)
                if not succ:
                    self._stop_track(to_address)
                else:
                    if to_address in self.current_created:
                        self.current_created.remove(to_address)
                    if to_address in self.last_created:
                        self.last_created.remove(to_address)
            elif to_address in self.tracked_honeypots:
                succ = self.tracked_honeypots[to_address].income(tx.tx_hash, from_address, value)
                if not succ:
                    self._stop_track(to_address)
            elif from_address in self.tracked_honeypots:
                succ = self.tracked_honeypots[from_address].withdraw(tx.tx_hash, to_address, value)
                if not succ:
                    self._stop_track(from_address)

    def attack_candidates(self):
        for addr, honeypot in self.tracked_honeypots.items():
            if honeypot.status != HONEYPOT_STATUS.CREATED:
                yield AttackCandidate(
                    self.name,
                    {
                        "contract": honeypot.contract_addr,
                        "status": HONEYPOT_STATUS.WITHDRAWED if honeypot.withdrawed else honeypot.status,
                        "create_time": DatetimeUtils.time_to_str(honeypot.create_time),
                        "create_tx": honeypot.create_tx,
                        "init_txs":honeypot.init_txs,
                        "profit_txs": honeypot.profit_txs,
                        "withdraw_txs": honeypot.withdraw_txs,
                    },
                    {
                        "bonus": honeypot.bonus,
                        "profits": honeypot.profit,
                        "withdrawed_eth": honeypot.withdraw_value,
                    }
                )
