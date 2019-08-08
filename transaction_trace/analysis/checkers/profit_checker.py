import logging
import pickle
from collections import defaultdict

from ...basic_utils import DatetimeUtils
from ...local import DatabaseName
from ..intermediate_representations import ResultGraph
from ..results import ResultType
from .checker import Checker, CheckerType

l = logging.getLogger("transaction-trace.analysis.checkers.ProfitChecker")


def check_time_interval(begin_time, end_time, date, time):
    if begin_time[:10] < date < end_time[:10]:
        return True
    elif date == begin_time[:10] and time > begin_time:
        return True
    elif date == end_time[:10] and time < end_time:
        return True
    else:
        return False


class ProfitChecker(Checker):

    def __init__(self, attack_candidate_exporter):
        super(ProfitChecker, self).__init__("profit-checker")
        self.income_cache = defaultdict(dict)
        self.out = attack_candidate_exporter

    @property
    def checker_type(self):
        return CheckerType.CONTRACT_CENTRIC

    def check_contract_income_forward(self, contract, account, timestamp, income_type):
        rt = ResultGraph.extract_result_type(income_type)
        if rt == ResultType.TOKEN_TRANSFER_EVENT:
            token_address = ResultGraph.extract_token_address(income_type)
        income = 0
        time = '2015-08-07 00:00:00'
        if contract in self.income_cache and account in self.income_cache[contract] and income_type in self.income_cache[contract][account]:
            for t in self.income_cache[contract][account][income_type]:
                if t <= timestamp and t > time:
                    time = t
                    income = self.income_cache[contract][account][income_type][t]

        if income != 0:
            l.info("income_cache matched: %s %s %s %s",
                   contract, account, time, income_type)

        txs = self.database[DatabaseName.CONTRACT_TRANSACTIONS_DATABASE].read_transactions_of_contract(
            contract)
        l.info("%d dates for %s", len(txs), contract)
        for date in txs:
            if date > timestamp[:10] or date < time[:10]:
                continue

            if rt == ResultType.ETHER_TRANSFER:
                trace_con = self.database[DatabaseName.TRACE_DATABASE].get_connection(
                    date)
                traces = defaultdict(list)
                for row in trace_con.read('traces', "transaction_hash, from_address, to_address, value, status, block_timestamp"):
                    if row['trace_type'] not in ('call', 'create', 'suicide'):
                        continue
                    tx_hash = row['transaction_hash']
                    traces[tx_hash].append(row)

                for tx_hash in txs[date]:
                    if not check_time_interval(time, timestamp, date, DatetimeUtils.time_to_str(traces[tx_hash][0]['block_timestamp'])):
                        continue
                    for trace in traces[tx_hash]:
                        if trace['status'] == 0:
                            continue

                        if account in (trace['from_address'], trace['to_address']) and trace['value'] > 0:
                            if trace['from_address'] == contract:
                                income -= trace['value']
                            elif trace['to_address'] == contract:
                                income += trace['value']
            elif rt == ResultType.TOKEN_TRANSFER_EVENT:
                token_transfer_con = self.database[DatabaseName.TOKEN_TRANSFER_DATABASE].get_connection(
                    date)
                token_transfers = defaultdict(list)
                for row in token_transfer_con.read('token_transfers', '*'):
                    tx_hash = row['transaction_hash']
                    token_transfers[tx_hash].append(row)

                for tx_hash in txs[date]:
                    if tx_hash not in token_transfers:
                        continue
                    if not check_time_interval(time, timestamp, date, DatetimeUtils.time_to_str(token_transfers[tx_hash][0]['block_timestamp'])):
                        continue
                    for token_transfer in token_transfers[tx_hash]:
                        if token_transfer['token_address'] != token_address:
                            continue
                        src = token_transfer['from_address']
                        dst = token_transfer['to_address']
                        amount = int(token_transfer['value'])
                        if src == contract:
                            if account == None or account == dst:
                                income -= amount
                        elif dst == contract:
                            if account == None or account == src:
                                income += amount

        if account not in self.income_cache[contract]:
            self.income_cache[contract][account] = defaultdict(dict)
        self.income_cache[contract][account][income_type][timestamp] = income

        return income

    def extract_candidate_profits(self, candidate):
        # extract candidate attack profits for integer-overflow & reentrancy from raw result
        candidate_profits = defaultdict(dict)

        for node in candidate.results:
            for result_type in candidate.results[node]:
                candidate_profits[node][result_type] = {
                    'victims': set(),
                    'amount': candidate.results[node][result_type]
                }

        # import ipdb;ipdb.set_trace()
        for attack in candidate.details['attacks']:
            for e in attack['intention']:
                ee = eval(e)
                profit_node = ee[1]
                victim_node = ee[0]

                if profit_node not in candidate.results:
                    continue
                for result_type in attack['intention'][e]:
                    rt = ResultGraph.extract_result_type(result_type)
                    if rt == ResultType.ETHER_TRANSFER and rt in candidate.results[profit_node]:
                        candidate_profits[profit_node][result_type]['victims'].add(
                            victim_node)
                    elif rt == ResultType.TOKEN_TRANSFER:
                        token_address = ResultGraph.extract_token_address(
                            result_type)
                        ert = "{}:{}".format(ResultType.TOKEN_TRANSFER_EVENT, token_address)
                        if ert in candidate.results[profit_node]:
                            candidate_profits[profit_node][ert]['victims'].add(
                                victim_node)

        return candidate_profits

    def do_check(self, **kwargs):
        attack_candidate = kwargs['attack_candidate']
        self.check_candidate(attack_candidate)

    def check_candidate(self, candidate):
        if candidate.type not in ('integer-overflow'):
            self.out.dump_candidate(candidate)
            return
        # extract the candidate attack profits
        candidate_profits = self.extract_candidate_profits(candidate)

        attack_net_profit = dict()
        for profit_node in candidate_profits:
            net_profits = dict()
            for result_type in candidate_profits[profit_node]:
                outlay = 0
                profit_account = None if candidate.type == 'integer-overflow' else profit_node
                victims = candidate_profits[profit_node][result_type]['victims']
                if len(victims) == 0:
                    continue
                for victim in victims:
                    outlay += self.check_contract_income_forward(
                        victim, profit_account, candidate.details['tx_time'], result_type)

                net_profit = candidate_profits[profit_node][result_type]['amount'] - outlay
                if net_profit > self.minimum_profit_amount[ResultGraph.extract_result_type(result_type)]:
                    net_profits[result_type] = net_profit

            if len(net_profits) > 0:
                attack_net_profit[profit_node] = net_profits

        if len(attack_net_profit) > 0:
            profits = candidate.results
            candidate.results = {
                'profits': profits,
                'net_profits': attack_net_profit
            }
            self.out.dump_candidate(candidate)
