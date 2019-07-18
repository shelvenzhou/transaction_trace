import logging
from collections import defaultdict

from ...datetime_utils import date_to_str, time_to_str
from ...local import DatabaseName
from ..intermediate_representations import ResultGraph, ResultType
from . import Checker, CheckerType

l = logging.getLogger("transaction-trace.analysis.checkers.ProfitChecker")


def check_time_interval(begin_time, end_time, date, time):
    if begin_time < date < end_time:
        return True
    elif date == begin_time[:10] and time > begin_time:
        return True
    elif date == end_time[:10] and time < end_time:
        return True
    else:
        return False


class ProfitChecker(Checker):

    def __init__(self):
        super(ProfitChecker, self).__init__("profit-checker")
        self.income_cache = defaultdict(dict)
        self.database = None

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
        l.info("%d transactions for %s", len(txs), contract)
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

                for tx_hash in traces:
                    if not check_time_interval(time, timestamp, date, time_to_str(traces[tx_hash][0]['block_timestamp'])):
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

                for tx_hash in token_transfers:
                    if not check_time_interval(time, timestamp, date, time_to_str(token_transfers[tx_hash][0]['block_timestamp'])):
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

    def extract_profit_candidates(self, attack_details):
        # extract candidate attack profits for call-injection & reentrancy from raw result
        candidates = dict()
        for checker_result in attack_details:
            if checker_result['checker'] not in ('reentrancy', 'call-injection', 'integer-overflow'):
                continue

            candidate_profits = defaultdict(dict)
            for node in checker_result['profit']:
                for result_type in checker_result['profit'][node]:
                    candidate_profits[node][result_type] = {
                        'victims': set(),
                        'amount': checker_result['profit'][node][result_type]
                    }

            for attack in checker_result['attacks']:
                for e in attack['results']:
                    profit_node = e[1]
                    victim_node = e[0]

                    if profit_node not in checker_result['profit']:
                        continue
                    for result_type in attack['results'][e]:
                        rt = ResultGraph.extract_result_type(result_type)
                        if rt == ResultType.ETHER_TRANSFER and rt in checker_result['profit'][profit_node]:
                            candidate_profits[profit_node][result_type]['victims'].add(
                                victim_node)
                        elif rt == ResultType.TOKEN_TRANSFER:
                            token_address = ResultGraph.extract_token_address(
                                result_type)
                            ert = f"{ResultType.TOKEN_TRANSFER_EVENT}:{token_address}"
                            if ert in checker_result['profit'][profit_node]:
                                candidate_profits[profit_node][ert]['victims'].add(
                                    victim_node)

            candidates[checker_result['checker']] = candidate_profits

        return candidates

    def do_check(self, txs, db):
        if self.database == None:
            self.database = db
        for tx in txs:
            if tx.is_attack == False:
                continue
            self.check_transaction(tx)

    def check_transaction(self, tx):
        # extract the candidate attack profits
        candidates = self.extract_profit_candidates(tx.attack_details)

        attack_net_profit = dict()
        for checker in candidates:
            attack_net_profit[checker] = dict()
            for profit_node in candidates[checker]:
                net_profits = dict()
                for result_type in candidates[checker][profit_node]:
                    outlay = 0
                    profit_account = None if checker == 'integer-overflow' else profit_node
                    for victim in candidates[checker][profit_node][result_type]['victims']:
                        outlay += self.check_contract_income_forward(
                            victim, profit_account, time_to_str(tx.block_timestamp), result_type)

                    net_profit = candidates[checker][profit_node][result_type]['amount'] - outlay
                    if net_profit > 0:
                        net_profits[result_type] = net_profit

                if len(net_profits) > 0:
                    attack_net_profit[checker][profit_node] = net_profits

        attack_details = list()
        for checker_result in tx.attack_details:
            if checker_result['checker'] in attack_net_profit:
                if len(attack_net_profit[checker_result['checker']]) > 0:
                    checker_result['net_profit'] = attack_net_profit[checker_result['checker']]
                    attack_details.append(checker_result)
            else:
                attack_details.append(checker_result)
        tx.attack_details = attack_details
        if len(attack_details) == 0:
            tx.is_attack = False
