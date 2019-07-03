from .checker import Checker, CheckerType
from ..intermediate_representations import ResultType
from ...local.ethereum_database import EthereumDatabase
from ..knowledge.sensitive_apis import SensitiveAPIs, extract_function_signature
from ...datetime_utils import date_to_str, time_to_str

from collections import defaultdict
import logging

l = logging.getLogger("transaction-trace.analysis.checkers.ProfitChecker")

class ProfitChecker(Checker):

    def __init__(self, db_folder):
        super(ProfitChecker, self).__init__("profit-checker")
        self.trace_db = EthereumDatabase(db_folder)
        self.income_cache = defaultdict(dict)

    @property
    def checker_type(self):
        return CheckerType.CONTRACT_CENTRIC

    def check_contract_income_forward(self, db, contract, account, timestamp, income_type, token=None):
        encoded_income_type = income_type
        if token != None:
            encoded_income_type = f"{income_type}:{token}"

        income = 0
        time = '2015-08-07 00:00:00'
        if contract in self.income_cache and account in self.income_cache[contract] and encoded_income_type in self.income_cache[contract][account]:
            for t in self.income_cache[contract][account][encoded_income_type]:
                if t <= timestamp and t > time:
                    time = t
                    income = self.income_cache[contract][account][encoded_income_type][t]

        if income != 0:
            l.info("income_cache matched: %s %s %s %s", contract, account, timestamp, income_type)

        txs = db.read_transactions_of_contract(contract)
        for date in txs:
            if date > timestamp[:10] or date < time[:10]:
                continue
            con = self.trace_db.get_connection(date)
            traces = defaultdict(list)
            for row in con.read_traces():
                if row['trace_type'] not in ('call', 'create', 'suicide'):
                    continue
                tx_hash = row['transaction_hash']
                traces[tx_hash].append(row)

            for tx_hash in traces:
                if date == timestamp[:10] and time_to_str(traces[tx_hash][0]['block_timestamp']) >= timestamp:
                    continue
                if date == time[:10] and time_to_str(traces[tx_hash][0]['block_timestamp']) <= time:
                    continue
                for trace in traces[tx_hash]:
                    if trace['status'] == 0:
                        continue

                    if income_type == ResultType.ETHER_TRANSFER and account in (trace['from_address'], trace['to_address']) and trace['value'] > 0:
                        if trace['from_address'] == contract:
                            income -= trace['value']
                        elif trace['to_address'] == contract:
                            income += trace['value']
                    elif income_type == ResultType.TOKEN_TRANSFER:
                        callee = extract_function_signature(trace['input'])
                        if callee not in SensitiveAPIs._sensitive_functions['token']:
                            continue
                        token_address = trace['to_address']
                        if token_address != token:
                            continue
                        for result_type, src, dst, amount in SensitiveAPIs.get_result_details(trace):
                            if result_type == ResultType.TOKEN_TRANSFER:
                                if src == contract and dst == account:
                                    income -= amount
                                elif dst == contract and src == account:
                                    income += amount

        if account not in self.income_cache[contract]:
            self.income_cache[contract][account] = defaultdict(dict)
        self.income_cache[contract][account][encoded_income_type][timestamp] = income

        return income

    def extract_profit_candidates(self, attack_details):
        # extract candidate attack profits for call-injection & reentrancy from raw result
        candidates = dict()
        for checker_result in attack_details:
            if checker_result['checker'] not in ('reentrancy, call-injection'):
                continue

            candidate_profits = defaultdict(dict)
            for node in checker_result['profit']:
                for result_type in checker_result['profit'][node]:
                    if result_type == ResultType.ETHER_TRANSFER:
                        candidate_profits[node][result_type] = {
                            'victims': set(),
                            'amount': checker_result['profit'][node][result_type]
                        }
                    elif result_type == ResultType.TOKEN_TRANSFER:
                        candidate_profits[node][result_type] = dict()
                        for row in checker_result['profit'][node][result_type]:
                            token = row[0]
                            candidate_profits[node][result_type][token] = {
                                'victims': set(),
                                'amount': row[1]
                            }

            for attack in checker_result['attacks']:
                for e in attack['results']:
                    profit_node = e[1]
                    victim_node = e[0]

                    for result_type in attack['results'][e]:
                        if profit_node in checker_result['profit'] and result_type in checker_result['profit'][profit_node]:
                            if result_type == ResultType.ETHER_TRANSFER:
                                candidate_profits[profit_node][result_type]['victims'].add(
                                    victim_node)
                            elif result_type == ResultType.TOKEN_TRANSFER:
                                for row in attack['results'][e][result_type]:
                                    token = row[0]
                                    if token in candidate_profits[profit_node][result_type]:
                                        candidate_profits[profit_node][result_type][token]['victims'].add(
                                            victim_node)
            candidates[checker_result['checker']] = candidate_profits

        return candidates

    def check_transaction(self, tx, db):
        # extract the candidate attack profits
        candidates = self.extract_profit_candidates(tx.attack_details)

        attack_net_profit = dict()
        for checker in candidates:
            attack_net_profit[checker] = dict()
            for profit_node in candidates[checker]:
                net_profits = dict()
                for result_type in candidates[checker][profit_node]:
                    if result_type == ResultType.ETHER_TRANSFER:
                        outlay = 0
                        for victim in candidates[checker][profit_node][result_type]['victims']:
                            outlay += self.check_contract_income_forward(
                                db, victim, profit_node, time_to_str(tx.block_timestamp), result_type)

                        net_profit = candidates[checker][profit_node][result_type]['amount'] - outlay
                        if net_profit > 0:
                            net_profits[result_type] = net_profit
                    elif result_type == ResultType.TOKEN_TRANSFER:
                        token_net_profits = dict()
                        for token in candidates[checker][profit_node][result_type]:
                            outlay = 0
                            for victim in candidates[checker][profit_node][result_type][token]['victims']:
                                outlay += self.check_contract_income_forward(
                                    db, victim, profit_node, time_to_str(tx.block_timestamp), result_type, token)

                            net_profit = candidates[checker][profit_node][result_type][token]['amount'] - outlay
                            if net_profit > 0:
                                token_net_profits[token] = net_profit
                        if len(token_net_profits) > 0:
                            net_profits[result_type] = token_net_profits
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
