from collections import defaultdict
from datetime import datetime
from dateutil.relativedelta import relativedelta
import sqlite3
import pickle
from web3 import Web3
from hashlib import sha256
import logging

from .local import EthereumDatabase
from .datetime_utils import time_to_str, month_to_str
from .analysis.intermediate_representations import ResultType

l = logging.getLogger('eval_util')

define_map = {
    'vandal': {
        'reentrantCall': 'reentrancy',
        'accessibleSuicide': 'call-after-destruct'
    },
    'zeus': {
        'Reentrancy': 'reentrancy',
        'Int_overflow': 'integer-overflow'
    },
    'oyente': {
        'reentrancy': 'reentrancy'
    },
    'securify': {
        'DAO': 'reentrancy',
        'LockedEther': 'call-after-destruct'
    },
    'HoneyBadger': {
        'honeypot': 'honeypot'
    }
}

dataset_latest_time = {
    'vandal': '2018-08-30',
    'zeus': '2017-03-15 09:45:39',
    'oyente': '2016-05-05',
    'securify': '2017-03-04 05:31:21',
    'HoneyBadger': '2018-10-12'
}

integer_flow_sensitive_function = {
    'transferMulti(address[],uint256[])',
    'transferProxy(address,address,uint256,uint256,uint8,bytes32,bytes32)',
    'batchTransfer(address[],uint256)',
    'multiTransfer(address[],uint256[])'
}

CAD_LOG_FILE = '/home/xiangjie/logs/suicide-contract-analyzer-20190625223619.log'
CI_LOG_FILE = '/home/xiangjie/logs/call-injection-analyzer-20190607031718.log'
HONEYPOT_LOG_FILE = '/home/xiangjie/logs/naive-honeypot.log'
PAPERS_RESULT_FILE = '/home/xiangjie/logs/pickles/papers_result'

REENTRANCY_ADDRS_MAP = '/home/xiangjie/logs/pickles/reen_addrs2target'


class EvalUtil:
    def __init__(self, log_file, with_cad_log_file=True, with_ci_log_file=True):
        self.papers_result_file = PAPERS_RESULT_FILE
        self.log_file = log_file
        self.honeypot_log_file = HONEYPOT_LOG_FILE
        self.cad_log_file = CAD_LOG_FILE if with_cad_log_file else None
        self.ci_log_file = CI_LOG_FILE if with_ci_log_file else None

        self.papers_result = None
        self.txs = None
        self.cad_txs = None
        self.ci_txs = None

        self.honeypot = None
        self.old_overflow = None

        self.reen_addrs2target = None

        self.open_sourced_contract = None
        self.create_time = None
        self.bytecode = None

        self.day2txs = None
        self.month2txs = None

        self.vul2txs = None
        self.vul2contrs = None
        self.vul2contrs_open_sourced = None

        self.contr2txs = None
        self.code2txs = None
        self.bytecode2txs = None

        self.vul2contrs_open_sourced = None

        self.load_data()

    def load_data(self):
        l.info("loading log file")
        f = open(self.log_file, 'r')
        lines = f.readlines()
        rows = []
        for line in lines:
            rows.append(eval(line.strip('\n')))
        txs = dict()
        for row in rows:
            txs[row['tx_hash']] = row
        self.txs = txs

        l.info("loading honeypot log file")
        f = open(self.honeypot_log_file, 'r')
        lines = f.readlines()
        rows = []
        for line in lines:
            if 'Closed profited' in line:
                time = line.split('[')[1].split(']')[0]
                contr = line.split(' ')[-1].strip('\n')
                rows.append((time, contr))
        self.honeypot = rows

        if self.cad_log_file != None:
            l.info("loading cad log file")
            f = open(self.cad_log_file, 'r')
            lines = f.readlines()
            rows = []
            for line in lines:
                rows.append(eval(line.strip('\n')))
            cad_txs = dict()
            for row in rows:
                cad_txs[row['tx_hash']] = row
            self.cad_txs = cad_txs

        if self.ci_log_file != None:
            l.info("load call-injection log file")
            f = open(self.ci_log_file, 'r')
            lines = f.readlines()
            rows = []
            for line in lines:
                rows.append(eval(line.strip('\n')))
            ci_txs = dict()
            for row in rows:
                ci_txs[row['tx_hash']] = row
            self.ci_txs = ci_txs

        l.info("loading reen_addrs2target_map")
        with open(REENTRANCY_ADDRS_MAP, 'rb') as f:
            self.reen_addrs2target = pickle.load(f)

        l.info("loading related paper results")
        with open(self.papers_result_file, 'rb') as f:
            self.papers_result = pickle.load(f)

        l.info("loading contract source code")
        open_sourced_contract = dict()
        etherscan_db = sqlite3.connect(
            '/home/xiangjie/database/etherscan.sqlite3')
        for row in etherscan_db.execute('select ContractAddress, SourceCode from contracts'):
            if row[1] != '':
                open_sourced_contract[row[0]] = row[1]
        self.open_sourced_contract = open_sourced_contract

        l.info("loading contract create time and bytecode")
        create_time = dict()
        bytecode = dict()
        contracts_db = EthereumDatabase(
            '/mnt/data/bigquery/ethereum_contracts', db_name='contracts')
        for con in contracts_db.get_all_connnections():
            print(con)
            for row in con.read('contracts', '*'):
                create_time[row['address']] = row['block_timestamp']
                bytecode[row['address']] = row['bytecode']
        self.create_time = create_time
        self.bytecode = bytecode

    def get_day2txs_and_month2txs(self):
        day2txs = dict()
        month2txs = dict()

        for tx_hash in self.txs:
            day = self.txs[tx_hash]['block_timestamp'][:10]
            if day not in day2txs:
                day2txs[day] = defaultdict(set)
            month = self.txs[tx_hash]['block_timestamp'][:7]
            if month not in month2txs:
                month2txs[month] = defaultdict(set)
            for checker in self.txs[tx_hash]['attack_details']:
                # if checker['checker'] == 'integer-overflow':
                #     for attack in checker['attacks']:
                #         if attack['func_name'] in integer_flow_sensitive_function:
                #             day2txs[day][checker['checker']].add(tx_hash)
                #             month2txs[month][checker['checker']].add(tx_hash)
                #             break
                # else:
                #     day2txs[day][checker['checker']].add(tx_hash)
                #     month2txs[month][checker['checker']].add(tx_hash)
                day2txs[day][checker['checker']].add(tx_hash)
                month2txs[month][checker['checker']].add(tx_hash)
        if self.cad_txs != None:
            for d in day2txs:
                day2txs[d]['call-after-destruct'].clear()
            for m in month2txs:
                month2txs[m]['call-after-destruct'].clear()
            for tx_hash in self.cad_txs:
                day = self.cad_txs[tx_hash]['time'][:10]
                if day not in day2txs:
                    day2txs[day] = defaultdict(set)
                month = self.cad_txs[tx_hash]['time'][:7]
                if month not in month2txs:
                    month2txs[month] = defaultdict(set)
                day2txs[day]['call-after-destruct'].add(tx_hash)
                month2txs[month]['call-after-destruct'].add(tx_hash)

        if self.ci_txs != None:
            for d in day2txs:
                day2txs[d]['call-injection'].clear()
            for m in month2txs:
                month2txs[m]['call-injection'].clear()
            for tx_hash in self.ci_txs:
                d = self.ci_txs[tx_hash]['time'][:10]
                m = self.ci_txs[tx_hash]['time'][:7]
                if d not in day2txs:
                    day2txs[d] = defaultdict(set)
                if m not in month2txs:
                    month2txs[m] = defaultdict(set)
                day2txs[d]['call-injection'].add(tx_hash)
                month2txs[m]['call-injection'].add(tx_hash)

        self.day2txs, self.month2txs = day2txs, month2txs

    def get_vuls_info(self):
        vul2txs = defaultdict(set)
        vul2contrs = defaultdict(set)
        contr2txs = defaultdict(dict)
        vul2contrs_open_sourced = defaultdict(set)

        for tx_hash in self.txs:
            for checker in self.txs[tx_hash]['attack_details']:
                name = checker['checker']
                vul2txs[name].add(tx_hash)
                if name == 'integer-overflow':
                    for attack in checker['attacks']:
                        # if attack['func_name'] not in integer_flow_sensitive_function:
                        #     continue
                        vul2txs[name].add(tx_hash)
                        node = attack['edge'][1]
                        address = node.split(":")[1]
                        vul2contrs[name].add(address)
                        if address in self.open_sourced_contract:
                            vul2contrs_open_sourced[name].add(address)
                        if address not in contr2txs[name]:
                            contr2txs[name][address] = set()
                        contr2txs[name][address].add(tx_hash)
                elif name == 'call-injection':
                    vul2txs[name].add(tx_hash)
                    for attack in checker['attacks']:
                        node = attack['edge'][1]
                        address = node.split(":")[1]
                        vul2contrs[name].add(address)
                        if address in self.open_sourced_contract:
                            vul2contrs_open_sourced[name].add(address)
                        if address not in contr2txs[name]:
                            contr2txs[name][address] = set()
                        contr2txs[name][address].add(tx_hash)
                elif name == 'reentrancy':
                    vul2txs[name].add(tx_hash)
                    for attack in checker['attacks']:
                        cycle = attack['cycle']
                        cycle.sort()
                        addrs = tuple(cycle)
                        if addrs not in self.reen_addrs2target:
                            continue
                        address = self.reen_addrs2target[addrs]
                        vul2contrs[name].add(address)
                        if address in self.open_sourced_contract:
                            vul2contrs_open_sourced[name].add(address)
                        if addrs not in contr2txs[name]:
                            contr2txs[name][address] = set()
                        contr2txs[name][address].add(tx_hash)
                elif name == 'airdrop-hunting':
                    vul2txs[name].add(tx_hash)
                    token_address = ''
                    m_amount = 0
                    for node in checker['profit']:
                        for row in checker['profit'][node][ResultType.TOKEN_TRANSFER]:
                            amount = row[1]
                            token = row[0]
                            if amount > m_amount:
                                token_address = token
                                m_amount = amount
                    vul2contrs[name].add(token_address)
                    if token_address in self.open_sourced_contract:
                        vul2contrs_open_sourced[name].add(token_address)
                    if token_address not in contr2txs[name]:
                        contr2txs[name][token_address] = set()
                    contr2txs[name][token_address].add(tx_hash)

        for row in self.honeypot:
            vul2contrs['honeypot'].add(row[1])
        for c in vul2contrs['honeypot']:
            if c in self.open_sourced_contract:
                vul2contrs_open_sourced['honeypot'].add(c)

        if self.cad_txs != None:
            vul2txs['call-after-destruct'].clear()
            vul2contrs['call-after-destruct'].clear()
            vul2contrs_open_sourced['call-after-destruct'].clear()
            contr2txs['call-after-destruct'].clear()
            for tx_hash in self.cad_txs:
                vul2txs['call-after-destruct'].add(tx_hash)
                for d in self.cad_txs[tx_hash]['detail']:
                    vul2contrs['call-after-destruct'].add(d['contract'])
                    if d['contract'] in self.open_sourced_contract:
                        vul2contrs_open_sourced['call-after-destruct'].add(d['contract'])
                    if d['contract'] not in contr2txs['call-after-destruct']:
                        contr2txs['call-after-destruct'][d['contract']] = set()
                    contr2txs['call-after-destruct'][d['contract']].add(tx_hash)

        if self.ci_txs != None:
            vul2txs['call-injection'].clear()
            vul2contrs['call-injection'].clear()
            contr2txs['call-injection'].clear()
            for tx_hash in self.ci_txs:
                vul2txs['call-injection'].add(tx_hash)
                vul2contrs['call-injection'].add(self.ci_txs[tx_hash]['entry'])
                if self.ci_txs[tx_hash]['entry'] not in contr2txs['call-injection']:
                    contr2txs['call-injection'][self.ci_txs[tx_hash]['entry']] = set()
                contr2txs['call-injection'][self.ci_txs[tx_hash]['entry']].add(tx_hash)

        self.vul2txs, self.vul2contrs, self.vul2contrs_open_sourced, self.contr2txs = vul2txs, vul2contrs, vul2contrs_open_sourced, contr2txs

    def replace_overflow_wt_old(self, overflow_pickle_file):
        with open(overflow_pickle_file, 'rb') as f:
            flow = pickle.load(f)
        self.old_overflow = flow
        contrs = set()
        contrs_open_sourced = set()
        txs = set()
        contr2txs = defaultdict(set)
        for c in flow:
            contrs.add(c)
            if c in self.open_sourced_contract:
                contrs_open_sourced.add(c)
            for row in flow[c]:
                txs.add(row[0])
                contr2txs[c].add(row[0])
        self.vul2contrs['integer-overflow'] = contrs
        self.vul2contrs_open_sourced['integer-overflow'] = contrs_open_sourced = set()
        self.vul2txs['integer-overflow'] = txs
        self.contr2txs['integer-overflow'] = contr2txs

    def papers_cmp_ours_wt_vul(self, vul2contrs):
        paper_inter_ours = dict()
        paper_resid_ours_open_sourced = dict()

        for p in self.papers_result:
            paper_inter_ours[p] = defaultdict(set)
            paper_resid_ours_open_sourced[p] = defaultdict(set)
            for v in self.papers_result[p]:
                if v in define_map[p]:
                    mp = define_map[p][v]
                    for c in self.papers_result[p][v]:
                        if c in vul2contrs[mp]:
                            paper_inter_ours[p][mp].add(c)
                        else:
                            if c in self.open_sourced_contract:
                                paper_resid_ours_open_sourced[p][v].add(c)
        return {'paper_inter_ours': paper_inter_ours, 'paper_resid_ours_open_sourced': paper_resid_ours_open_sourced}

    def papers_cmp_ours_wo_vul(self, vul2contrs):
        paper_candidates = defaultdict(set)
        our_candidates = set()
        reported = defaultdict(set)
        not_reported = defaultdict(set)
        resid_ours = defaultdict(set)

        for p in self.papers_result:
            for v in self.papers_result[p]:
                for c in self.papers_result[p][v]:
                    paper_candidates[p].add(c)

        for v in vul2contrs:
            for c in vul2contrs[v]:
                our_candidates.add(c)

        for c in our_candidates:
            for p in paper_candidates:
                if c in paper_candidates[p]:
                    reported[p].add(c)
                elif c in self.create_time and time_to_str(self.create_time[c]) <= dataset_latest_time[p]:
                    not_reported[p].add(c)

        for p in paper_candidates:
            for c in paper_candidates[p]:
                if c not in our_candidates:
                    resid_ours[p].add(c)

        return {'paper_candidates': paper_candidates, 'our_candidates': our_candidates, 'reported': reported, 'not_reported': not_reported, 'resid_ours': resid_ours}

    def get_contr_popularity(self, paper_candidates, our_candidates):
        reported_contr_popularity = dict()
        attacked_contr_popularity = dict()
        for p in paper_candidates:
            for c in paper_candidates[p]:
                reported_contr_popularity[c] = {
                    'failed': defaultdict(set), 'normal': defaultdict(set)}
        for c in our_candidates:
            attacked_contr_popularity[c] = {
                'failed': defaultdict(set), 'normal': defaultdict(set)}

        trace_db = EthereumDatabase('/mnt/data/bigquery/ethereum_traces')
        for con in trace_db.get_all_connnections():
            print(con)
            m = con.date[:7]
            for row in con.read_traces():
                if row['status'] == 0:
                    ty = 'failed'
                else:
                    ty = 'normal'
                if row['from_address'] in reported_contr_popularity:
                    reported_contr_popularity[row['from_address']][ty][m].add(
                        row['transaction_hash'])
                if row['from_address'] in attacked_contr_popularity:
                    attacked_contr_popularity[row['from_address']][ty][m].add(
                        row['transaction_hash'])

                if row['to_address'] in reported_contr_popularity:
                    reported_contr_popularity[row['to_address']][ty][m].add(
                        row['transaction_hash'])
                if row['to_address'] in attacked_contr_popularity:
                    attacked_contr_popularity[row['to_address']][ty][m].add(
                        row['transaction_hash'])

        for c in reported_contr_popularity:
            for ty in reported_contr_popularity[c]:
                for m in reported_contr_popularity[c][ty]:
                    reported_contr_popularity[c][ty][m] = len(
                        reported_contr_popularity[c][ty][m])

        for c in attacked_contr_popularity:
            for ty in attacked_contr_popularity[c]:
                for m in attacked_contr_popularity[c][ty]:
                    attacked_contr_popularity[c][ty][m] = len(
                        attacked_contr_popularity[c][ty][m])

        return {'reported_contr_popularity': reported_contr_popularity, 'attacked_contr_popularity': attacked_contr_popularity}

    def dat_contr_month_popularity(self, paper_candidates, reported_contr_popularity, attacked_contr_popularity):
        begin = datetime(2015, 8, 1, 0, 0)
        normal_month_popularity = dict()
        failed_month_popularity = dict()
        while begin < datetime(2019, 4, 1, 0, 0):
            normal_month_popularity[month_to_str(begin)] = {
                'vandal': 0,
                'zeus': 0,
                'oyente': 0,
                'securify': 0,
                'HoneyBadger': 0,
                'papers': 0,
                'ours': 0
            }
            failed_month_popularity[month_to_str(begin)] = {
                'vandal': 0,
                'zeus': 0,
                'oyente': 0,
                'securify': 0,
                'HoneyBadger': 0,
                'papers': 0,
                'ours': 0
            }
            begin += relativedelta(months=1)

        for c in attacked_contr_popularity:
            for ty in attacked_contr_popularity[c]:
                for m in attacked_contr_popularity[c][ty]:
                    if ty == 'normal':
                        normal_month_popularity[m]['ours'] += attacked_contr_popularity[c][ty][m]
                    else:
                        failed_month_popularity[m]['ours'] += attacked_contr_popularity[c][ty][m]

        for p in paper_candidates:
            for c in paper_candidates[p]:
                if c not in reported_contr_popularity:
                    continue
                for ty in reported_contr_popularity[c]:
                    for m in reported_contr_popularity[c][ty]:
                        if ty == 'normal':
                            normal_month_popularity[m][p] += reported_contr_popularity[c][ty][m]
                            normal_month_popularity[m]['papers'] += reported_contr_popularity[c][ty][m]
                        else:
                            failed_month_popularity[m][p] += len(
                                reported_contr_popularity[c][ty][m])
                            failed_month_popularity[m]['papers'] += reported_contr_popularity[c][ty][m]

        return {'normal_month_popularity_dat': normal_month_popularity, 'failed_month_popularity_dat': failed_month_popularity}

    def dat_month2txs(self, month2txs):
        begin = datetime(2015, 8, 1, 0, 0)
        month2txs_dat = dict()
        while begin < datetime(2019, 4, 1, 0, 0):
            month2txs_dat[month_to_str(begin)] = {
                'airdrop-hunting': 0,
                'reentrancy': 0,
                'integer-overflow': 0,
                'call-injection': 0,
                'call-after-destruct': 0,
                'honeypot': 0
            }
            begin += relativedelta(months=1)

        for m in month2txs:
            for v in month2txs[m]:
                month2txs_dat[m][v] = len(month2txs[m[v]])

        return month2txs_dat

    def dat_contract_cdf(self):
        contr_cdf_dat = defaultdict(dict)
        for i in range(1, 101):
            contr_cdf_dat[i] = {
                'airdrop-hunting': 0,
                'reentrancy': 0,
                'integer-overflow': 0,
                'call-injection': 0,
                'call-after-destruct': 0,
                'honeypot': 0
            }
        for v in self.contr2txs:
            rows = []
            for c in self.contr2txs[v]:
                rows.append((c, len(self.contr2txs[v][c])))
            rows.sort(reverse=True, key=lambda x: x[1])
            l = len(rows)
            for i in range(1, l+1):
                row = rows[i-1]
                pos = int(i*100/l) if int(i*100/l) == i * \
                    100/l else int(i*100/l+1)
                contr_cdf_dat[pos][v] += row[1]*100/len(self.vul2txs[v])
        for i in contr_cdf_dat:
            for v in contr_cdf_dat[i]:
                if contr_cdf_dat[i][v] == 0:
                    if i != 1:
                        contr_cdf_dat[i][v] = '?'
        return contr_cdf_dat

    def get_code2txs(self, fixed_vul2contrs):
        code2txs = dict()
        for v in self.contr2txs:
            code2txs[v] = defaultdict(set)
            for c in fixed_vul2contrs[v]:
                if c not in self.open_sourced_contract:
                    continue
                code = self.open_sourced_contract[c]
                h = sha256(code.encode('utf-8')).hexdigest()
                for tx_hash in self.contr2txs[v][c]:
                    code2txs[v][h].add(tx_hash)
        self.code2txs = code2txs
        return code2txs

    def dat_code_cdf(self):
        code_cdf_dat = defaultdict(dict)
        for i in range(1, 101):
            code_cdf_dat[i] = {
                'airdrop-hunting': 0,
                'reentrancy': 0,
                'integer-overflow': 0,
                'call-injection': 0,
                'call-after-destruct': 0,
                'honeypot': 0
            }
        for v in self.code2txs:
            rows = []
            for h in self.code2txs[v]:
                rows.append((h, len(self.contr2txs[v][h])))
            rows.sort(reverse=True, key=lambda x: x[1])
            l = len(rows)
            for i in range(1, l+1):
                row = rows[i-1]
                pos = int(i*100/l) if int(i*100/l) == i * \
                    100/l else int(i*100/l+1)
                code_cdf_dat[pos][v] += row[1]*100/len(self.vul2txs[v])
        for i in code_cdf_dat:
            for v in code_cdf_dat[i]:
                if code_cdf_dat[i][v] == 0:
                    if i != 1:
                        code_cdf_dat[i][v] = '?'
        return code_cdf_dat

    def get_bytecode2txs(self):
        bytecode2txs = dict()
        for v in self.contr2txs:
            bytecode2txs[v] = defaultdict(set)
            for c in self.contr2txs[v]:
                if c not in self.bytecode:
                    continue
                code = self.bytecode[c]
                h = sha256(code.encode('utf-8')).hexdigest()
                for tx_hash in self.contr2txs[v][c]:
                    bytecode2txs[v][h].add(tx_hash)
        self.bytecode2txs = bytecode2txs
        return bytecode2txs

    def dat_bytecode_cdf(self):
        bytecode_cdf_dat = defaultdict(dict)
        for i in range(1, 101):
            bytecode_cdf_dat[i] = {
                'airdrop-hunting': 0,
                'reentrancy': 0,
                'integer-overflow': 0,
                'call-injection': 0,
                'call-after-destruct': 0,
                'honeypot': 0
            }
        for v in self.bytecode2txs:
            rows = []
            for h in self.bytecode2txs[v]:
                rows.append((h, len(self.bytecode2txs[v][h])))
            rows.sort(reverse=True, key=lambda x: x[1])
            l = len(rows)
            for i in range(1, l+1):
                row = rows[i-1]
                pos = int(i*100/l) if int(i*100/l) == i * \
                    100/l else int(i*100/l+1)
                bytecode_cdf_dat[pos][v] += row[1]*100/len(self.vul2txs[v])
        for i in bytecode_cdf_dat:
            for v in bytecode_cdf_dat[i]:
                if bytecode_cdf_dat[i][v] == 0:
                    if i != 1:
                        bytecode_cdf_dat[i][v] = '?'
        return bytecode_cdf_dat

    @staticmethod
    def get_contract_attrs(eu):
        contract_attrs = dict()
        for tx_hash in eu.txs:
            for checker in eu.txs[tx_hash]['attack_details']:
                name = checker['checker']
                time = eu.txs[tx_hash]['block_timestamp']
                # if name == 'integer-overflow':
                #     for attack in checker['attacks']:
                #         if attack['func_name'] not in integer_flow_sensitive_function:
                #             continue
                #         node = attack['edge'][1]
                #         address = node.split(":")[1]
                #         if address not in eu.create_time:
                #             continue
                #         if address not in contract_attrs:
                #             contract_attrs[address] = {'create_time': time_to_str(eu.create_time[address]), 'attacked_time': set(), 'vul_type': set()}
                #         contract_attrs[address]['attacked_time'].add(time)
                #         contract_attrs[address]['vul_type'].add(name)
                # if name == 'call-injection':
                #     for attack in checker['attacks']:
                #         node = attack['edge'][1]
                #         address = node.split(":")[1]
                #         if address not in contract_attrs:
                #             contract_attrs[address] = {'create_time': time_to_str(eu.create_time[address]), 'attacked_time': set(), 'vul_type': set()}
                #         contract_attrs[address]['attacked_time'].add(time)
                #         contract_attrs[address]['vul_type'].add(name)
                if name == 'reentrancy':
                    for attack in checker['attacks']:
                        cycle = attack['cycle']
                        cycle.sort()
                        addrs = tuple(cycle)
                        if addrs not in eu.reen_addrs2target:
                            continue
                        addr = eu.reen_addrs2target[addrs]
                        if addr not in contract_attrs:
                            contract_attrs[addr] = {'create_time': time_to_str(eu.create_time[addr]), 'attacked_time': set(), 'vul_type': set()}
                        contract_attrs[addr]['attacked_time'].add(time)
                        contract_attrs[addr]['vul_type'].add(name)
                elif name == 'airdrop-hunting':
                    token_address = ''
                    m_amount = 0
                    for node in checker['profit']:
                        for row in checker['profit'][node][ResultType.TOKEN_TRANSFER]:
                            amount = row[1]
                            token = row[0]
                            if amount > m_amount:
                                token_address = token
                                m_amount = amount
                    if token_address not in contract_attrs:
                        contract_attrs[token_address] = {'create_time': time_to_str(eu.create_time[token_address]), 'attacked_time': set(), 'vul_type': set()}
                    contract_attrs[token_address]['attacked_time'].add(time)
                    contract_attrs[token_address]['vul_type'].add(name)

        for tx_hash in eu.ci_txs:
            row = eu.ci_txs[tx_hash]
            c = row['entry']
            if c not in eu.create_time:
                    continue
            if c not in contract_attrs:
                contract_attrs[c] = {'create_time': time_to_str(eu.create_time[c]), 'attacked_time': set(), 'vul_type': set()}
            contract_attrs[c]['vul_type'].add('call-injection')
            contract_attrs[c]['attacked_time'].add(row['time'])

        for p in eu.papers_result:
            for v in eu.papers_result[p]:
                if v not in define_map[p]:
                    continue
                mv = define_map[p][v]
                for c in eu.papers_result[p][v]:
                    if c not in eu.create_time:
                        continue
                    if c not in contract_attrs:
                        contract_attrs[c] = {'create_time': time_to_str(eu.create_time[c]), 'attacked_time': set(), 'vul_type': set()}
                    contract_attrs[c]['vul_type'].add(mv)

        for c in eu.old_overflow:
            if c not in eu.create_time:
                continue
            if c not in contract_attrs:
                contract_attrs[c] = {'create_time': time_to_str(eu.create_time[c]), 'attacked_time': set(), 'vul_type': set()}
            for row in eu.old_overflow[c]:
                contract_attrs[c]['attacked_time'].add(row[1])

        for row in eu.honeypot:
            if row[1] not in eu.create_time:
                continue
            if row[1] not in contract_attrs:
                contract_attrs[row[1]] = {'create_time': time_to_str(eu.create_time[row[1]]), 'attacked_time': set(), 'vul_type': set()}
            contract_attrs[row[1]]['vul_type'].add('honeypot')

        for tx_hash in eu.cad_txs:
            for d in eu.cad_txs[tx_hash]['detail']:
                c = d['contract']
                if c not in eu.create_time:
                    continue
                if c not in contract_attrs:
                    contract_attrs[c] = {'create_time': time_to_str(eu.create_time[c]), 'attacked_time': set(), 'vul_type': set()}
                contract_attrs[c]['vul_type'].add('call-after-destruct')
