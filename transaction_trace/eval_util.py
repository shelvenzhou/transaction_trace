from collections import defaultdict
from datetime import datetime
from dateutil.relativedelta import relativedelta
import sqlite3
import pickle
from web3 import Web3
from hashlib import sha256

from .local import EthereumDatabase
from .datetime_utils import time_to_str, month_to_str
from .analysis.intermediate_representations import ResultType


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
    }
}

dataset_latest_time = {
    'vandal': '2018-08-30',
    'zeus': '2017-03-15 09:45:39',
    'oyente': '2016-05-05',
    'securify': '2017-03-04 05:31:21'
}


class EvalUtil:
    def __init__(self, log_file, cad_log_file, papers_result, ci_log_file=None):
        self.log_file = log_file
        self.cad_log_file = cad_log_file
        self.papers_result = papers_result
        self.ci_log_file = ci_log_file

        self.txs = None
        self.cad_txs = None
        self.ci_txs = None

        self.open_sourced_contract = None
        self.create_time = None

        self.day2txs = None
        self.month2txs = None

        self.vul2txs = None
        self.vul2contrs = None
        self.contr2txs = None
        self.code2txs = None

        self.vul2contrs_open_sourced = None

    def tmp_process_honeypot_log(self, honeypot_log_file):
        f = open(honeypot_log_file, 'r')
        lines = f.readlines()
        rows = []
        for line in lines:
            if 'Closed profited' in line:
                time = line.split('[')[1].split(']')[0]
                contr = line.split(' ')[-1]
                rows.append((time, contr))

        self.honeypot = rows
        return rows

    def process_data(self):
        f = open(log_file, 'r')
        lines = f.readlines()
        rows = []
        for line in lines:
            rows.append(eval(line.strip('\n')))
        txs = dict()
        for row in rows:
            txs[row['tx_hash']] = row
        self.txs = txs

        f = open(cad_log_file, 'r')
        lines = f.readlines()
        rows = []
        for line in lines:
            rows.append(eval(line.strip('\n')))
        cad_txs = dict()
        for row in rows:
            cad_txs[row['tx_hash']] = row
        self.cad_txs = cad_txs

        f = open(ci_log_file, 'r')
        lines = f.readlines()
        rows = []
        for line in lines:
            rows.append(eval(line.strip('\n')))
        ci_txs = dict()
        for row in rows:
            ci_txs[row['tx_hash']] = row
        self.ci_txs = cad_txs

        open_sourced_contract = dict()
        etherscan_db = sqlite3.connect(
            '/home/xiangjie/database/etherscan.sqlite3')
        for row in etherscan_db.execute('select ContractAddress, SourceCode from contracts'):
            if row[1] != '':
                open_sourced_contract[row[0]] = row[1]
        self.open_sourced_contract = open_sourced_contract

        create_time = dict()
        contracts_db = EthereumDatabase(
            '/mnt/data/bigquery/ethereum_contracts', db_name='contracts')
        for con in contracts_db.get_all_connnections():
            print(con)
            for row in con.read('contracts', '*'):
                create_time[row['address']] = row['block_timestamp']
        self.create_time = create_time

    def get_day2txs_and_month2txs(self):
        day2txs = dict()
        month2txs = dict()

        for tx_hash in self.txs:
            day = self.txs[tx_hash]['block_timestamp'][:10]
            if day not in day2txs:
                day2txs[day] = defaultdict(set)
            month = txs[tx_hash]['block_timestamp'][:7]
            if month not in month2txs:
                month2txs[month] = defaultdict(set)
            for checker in self.txs[tx_hash]['attack_details']:
                day2txs[day][checker['checker']].add(tx_hash)
                month2txs[month][checker['checker']].add(tx_hash)

        for tx_hash in self.cad_txs:
            day = self.cad_txs[tx_hash]['time'][:10]
            if day not in day2txs:
                day2txs[day] = defaultdict(set)
            month = cad_txs[tx_hash]['time'][:7]
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
                day2txs[d]['call-injection'].add(tx_hash)
                month2txs[m]['call-injection'].add(tx_hash)

        self.day2txs, self.month2txs = day2txs, month2txs
        return {'day2txs': day2txs, 'month2txs': month2txs}

    def get_vul2txs_and_vul2conts(self):
        vul2txs = defaultdict(set)
        vul2contrs = defaultdict(set)
        contr2txs = defaultdict(dict)

        for tx_hash in self.txs:
            for checker in txs[tx_hash]['attack_details']:
                name = checker['checker']
                vul2txs[name].add(tx_hash)
                if name in ('call-injection', 'integer-overflow'):
                    for attack in checker['attacks']:
                        node = attack['edge'][1]
                        address = node.split(":")[1]
                        vul2contracts[name].add(address)
                        if address not in contr2txs[name]:
                            contr2txs[name][address] = set()
                        contr2txs[name][address].add(tx_hash)
                elif name == 'reentrancy':
                    for attack in checker['attacks']:
                        cycle = attack['cycle']
                        cycle.sort()
                        addrs = tuple(cycle)
                        vul2contrs[name].add(addrs)
                        if addrs not in contr2txs[name]:
                            contr2txs[name][addrs] = set()
                        contr2txs[name][addrs].add(tx_hash)
                elif name == 'airdrop-hunting':
                    token_address = ''
                    m_amount = 0
                    for node in checker['profit']:
                        for token in checker['profit'][node][ResultType.TOKEN_TRANSFER]:
                            amount = checker['profit'][node][ResultType.TOKEN_TRANSFER][token]
                            if amount > m_amount:
                                token_address = token
                                m_amount = amount
                    vul2contrs[name].add(token_address)
                    if token_address not in contr2txs[name]:
                        contr2txs[name][token_address] = set()
                    contr2txs[name][token_address].add(tx_hash)

        for tx_hash in self.cad_txs:
            vul2txs['call-after-destruct'].add(tx_hash)
            for d in self.cad_txs[tx]['detail']:
                vul2contrs['call-after-destruct'].add(d['contract'])

        if self.ci_txs != None:
            vul2txs['call-injection'].clear()
            vul2contrs['call-injection'].clear()
            for tx_hash in self.ci_txs:
                vul2txs['call-injection'].add(tx_hash)
                vul2contrs['call-injection'].add(self.ci_txs[tx_hash]['entry'])

        self.vul2txs, self.vul2contrs, self.contr2txs = vul2txs, vul2contrs, contr2txs
        return {'vul2txs': vul2txs, 'vul2contrs': vul2contrs, 'contr2txs': contr2txs}

    def get_vul2contrs_open_sourced(self, vul2contrs):
        vul2contrs_open_sourced = defaultdict(set)
        for v in vul2contrs:
            if v == 'reentrancy':
                open_sourced_contrs = list()
                for addrs in vul2contrs[v]:
                    open_sourced_contrs = list()
                    for c in addrs:
                        if c in self.open_sourced_contract:
                            open_sourced_contrs.append(c)
                    if len(open_sourced_contrs) > 0:
                        vul2contrs_open_sourced[v].add(
                            tuple(open_sourced_contrs))
            for c in vul2contrs[v]:
                if c in self.open_sourced_contract:
                    vul2contrs_open_sourced[v].add(c)

        self.vul2contrs_open_sourced = vul2contrs_open_sourced
        return vul2contrs_open_sourced

    def papers_cmp_ours_wt_vul(self, vul2contrs):
        paper_inter_ours = defaultdict(set)
        paper_resid_ours_open_sourced = defaultdict(set)

        for p in self.papers_result:
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

        for p in self.papers_result:
            for v in self.papers_result[p]:
                for c in self.papers_result[p][v]:
                    candidates[p].add(c)

        for v in vul2contrs:
            for c in vul2contrs[v]:
                our_candidates.add(c)

        for c in our_candidates:
            for p in paper_candidates:
                if c in paper_candidates[p]:
                    reported[p].add(c)
                elif c in create_time and time_to_str(create_time[c]) <= dataset_latest_time[p]:
                    not_reported[p].add(c)

        return {'paper_candidates': paper_candidates, 'our_candidates': our_candidates, 'reported': reported, 'not_reported': not_reported}

    def fix_reen_contrs(self, addrs2contr):
        fixed_vul2contrs = defaultdict(set)
        fixed_vul2contrs_open_sourced = defaultdict(set)
        fixed_contr2txs = defaultdict(dict)

        for v in self.vul2contrs:
            if v == 'reentrancy':
                for addrs in self.vul2contrs[v]:
                    contr = addrs2contr[addrs]
                    fixed_vul2contrs[v].add(contr)
                    if contr in self.open_sourced_contract:
                        fixed_vul2contrs_open_sourced[v].add(contr)
            else:
                fixed_vul2contrs[v] = self.vul2contrs[v]
                fixed_vul2contrs_open_sourced[v] = self.vul2contrs_open_sourced[v]

        for v in self.contr2txs:
            if v == 'reentrancy':
                for addrs in self.contr2txs[v]:
                    contr = addrs2contr[addrs]
                    fixed_contr2txs[v][contr] = self.contr2txs[v][addrs]
            else:
                fixed_contr2txs[v] = self.contr2txs[v]

        self.vul2contrs, self.vul2contrs_open_sourced, self.contr2txs = fixed_vul2contrs, fixed_vul2contrs_open_sourced, fixed_contr2txs

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

    def dat_month2txs(self, month2txs):
        begin = datetime(2015, 8, 1, 0, 0)
        month2txs_dat = dict()
        while begin < datetime(2018, 4, 1, 0, 0):
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
                pos = int(i*100/l) if int(i*100/l) == i*100/l else int(i*100/l+1)
                contr_cdf_dat[pos][v] += row[1]*100/len(self.vul2txs[v])
        for i in contr_cdf_dat:
            for v in contr_cdf_dat[i]:
                if contr_cdf_dat[i][v] == 0:
                    if i != 1:
                        contr_cdf_dat[i][v] = '?'
        return contr_cdf_dat

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
                pos = int(i*100/l) if int(i*100/l) == i*100/l else int(i*100/l+1)
                contr_cdf_dat[pos][v] += row[1]*100/len(self.vul2txs[v])
        for i in code_cdf_dat:
            for v in code_cdf_dat[i]:
                if code_cdf_dat[i][v] == 0:
                    if i != 1:
                        code_cdf_dat[i][v] = '?'
        return code_cdf_dat
