import json
import logging
import os
import pickle
import sys
import time
from collections import defaultdict

import transaction_trace
from transaction_trace.analysis import (ContractCentricAnalysis, PreProcess,
                                        TransactionCentricAnalysis)
from transaction_trace.analysis.checkers import *
from transaction_trace.analysis.intermediate_representations import Transaction
from transaction_trace.analysis.results import AttackCandidateExporter
from transaction_trace.analysis.trace_analysis import TraceAnalysis

l = logging.getLogger('analysis_pipeline')


def main(db_folder, tx_filepath):
    with open(tx_filepath, "r") as f:
        success_attack_txs = json.load(f)

    all_txs = set()
    tx_times = dict()
    for vul, txs in success_attack_txs.items():
        for tx in txs:
            all_txs.add(tx)

    p = TraceAnalysis(db_folder=db_folder)
    for conn in p.database.get_all_connnections():
        l.info("construct for %s", conn)
        for row in conn.read_traces():
            if row['trace_type'] not in ('call', 'create', 'suicide'):
                l.debug("ignore trace of type %s", row['trace_type'])
                continue

            if row['status'] == 0:
                continue

            block_number = row["block_number"]
            tx_index = row["transaction_index"]
            tx_hash = row["transaction_hash"]
            rowid = row['rowid']

            if block_number is None or tx_index is None:
                continue

            if tx_hash in all_txs and tx_hash not in tx_times:
                tx_times[tx_hash] = row['block_timestamp']


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 %s db_folder tx_filepath" % sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2])
