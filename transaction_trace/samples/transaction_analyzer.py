import os
import sys
import time

import transaction_trace
from transaction_trace.analysis import TransactionAnalyzer


def main(db_folder, from_time, to_time, log_path):
    with open(os.path.join(log_path, "transaction-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        analyzer = TransactionAnalyzer(db_folder, log_file)
        analyzer.find_honeypot(from_time, to_time)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
