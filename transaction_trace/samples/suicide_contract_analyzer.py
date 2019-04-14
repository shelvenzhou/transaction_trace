import os
import sys
import time

from transaction_trace.analysis.contract import Contract


def main(db_folder, from_time, to_time, log_path):
    with open(os.path.join(log_path, "suicide-contract-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        contract_analyzer = Contract(db_folder, log_file)
        contract_analyzer.find_call_after_destruct(from_time, to_time)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
