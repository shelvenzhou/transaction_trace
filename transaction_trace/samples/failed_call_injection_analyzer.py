import os
import sys
import time

from transaction_trace.analysis import AuthorityAnalyzer



def main(db_folder, from_time, to_time, input_log):
    log_path = input_log.strip(input_log.split("/")[-1])
    with open(os.path.join(log_path, "authority-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        authority_analyzer = AuthorityAnalyzer(db_folder, log_file)
        authority_analyzer.find_failed_call_injection(from_time, to_time, input_log)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time input_log" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
