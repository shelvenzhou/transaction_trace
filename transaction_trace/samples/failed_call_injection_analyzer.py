import os
import sys
import time
from collections import defaultdict

from transaction_trace.local.ethereum_database import EthereumDatabase


def main(db_folder, from_time, to_time, log_file):
    call_injection = defaultdict(set)
    with open(log_file, "r") as f:
        for line in f.readlines():
            if "CallInjection" in line:
                entry_pos = line.find("entry")
                entry = line[entry_pos + 7: entry_pos + 49]
                func_pos = line.find("func")
                func = line[func_pos + 6: func_pos + 16]
                call_injection[entry].add(func)

    log_path = log_file.strip(log_file.split("/")[-1])
    with open(os.path.join(log_path, "failed-call-injection-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        db = EthereumDatabase(db_folder)
        for db_conn in db.get_connections(from_time, to_time):
            pass


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s db_folder from_time to_time log_file" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
