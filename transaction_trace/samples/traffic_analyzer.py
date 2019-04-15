
import sys
import os
import time
from transaction_trace.analysis.traffic import TrafficAnalyzer


def main(db_folder, db_name, from_time, to_time, t, log_path):
    with open(os.path.join(log_path, "traffic-analyzer-%s.log" % str(time.strftime('%Y%m%d%H%M%S'))), "w+") as log_file:
        traffic_analyzer = TrafficAnalyzer(db_folder, db_name, log_file)
        traffic_analyzer.find_block_jam(from_time, to_time, t)


if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python3 %s db_folder db_name from_time to_time t log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3],
         sys.argv[4], sys.argv[5], sys.argv[6])
