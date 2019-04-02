
import sys
from transaction_trace.analysis.traffic import TrafficAnalyzer


def main(db_folder, from_time, to_time, t, log_path):
    traffic_analyzer = TrafficAnalyzer(db_folder, log_path)
    traffic_analyzer.find_block_jam(from_time, to_time, t)


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 %s db_folder from_time to_time t log_path" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
