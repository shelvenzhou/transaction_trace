import sys

import transaction_trace
from transaction_trace.analysis import SubtraceBuilder


def main(db_folder, from_time, to_time):
    subtrace_builder = SubtraceBuilder(db_folder)
    subtrace_builder.build_subtrace(from_time, to_time)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 %s db_folder from_time to_time" % sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
