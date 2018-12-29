from datetime import datetime

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def time_to_str(t):
    return t.strftime(DATETIME_FORMAT)


def str_to_time(s):
    return datetime.strptime(s, DATETIME_FORMAT)
