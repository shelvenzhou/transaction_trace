from datetime import datetime

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DATE_FORMAT = "%Y-%m-%d"


def time_to_str(t):
    return t.strftime(DATETIME_FORMAT)


def str_to_time(s):
    return datetime.strptime(s, DATETIME_FORMAT)

def date_to_str(d):
    return d.strftime(DATE_FORMAT)
