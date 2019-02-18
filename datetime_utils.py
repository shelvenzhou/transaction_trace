from datetime import datetime

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DATE_FORMAT = "%Y-%m-%d"
MONTH_FORMAT = "%Y-%m"

def time_to_str(t):
    return t.strftime(DATETIME_FORMAT)


def str_to_time(s):
    return datetime.strptime(s, DATETIME_FORMAT)

def date_to_str(d):
    return d.strftime(DATE_FORMAT)

def month_to_str(m):
    return m.strftime(MONTH_FORMAT)
