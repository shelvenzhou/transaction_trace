from datetime import datetime

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def time_to_str(t):
    return t.strftime(DATETIME_FORMAT)


def str_to_time(s):
    try:
        time = datetime.strptime(s, DATETIME_FORMAT)
    except ValueError:
        try:
            time = datetime.strptime(s, "%a %b %d %H:%M:%S %Y")
        except ValueError:
            print(ValueError)
    return time
