from datetime import datetime

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DATE_FORMAT = "%Y-%m-%d"
MONTH_FORMAT = "%Y-%m"


class DatetimeUtils:

    @staticmethod
    def time_to_str(t):
        return t.strftime(DATETIME_FORMAT)

    @staticmethod
    def str_to_time(s):
        return datetime.strptime(s, DATETIME_FORMAT)

    @staticmethod
    def date_to_str(d):
        return d.strftime(DATE_FORMAT)

    @staticmethod
    def str_to_date(s):
        return datetime.strptime(s, DATE_FORMAT)

    @staticmethod
    def month_to_str(m):
        return m.strftime(MONTH_FORMAT)

    @staticmethod
    def str_to_month(s):
        return datetime.strptime(s, MONTH_FORMAT)
