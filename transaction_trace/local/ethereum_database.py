import datetime
import logging
import os
import re

from sortedcontainers import SortedList

from ..basic_utils import DatetimeUtils
from .database_name import DatabaseName
from .single_database import SingleDatabaseFactory, SingleTraceDatabase

l = logging.getLogger("transaction-trace.local.ethereum_database")


def data_time_range(db_folder, db_name):
    prog = re.compile(r"%s_(\d{4}\-\d{2}\-\d{2})\.sqlite3" % db_name)
    dates = SortedList(key=lambda x: DatetimeUtils.str_to_date(x))
    for file in os.listdir(db_folder):
        m = prog.match(file)
        if m is not None:
            dates.add(m[1])

    return dates


def db_filename(db_name, date):
    return "%s_%s.sqlite3" % (db_name, date)


class EthereumDatabase:

    def __init__(self, db_folder, db_name=DatabaseName.TRACE_DATABASE, cache_capacity=20):
        self._db_folder = db_folder
        self._db_name = db_name

        self._data_time_range = data_time_range(db_folder, self._db_name)

        self._cache_capacity = cache_capacity
        self._connection_cache = dict()
        self._connection_access = list()

    def __repr__(self):
        return "database manager of %s" % self._db_folder

    @property
    def time_range(self):
        return self._data_time_range

    def get_connection(self, date):
        if isinstance(date, datetime.datetime):
            date = DatetimeUtils.date_to_str(date)

        if date not in self._data_time_range:
            return None

        if date in self._connection_cache:
            self._connection_access.remove(date)
            self._connection_access.append(date)
            return self._connection_cache[date]

        if len(self._connection_cache) == self._cache_capacity:
            lru = self._connection_access.pop(0)
            conn = self._connection_cache.pop(lru)
            del conn

        db_filepath = os.path.join(
            self._db_folder, db_filename(self._db_name, date))
        db = SingleDatabaseFactory.get_single_database(self._db_name)(db_filepath, date)
        self._connection_access.append(date)
        self._connection_cache[date] = db
        return db

    def get_connections(self, from_time, to_time):
        '''
        Time range can be datetime.datetime or string.
        '''
        if isinstance(from_time, datetime.datetime):
            from_time = DatetimeUtils.date_to_str(from_time)
        if isinstance(to_time, datetime.datetime):
            to_time = DatetimeUtils.date_to_str(to_time)

        for i in range(self._data_time_range.bisect_left(from_time), self._data_time_range.bisect_right(to_time)):
            date = self._data_time_range[i]
            yield self.get_connection(date)

    def get_all_connnections(self):
        for date in self._data_time_range:
            yield self.get_connection(date)

    def read_traces(self, from_time, to_time):
        '''
        Time range can be datetime.datetime or string.
        '''
        for db in self.get_connections(from_time, to_time):
            for row in db.read_traces():
                yield row
