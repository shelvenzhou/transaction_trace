import logging
import sys

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    '%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))

logging.root.addHandler(handler)
logging.root.setLevel(logging.INFO)
