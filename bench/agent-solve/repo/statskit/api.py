from .core import median
from .window import rolling


def rolling_median(data, size):
    return [median(w) for w in rolling(data, size)]
