def mean(xs):
    return sum(xs) / len(xs)


def median(xs):
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2
