from statskit import rolling_median

cases = [
    ([1, 2, 3, 4, 5], 3, [2, 3, 4]),
    ([10, 20, 30, 40], 2, [15, 25, 35]),
    ([5], 1, [5]),
]
for data, size, want in cases:
    got = rolling_median(data, size)
    assert got == want, f"rolling_median({data}, {size}) = {got}, expected {want}"
print("all rolling_median cases pass")
