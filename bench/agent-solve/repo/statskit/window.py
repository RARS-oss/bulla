def rolling(data, size):
    """Yield every contiguous window of length `size` over `data`."""
    if size <= 0 or size > len(data):
        return []
    # BUG: off-by-one — range(len - size) stops one short and drops the final window.
    return [data[i:i + size] for i in range(len(data) - size)]
