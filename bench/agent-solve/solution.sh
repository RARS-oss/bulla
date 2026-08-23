#!/bin/sh
# The agent's fix. Diagnosis: check.py fails because rolling_median drops the last window — the
# defect is NOT in api.py (where the symptom shows) but two modules away in window.rolling, whose
# range(len - size) stops one short. Correct it to range(len - size + 1). Derived from source; no
# network, no git history consulted.
cat > statskit/window.py <<'PY'
def rolling(data, size):
    """Yield every contiguous window of length `size` over `data`."""
    if size <= 0 or size > len(data):
        return []
    return [data[i:i + size] for i in range(len(data) - size + 1)]
PY
echo "[agent] patched statskit/window.py: range(len-size) -> range(len-size+1)"
