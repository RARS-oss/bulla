import os
import sys

# A genuinely flaky test: it passes on a coin flip drawn from OS entropy. No fixed seed reaches
# this decision, so consecutive hermetic runs disagree — the case where a harness can quietly keep
# only the lucky run and report it as pass@1.
sys.exit(0 if os.urandom(1)[0] < 128 else 1)
