import os
import sys
from contextlib import redirect_stdout, redirect_stderr

with open(os.devnull, 'w') as f, redirect_stdout(f), redirect_stderr(f):
    print("SHOULD NOT PRINT")
    print("ERROR SHOULD NOT PRINT", file=sys.stderr)

print("SHOULD PRINT")
print("ERROR SHOULD PRINT", file=sys.stderr)