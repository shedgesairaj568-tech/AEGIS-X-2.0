# AEGIS-X — Windows convenience wrapper for the test runner.
# Just forwards to the real (cross-platform) Python script, so behavior
# is guaranteed identical to running it directly with `python`.
#
# Usage:
#   .\tests\run_all_tests.ps1
#   .\tests\run_all_tests.ps1 --fast
#   .\tests\run_all_tests.ps1 --module backend

python "$PSScriptRoot\run_all_tests.py" @args
exit $LASTEXITCODE
