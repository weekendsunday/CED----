@echo off
cd /d %~dp0
echo === CED self-check ===
echo --- test_pipeline ---
python ced\tests\test_pipeline.py
echo --- test_socket_probe ---
python ced\tests\test_socket_probe.py
echo --- test_chain_e2e ---
python ced\tests\test_chain_e2e.py
echo --- known-case regression ---
python -m ced regression
echo.
echo Done.
pause >nul
