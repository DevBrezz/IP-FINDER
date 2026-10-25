# Contributing

1. Use Python 3.10 or newer.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Run the offline test suite with `python -m unittest discover -s tests -v`.
4. Keep network tests mocked in automated tests; do not require live third-party services in CI.
5. Preserve the project identity (`IP-FINDER`, author `DevBrezz`, version `1.0.0`) unless the maintainers explicitly decide otherwise.
6. Keep targets user-supplied, timeouts bounded, and batch/repeated requests capped. Do not add stress, flood, credential-guessing, or stealth features.
