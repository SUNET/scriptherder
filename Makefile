untyped:
	# pip install strip-hints
	strip-hints --outfile scriptherder-untyped.py src/scriptherder.py
	black --line-length 120 --target-version py39 scriptherder-untyped.py

typecheck:
	mypy --strict src/scriptherder.py
