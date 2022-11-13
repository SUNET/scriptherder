untyped:
	# pip install strip-hints
	strip-hints --outfile scriptherder-untyped.py src/scriptherder.py

typecheck:
	mypy --strict src/scriptherder.py
