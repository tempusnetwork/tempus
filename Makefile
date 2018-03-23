SHELL:=/bin/bash

test:
	source venv/bin/activate; PYTHONPATH=. pytest tests