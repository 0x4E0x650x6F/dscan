PROJECT_PATH=./tests

help:
	@echo "    clean-pyc"
	@echo "        Remove python artifacts."
	@echo "    clean-build"
	@echo "        Remove build artifacts."
	@echo "    isort"
	@echo "        Sort import statements."
	@echo "    lint"
	@echo "        Fix pep8 style with autopep8."
	@echo "        Check style with flake8."
	@echo "    test"
	@echo "        run tests with unittest."
	@echo "    init."
	@echo "        install requirements."

init:
	pip install -r requirements.txt

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

clean-build:
	rm -rf build/
	rm -rf dist/
	rm -rf docs/_build
	rm -rf *.egg-info

isort:
	isort $(PROJECT_PATH)

lint: isort
	autopep8 --verbose --recursive --in-place --aggressive $(PROJECT_PATH)
	#flake8  $(PROJECT_PATH)

test: lint
	python3 -m unittest discover -s $(PROJECT_PATH)

docs: clean-build
	cd docs && make html

.PHONY: clean-pyc clean-build