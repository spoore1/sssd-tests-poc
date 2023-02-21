# :warning: This repository is OUTDATED and was converted into upstream pull request

The repository has been converted into upstream pull request that has some changes not available in this repository. **This repository is therefore outdated.**

Please refer to the pull request instead. Once the pull request is merged, this repository is going to be deleted.

## https://github.com/SSSD/sssd/pull/6521

:warning: :warning: :warning:

---

# SSSD Test Framework PoC

**Work in progress.**

## Install dependencies

```
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r ./requirements.txt
```

## Run tests

```
pytest --mh-log-path=mhc.yaml -v
```

## Build documentation

```
source .venv/bin/activate
pip3 install -r ./docs/requirements.txt
make -C docs html
firefox docs/_build/html/index.html
```

The documentation is available here: https://sssd-tests-poc.readthedocs.io
