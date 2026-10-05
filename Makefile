# SEDI formal analysis: Tamarin + ProVerif.
#
#   make                 run every analysis (Tamarin + all ProVerif suites)
#   make tamarin         Tamarin runs from scripts/manifest.json
#   make proverif        all ProVerif suites
#   make cry01           one requirement (Tamarin + ProVerif where both exist)
#   make bbs             joint check of all requirements on a BBS + ZK design
#   make prv01 ONLY=A_   restrict to configs/runs whose id starts with A_
#   make list            list every run / config id
#   make help            this text
#
# Variables (override on the command line):
#   PYTHON    python interpreter                       (default: python3)
#   ONLY      id prefix filter, passed as --only       (default: all)
#   TIMEOUT   per-lemma / per-model timeout in seconds (default: script's own)
#   JOBS      parallel Tamarin provers                 (default: 4)
#   PROVERIF  path to the proverif binary              (default: PATH, then
#             ~/opt/proverif2.05/proverif)

PYTHON   ?= python3
ONLY     ?=
TIMEOUT  ?=
JOBS     ?= 4
PROVERIF ?=

PV_SUITES := cry01 cry02 prv01 prv02 prv03 bbs

COMMON_ARGS := $(if $(ONLY),--only $(ONLY)) $(if $(TIMEOUT),--timeout $(TIMEOUT))
PV_ARGS     := $(COMMON_ARGS) $(if $(PROVERIF),--proverif $(PROVERIF))
TAM_ARGS    := $(COMMON_ARGS) --jobs $(JOBS)

.PHONY: all help tamarin proverif generate list clean check-tools \
        $(PV_SUITES) $(addprefix proverif-,$(PV_SUITES)) \
        $(addprefix generate-,$(PV_SUITES)) cry01-tamarin

all: tamarin proverif

help:
	@sed -n '1,/^$$/p' $(firstword $(MAKEFILE_LIST)) | sed 's/^# \{0,1\}//'

# ---------------------------------------------------------------- Tamarin ---

# Every run in scripts/manifest.json -> results/results.json, results/summary.md
tamarin:
	$(PYTHON) scripts/run_all.py $(TAM_ARGS)

# Tamarin runs for CRY-01 only (ignores ONLY, uses the cry01 prefix)
cry01-tamarin:
	$(PYTHON) scripts/run_all.py --only cry01 $(if $(TIMEOUT),--timeout $(TIMEOUT)) --jobs $(JOBS)

# --------------------------------------------------------------- ProVerif ---

# Generate the .pv models and run them -> results/<suite>/
proverif: $(addprefix proverif-,$(PV_SUITES))

$(addprefix proverif-,$(PV_SUITES)): proverif-%:
	$(PYTHON) scripts/$*_proverif.py $(PV_ARGS)

# Only write proverif/<suite>/*.pv, do not run ProVerif
generate: $(addprefix generate-,$(PV_SUITES))

$(addprefix generate-,$(PV_SUITES)): generate-%:
	$(PYTHON) scripts/$*_proverif.py --generate $(if $(ONLY),--only $(ONLY))

# ------------------------------------------------------- per requirement ---

cry01: cry01-tamarin proverif-cry01
cry02: proverif-cry02
prv01: proverif-prv01
prv02: proverif-prv02
prv03: proverif-prv03
bbs:   proverif-bbs

# ------------------------------------------------------------- utilities ---

list:
	@echo "== tamarin"; $(PYTHON) scripts/run_all.py --list
	@for s in $(PV_SUITES); do echo "== proverif $$s"; \
	  $(PYTHON) scripts/$${s}_proverif.py --list; done

check-tools:
	@command -v $(PYTHON) >/dev/null || { echo "missing: $(PYTHON)"; exit 1; }
	@command -v tamarin-prover >/dev/null || echo "missing: tamarin-prover"
	@{ test -n "$(PROVERIF)" && test -x "$(PROVERIF)"; } \
	  || command -v proverif >/dev/null \
	  || test -x $(HOME)/opt/proverif2.05/proverif \
	  || echo "missing: proverif (set PROVERIF=/path/to/proverif)"
	@tamarin-prover --version 2>/dev/null | head -2 || true

# results/ is gitignored; generated .pv models are left in place
clean:
	rm -rf results
