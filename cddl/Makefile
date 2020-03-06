.DEFAULT_GOAL := test

SHELL := /bin/bash

cddl ?= $(shell command -v cddl)
ifeq ($(strip $(cddl)),)
  $(error cddl tool not found. To install cddl, run: 'gem install cddl')
endif

diag2cbor ?= $(shell command -v diag2cbor.rb)
ifeq ($(strip $(diag2cbor)),)
  $(error diag2cbor tool not found. To install diag2cbor, run: 'gem install cbor-diag')
endif

CLEANFILES :=

FRAGMENTS := psa-token.cddl
FRAGMENTS += psa-common-types.cddl
FRAGMENTS += psa-boot-seed.cddl
FRAGMENTS += psa-client-id.cddl
FRAGMENTS += psa-hardware-version.cddl
FRAGMENTS += psa-implementation-id.cddl
FRAGMENTS += psa-instance-id.cddl
FRAGMENTS += psa-no-sw-measurements.cddl
FRAGMENTS += psa-nonce.cddl
FRAGMENTS += psa-profile.cddl
FRAGMENTS += psa-security-lifecycle.cddl
FRAGMENTS += psa-software-components.cddl
FRAGMENTS += psa-verification-service-indicator.cddl

AMALGAMATION := psa-attestation.cddl

$(AMALGAMATION): $(FRAGMENTS) ; @$(RM) $@ && cat $^ >> $@

CLEANFILES += $(AMALGAMATION)

%.cbor: %.diag ; @$(diag2cbor) $< > $@

DIAG_FILES := $(wildcard test/*.diag)
CBOR_FILES := $(DIAG_FILES:.diag=.cbor)

CLEANFILES += $(CBOR_FILES)

test: $(AMALGAMATION) $(CBOR_FILES)
	@for f in $(CBOR_FILES); do \
		$(cddl) $< validate $$f &> /dev/null ; \
		case $$f in \
		*GOOD_*) [ $$? -eq 0 ] && echo "[OK] $$f" ;; \
		*FAIL_*) [ $$? -ne 0 ] && echo "[OK] $$f" ;; \
		esac ; \
	done
.PHONY: test

clean: ; $(RM) $(CLEANFILES)
.PHONY: clean
