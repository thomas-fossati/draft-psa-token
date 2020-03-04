SHELL := /bin/bash

FRAGMENTS := psa-token.cddl
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

$(AMALGAMATION): $(FRAGMENTS) ; $(RM) $@ && cat $(FRAGMENTS) >> $@

clean: ; $(RM) $(AMALGAMATION)
.PHONY: clean
