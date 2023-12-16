LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif

CDDL_FRAGS := cddl/psa-boot-seed.cddl
CDDL_FRAGS += cddl/psa-certification-reference.cddl
CDDL_FRAGS += cddl/psa-client-id.cddl
CDDL_FRAGS += cddl/psa-common-types.cddl
CDDL_FRAGS += cddl/psa-implementation-id.cddl
CDDL_FRAGS += cddl/psa-instance-id.cddl
CDDL_FRAGS += cddl/psa-nonce.cddl
CDDL_FRAGS += cddl/psa-profile.cddl
CDDL_FRAGS += cddl/psa-security-lifecycle.cddl
CDDL_FRAGS += cddl/psa-software-components.cddl
CDDL_FRAGS += cddl/psa-verification-service-indicator.cddl

EXAMPLES := $(wildcard cddl/example/*.diag)
EXAMPLES += $(wildcard cddl/example/*.json)

ARTWORK := art/psa-attester.ascii-art
ARTWORK += art/psa-lifecycle.ascii-art
ARTWORK += art/psa-boot.ascii-art
ARTWORK += art/psa-runtime.ascii-art

TESTS := $(wildcard cddl/test/GOOD_*.diag)
TESTS += $(wildcard cddl/test/FAIL_*.diag)

DRAFT_DEPS := cddl/psa-attestation.cddl
DRAFT_DEPS += cddl/example/psa-token.cbor
DRAFT_DEPS += $(ARTWORK)
DRAFT_DEPS += $(EXAMPLES)
DRAFT_DEPS += $(CDDL_FRAGS)
DRAFT_DEPS += $(TESTS)

$(drafts_xml):: $(DRAFT_DEPS)

cddl/psa-attestation.cddl: $(CDDL_FRAGS) ; $(MAKE) -C cddl test

cddl/example/psa-token.cbor: ; $(MAKE) -C cddl check-example

clean:: ; $(MAKE) -C cddl clean
