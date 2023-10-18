#!/bin/bash

set -eux
set -o pipefail

function extract_payload_from_cose() {
	local cose=$1
	local payload=$2

	cat ${cose} \
		| cut -d, -f 3 \
		| egrep --color=never -o '[A-F0-9]*' \
		| xxd -p -r \
		| cbor2diag.rb \
		> ${payload}
}

SIGN1_IAK="tfm-es-iak.pem"
SIGN1_CLAIMS_YAML="sign1-claims.yaml"
SIGN1_OUT="psa-sign1.cbor"
SIGN1_HEX="psa-sign1.hex"
SIGN1_DIAG="psa-sign1.diag"
SIGN1_CLAIMS_DIAG="sign1-claims.diag"

#
# Sign1
#
compile_token \
	-k ${SIGN1_IAK} \
	-m sign \
	-t PSA-2.0.0-token \
	-o ${SIGN1_OUT} \
	${SIGN1_CLAIMS_YAML}

cbor2diag.rb ${SIGN1_OUT} > ${SIGN1_DIAG}

xxd -p ${SIGN1_OUT} | fold -w 64 > ${SIGN1_HEX}

extract_payload_from_cose ${SIGN1_DIAG} ${SIGN1_CLAIMS_DIAG}

MAC0_IAK="tfm-hs-iak.bin"
MAC0_CLAIMS_YAML="mac0-claims.yaml"
MAC0_OUT="psa-mac0.cbor"
MAC0_HEX="psa-mac0.hex"
MAC0_DIAG="psa-mac0.diag"
MAC0_CLAIMS_DIAG="mac0-claims.diag"

#
# Mac0
#
compile_token \
	-k ${MAC0_IAK} \
	-m mac \
	-t PSA-2.0.0-token \
	-o ${MAC0_OUT} \
	${MAC0_CLAIMS_YAML}

cbor2diag.rb ${MAC0_OUT} > ${MAC0_DIAG}

xxd -p ${MAC0_OUT} | fold -w 64 > ${MAC0_HEX}

extract_payload_from_cose ${MAC0_DIAG} ${MAC0_CLAIMS_DIAG}

