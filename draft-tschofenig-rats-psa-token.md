---
title: "Arm's Platform Security Architecture (PSA) Attestation Token"
abbrev: "PSA Attestation Token"
docname: draft-tschofenig-rats-psa-token
category: info

ipr: trust200902
area: Security
workgroup: RATS
keyword: Internet-Draft

stand_alone: yes

pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  text-list-symbols: -o*+

author:
 -
    ins: H. Tschofenig
    name: Hannes Tschofenig
    organization: Arm Limited
    email: Hannes.Tschofenig@arm.com
 -
    ins: S. Frost
    name: Simon Frost
    organization: Arm Limited
    email: Simon.Frost@arm.com
 -
    ins: M. Brossard
    name: Mathias Brossard
    organization: Arm Limited
    email: Mathias.Brossard@arm.com
 -
    ins: A. Shaw
    name: Adrian Shaw
    organization: Arm Limited
    email: Adrian.Shaw@arm.com
 -
    ins: T. Fossati
    name: Thomas Fossati
    organization: Arm Limited
    email: Thomas.Fossati@arm.com

normative:
  PSA-SM:
    author:
      org: Arm
    title: Platform Security Architecture Security Model 1.0 (PSA-SM)
    target: https://pages.arm.com/psa-resources-sm.html
    date: 19. Feb. 2019
  EAN-13:
    author:
      org: GS1
    title: International Article Number - EAN/UPC barcodes
    target: https://www.gs1.org/standards/barcodes/ean-upc
    date: 2019

informative:
  IANA-CWT:
    author:
      org: IANA
    title: CBOR Web Token (CWT) Claims
    target: https://www.iana.org/assignments/cwt/cwt.xhtml
    date: 2020
  TF-M:
    author:
      org: Linaro
    title: Trusted Firmware
    target: https://www.trustedfirmware.org
    date: 2020
  PSA:
    author:
      org: Arm
    title: Platform Security Architecture Resources
    target: https://www.arm.com/why-arm/architecture/platform-security-architecture/psa-resources
    date: 2019

--- abstract

The Platform Security Architecture (PSA) is a family of security and software
specifications to help device makers build best-practice security into
products. Devices that are PSA compliant are able to produce attestation
tokens, which are the basis for a number of different protocols, including
secure provisioning and network access control.  This document specifies the
PSA attestation token structure and semantics.

At its core, the CWT (COSE Web Token) format is used and populated with a set
of claims in a way similar to EAT (Entity Attestation Token). This
specification describes what claims are used by PSA compliant systems.

--- middle

# Introduction

Trusted execution environments are now present in many devices, which provide a
safe environment to place security sensitive code, such as cryptography, secure
boot, secure storage, and other essential security functions. These security
functions are typically exposed through a narrow and well-defined interface,
and can be used by operating system libraries and applications.  Various APIs
have been developed by Arm as part of the Platform Security Architecture
{{PSA}} framework.  This document focuses on the output provided by PSA's
Initial Attestation API. Since the tokens are also consumed by services outside
the device, there is an actual need to ensure interoperability.
Interoperability needs are addressed here by describing the exact syntax and
semantics of the attestation claims, and defining the way these claims are
encoded and cryptographically protected.

Further details on concepts expressed below can be found in the PSA Security
Model documentation {{PSA-SM}}.

# Conventions and Definitions

{::boilerplate bcp14}

## Glossary

RoT
: Root of Trust, the minimal set of software, hardware and data that has to be
implicitly trusted in the platform - there is no software or hardware at a
deeper level that can verify that the Root of Trust is authentic and
unmodified.

SPE
: Secure Processing Environment, a platform's processing environment for
software that provides confidentiality and integrity for its runtime state,
from software and hardware, outside of the SPE. Contains trusted code and
trusted hardware.

NSPE
: Non Secure Processing Environment, the security domain outside of the SPE,
the Application domain, typically containing the application firmware,
operating systems, and general hardware.

# PSA Claims
{: #sec-psa-claims }

This section describes the claims to be used in a PSA attestation token.

CDDL {{!RFC8610}} along with text descriptions is used to define each claim
independent of encoding.

## Caller Claims

### Auth Challenge

The Auth Challenge claim is an input object from the caller. For example, this
can be a cryptographic nonce, a hash of locally attested data. The length must
be 32, 48, or 64 bytes.

This claim MUST be present in a PSA attestation token.

~~~
psa-nonce-type = bytes .size 32 / bytes .size 48 / bytes .size 64

psa-nonce-claim = (
    arm_psa_nonce => psa-nonce-type
)
~~~

### Client ID

The Client ID claim represents the ID of the caller. It is a signed integer
whereby negative values represent callers from the NSPE and where positive IDs
represent callers from the SPE.

This claim MUST be present in a PSA attestation token.

~~~
psa-client-id-type = -2147483648..2147483647

psa-client-id = (
    arm_psa_partition_id => psa-client-id-type
)
~~~

## Target Identification Claims

### Instance ID

The Instance ID claim represents the unique identifier of the instance. It is a
hash of the public key corresponding to the Initial Attestation Key (IAK). If
the IAK is a symmetric key then the Instance ID is a hash of the IAK. The full
definition is in the {{PSA-SM}}.

This claim MUST be present in a PSA attestation token.

~~~
psa-instance-id-type = bytes .size 33

psa-instance-id = (
    arm_psa_UEID => psa-instance-id-type
)
~~~

### Implementation ID

The Implementation ID claim uniquely identifies the underlying immutable PSA
RoT. A verification service can use this claim to locate the details of the
verification process. Such details include the implementation's origin and
associated certification state.

This claim MUST be present in a PSA attestation token.

~~~
psa-implementation-id-type = bytes .size 32

psa-implementation-id = (
    arm_psa_implementation_id => psa-implementation-id-type
)
~~~

### Hardware Version

The Hardware Version claim provides metadata linking the token to the GDSII
that went to fabrication for this instance. It can be used to link the class of
chip and PSA RoT to the data on a certification website. It MUST be represented
as a thirteen-digit {{EAN-13}}

~~~
psa-hardware-version-type = text .regexp "[0-9]{13}"

psa-hardware-version = (
    arm_psa_hw_version => psa-hardware-version-type
)
~~~

## Target State Claims

### Security Lifecycle

The Security Lifecycle claim represents the current lifecycle state of the PSA
RoT. The state is represented by an integer that is divided to convey a major
state and a minor state. A major state is mandatory and defined by {{PSA-SM}}.
A minor state is optional and 'IMPLEMENTATION DEFINED'. The encoding is:
version\[15:8\] - PSA security lifecycle state, and version\[7:0\] -
IMPLEMENTATION DEFINED state. The PSA lifecycle states are illustrated in
{{fig-lifecycle-states}}. For PSA, a remote verifier can only trust reports
from the PSA RoT when it is in SECURED or NON_PSA_ROT_DEBUG major states.

This claim MUST be present in a PSA attestation token.

<t>
  <figure anchor="fig-lifecycle-states" title="PSA Lifecycle States">
    <artset>
      <artwork type="ascii-art" src="art/psa-lifecycle.ascii-art" />
      <artwork type="svg" src="art/psa-lifecycle.svg" />
    </artset>
  </figure>
</t>

~~~
psa-lifecycle-type = (
    unknown: 0x0000,
    assembly_and_test: 0x1000,
    psa_rot_provisioning: 0x2000,
    secured: 0x3000,
    non_psa_rot_debug: 0x4000,
    recoverable_psa_rot_debug: 0x5000,
    decommissioned: 0x6000,
)

psa-lifecycle = (
    arm_psa_security_lifecycle => &psa-lifecycle-type
)
~~~

### Boot Seed

The Boot Seed claim represents a random value created at system boot time that
will allow differentiation of reports from different boot sessions.

This claim MUST be present in a PSA attestation token.

~~~
psa-boot-seed-type = bytes .size 32

psa-boot-seed = (
    arm_psa_boot_seed => psa-boot-seed-type
)
~~~

## Target Software Inventory Claims

### Software Components
{: #sec-sw-components }

The Software Components claim is a list of software components that includes
all the software loaded by the PSA RoT. This claim SHALL be included in
attestation tokens produced by an implementation conformant with {{PSA-SM}}.
If the Software Components claim is present, then the No Software Measurement
claim ({{sec-no-sw-measurements}}) MUST NOT be present.

Each entry in the Software Components list describes one software component
using the attributes described in the following subsections.  Unless explicitly
stated, the presence of an attribute is OPTIONAL.

~~~
psa-software-component-type = (
    ? 1 => text,        ; measurement type
    2 => bytes .size 32 ; measurement value
    ? 4  => text,       ; version
    5 => bytes,         ; signer id
    ? 6 => text,        ; measurement description
)

psa-software-components = (
    arm_psa_sw_components => [ + psa-software-component-type ]
)
~~~

#### Measurement Type

The Measurement Type attribute (key=1) is short string representing the role of
this software component.

The following measurement types MAY be used:

* "BL": a Boot Loader
* "PRoT": a component of the PSA Root of Trust
* "ARoT": a component of the Application Root of Trust
* "App": a component of the NSPE application
* "TS": a component of a Trusted Subsystem

#### Measurement Value

The Measurement Value attribute (key=2) represents a hash of the invariant
software component in memory at startup time. The value MUST be a cryptographic
hash of 256 bits or stronger.

This attribute MUST be present in a PSA software component.

#### Version

The Version attribute (key=4) is the issued software version in the form of a
text string. The value of this attribute will correspond to the entry in the
original signed manifest of the component.

#### Signer ID

The Signer ID attribute (key=5) is the hash of a signing authority public key
for the software component. The value of this attribute will correspond to the
entry in the original manifest for the component. This can be used by a
verifier to ensure the components were signed by an expected trusted source.

This attribute MUST be present in a PSA software component to be compliant with
{{PSA-SM}}.

#### Measurement Description

The Measurement Description attribute (key=6) is the description of the way in
which the measurement value of the software component is computed. The value
will be a text string containing an abbreviated description (or name) of the
measurement method which can be used to lookup the details of the method in a
profile document. This attribute will normally be excluded, unless there was an
exception to the default measurement described in the profile for a specific
component.

### No Software Measurements
{: #sec-no-sw-measurements }

In the event that the implementation does not contain any software measurements
then the Software Components claim {{sec-sw-components}} can be omitted but
instead the token MUST include this claim to indicate this is a deliberate
state. This claim is intended for devices that are not compliant with
{{PSA-SM}}.

~~~
psa-no-sw-measuremments-type = 0..1

psa-no-sw-measurement = (
    arm_psa_no_sw_measurements => psa-no-sw-measuremments-type
)
~~~

## Verification Claims

### Verification Service Indicator

The Verification Service Indicator claim is a hint used by a relying party to
locate a validation service for the token. The value is a text string that can
be used to locate the service or a URL specifying the address of the service. A
verifier may choose to ignore this claim in favor of other information.

~~~
psa-verification-service-indicator-type = text

psa-verification-service-indicator = (
    arm_psa_origination => psa-verification-service-indicator-type
)
~~~

### Profile Definition

The Profile Definition claim contains the name of a document that describes the
'profile' of the report. The document name may include versioning. The value
for this specification MUST be PSA_IOT_PROFILE_1.

~~~
psa-profile-type = "PSA_IOT_PROFILE_1"

psa-profile = (
    arm_psa_profile_id => psa-profile-type
)
~~~

# Token Encoding

The report is encoded as a COSE Web Token (CWT) {{!RFC8392}}, similar to the
Entity Attestation Token (EAT) {{?I-D.ietf-rats-eat}}. The token consists of a
series of claims declaring evidence as to the nature of the instance of
hardware and software. The claims are encoded in CBOR {{!RFC7049}} format.

# Collected CDDL

~~~
{::include psa-token.cddl}
~~~

# Security and Privacy Considerations

This specification re-uses the CWT and the EAT specification. Hence, the
security and privacy considerations of those specifications apply here as well.

Since CWTs offer different ways to protect the token, this specification
profiles those options and allows use of public key cryptography as well as MAC
authentication. The token MUST be signed following the structure of the COSE
specification {{!RFC8152}}.  The COSE type MUST be COSE-Sign1 for public key
signatures or COSE-Mac0 for MAC authentication.  Note however that use of MAC
authentication is NOT RECOMMENDED due to the associated infrastructure costs
for key management and protocol complexities. It may also restrict the ability
to interoperate with third parties.

Attestation tokens contain information that may be unique to a device and
therefore they may allow to single out an individual device for tracking
purposes.  Implementations that have privacy requirements must take appropriate
measures to ensure that the token is only used to provision anonymous/pseudonym
keys. This may be achieved using a Privacy CA or a DAA scheme.

# IANA Considerations

IANA is requested to allocate the claims defined in {{sec-psa-claims}} to the
CBOR Web Token (CWT) Claims registry {{IANA-CWT}}. The change controller are
the authors and the reference is this document.

--- back

# Reference Implementation

A reference implementation is provided by the Trusted Firmware project {{TF-M}}.

# Example

The following example shows an attestation token that was produced for a device
that has a single-stage bootloader, and an RTOS with a device management
client. From a code point of view, the RTOS and the device management client
form a single binary.

EC key using curve P-256 with:

* x: 0xdcf0d0f4bcd5e26a54ee36cad660d283d12abc5f7307de58689e77cd60452e75
* y: 0x8cbadb5fe9f89a7107e5a2e8ea44ec1b09b7da2a1a82a0252a4c1c26ee1ed7cf
* d: 0xc74670bcb7e85b3803efb428940492e73e3fe9d4f7b5a8ad5e480cbdbcb554c2

Key using COSE format (base64-encoded):

~~~
    pSJYIIy621/p+JpxB+Wi6OpE7BsJt9oqGoKgJSpMHCbuHtfPI1ggx0ZwvLfoWzgD77Q
    olASS5z4/6dT3taitXkgMvby1VMIBAiFYINzw0PS81eJqVO42ytZg0oPRKrxfcwfeWG
    ied81gRS51IAE=
~~~

Example of EAT token (base64-encoded):

~~~
    0oRDoQEmoFkCIqk6AAEk+1ggAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
    6AAEk+lggAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh86AAEk/YSkAlggAA
    ECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8EZTMuMS40BVggAAECAwQFBgcIC
    QoLDA0ODxAREhMUFRYXGBkaGxwdHh8BYkJMpAJYIAABAgMEBQYHCAkKCwwNDg8QERIT
    FBUWFxgZGhscHR4fBGMxLjEFWCAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0
    eHwFkUFJvVKQCWCAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHwRjMS4wBV
    ggAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8BZEFSb1SkAlggAAECAwQFB
    gcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8EYzIuMgVYIAABAgMEBQYHCAkKCwwNDg8Q
    ERITFBUWFxgZGhscHR4fAWNBcHA6AAEk+RkwADoAAST/WCAAAQIDBAUGBwgJCgsMDQ4
    PEBESExQVFhcYGRobHB0eHzoAASUBbHBzYV92ZXJpZmllcjoAAST4IDoAASUAWCEBAA
    ECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh86AAEk93FQU0FfSW9UX1BST0ZJT
    EVfMVhAWIYFCO5+jMSOuoctu11pSlQrEyKtDVECPBlw30KfBlAcaDqVEIoMztCm6A4J
    ZvIr1j0cAFaXShG6My14d4f7Tw==
~~~

Same token using extended CBOR diagnostic format:

~~~
18(
  [
  / protected / h'a10126' / {
      \ alg \ 1: -7 \ ECDSA 256 \
    } / ,
  / unprotected / {},
  / payload / h'a93a000124fb5820000102030405060708090a0b0c0d0e0f1011121
  31415161718191a1b1c1d1e1f3a000124fa5820000102030405060708090a0b0c0d0e
  0f101112131415161718191a1b1c1d1e1f3a000124fd84a4025820000102030405060
  708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0465332e312e34055820
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01624
  24ca4025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c
  1d1e1f0463312e31055820000102030405060708090a0b0c0d0e0f101112131415161
  718191a1b1c1d1e1f016450526f54a4025820000102030405060708090a0b0c0d0e0f
  101112131415161718191a1b1c1d1e1f0463312e30055820000102030405060708090
  a0b0c0d0e0f101112131415161718191a1b1c1d1e1f016441526f54a4025820000102
  030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0463322e320
  55820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  01634170703a000124f91930003a000124ff5820000102030405060708090a0b0c0d0
  e0f101112131415161718191a1b1c1d1e1f3a000125016c7073615f76657269666965
  723a000124f8203a00012500582101000102030405060708090a0b0c0d0e0f1011121
  31415161718191a1b1c1d1e1f3a000124f7715053415f496f545f50524f46494c455f
  31' / {
     / arm_psa_boot_seed / -75004: h'000102030405060708090a0b0c0d0e0f10
     1112131415161718191a1b1c1d1e1f',
     / arm_psa_implementation_id / -75003: h'000102030405060708090a0b0c
     0d0e0f101112131415161718191a1b1c1d1e1f',
     / arm_psa_sw_components / -75006: [
          {
            / measurement / 2: h'000102030405060708090a0b0c0d0e0f101112
            131415161718191a1b1c1d1e1f',
            / version / 4: "3.1.4",
            / signerID / 5: h'000102030405060708090a0b0c0d0e0f101112131
            415161718191a1b1c1d1e1f',
            / type / 1: "BL"
          },
          {
            / measurement / 2: h'000102030405060708090a0b0c0d0e0f101112
            131415161718191a1b1c1d1e1f',
            / version / 4: "1.1",
            / signerID / 5: h'000102030405060708090a0b0c0d0e0f101112131
            415161718191a1b1c1d1e1f',
            / type / 1: "PRoT"
          },
          {
            / measurement / 2: h'000102030405060708090a0b0c0d0e0f101112
            131415161718191a1b1c1d1e1f',
            / version / 4: "1.0",
            / signerID / 5: h'000102030405060708090a0b0c0d0e0f101112131
            415161718191a1b1c1d1e1f',
            / type / 1: "ARoT"
          },
          {
            / measurement / 2: h'000102030405060708090a0b0c0d0e0f101112
            131415161718191a1b1c1d1e1f',
            / version / 4: "2.2",
            / signerID / 5: h'000102030405060708090a0b0c0d0e0f101112131
            415161718191a1b1c1d1e1f',
            / type / 1: "App"
          }
        ],
      / arm_psa_security_lifecycle / -75002: 12288 / SECURED /,
      / arm_psa_nonce / -75008: h'000102030405060708090a0b0c0d0e0f10111
      2131415161718191a1b1c1d1e1f',
      / arm_psa_origination / -75010: "psa_verifier",
      / arm_psa_partition_id / -75001: -1,
      / arm_psa_UEID / -75009: h'01000102030405060708090a0b0c0d0e0f1011
      12131415161718191a1b1c1d1e1f',
      / arm_psa_profile_id / -75000: "PSA_IoT_PROFILE_1"
    }),
    } / ,
  / signature / h'58860508ee7e8cc48eba872dbb5d694a542b1322ad0d51023c197
  0df429f06501c683a95108a0cced0a6e80e0966f22bd63d1c0056974a11ba332d7877
  87fb4f'
  ]
)
~~~

# Contributors
{:numbered="false"}

We would like to thank the following colleagues for their contributions:

~~~
* Laurence Lundblade
  Security Theory LLC
  lgl@securitytheory.com
~~~

~~~
* Tamas Ban
  Arm Limited
  Tamas.Ban@arm.com
~~~

~~~
* Sergei Trofimov
  Arm Limited
  Sergei.Trofimov@arm.com
~~~

# Acknowledgments
{:numbered="false"}

Thanks to Carsten Bormann for help with the CDDL.
