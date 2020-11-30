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
  PSA-FF:
    author:
      org: Arm
    title: Platform Security Architecture Firmware Framework 1.0 (PSA-FF)
    target: https://pages.arm.com/psa-resources-ff.html
    date: 20. Feb. 2019

informative:
  IANA-CWT:
    author:
      org: IANA
    title: CBOR Web Token (CWT) Claims
    target: https://www.iana.org/assignments/cwt/cwt.xhtml
    date: 2020
  IANA-MediaTypes:
    author:
      org: IANA
    title: Media Types
    target: http://www.iana.org/assignments/media-types
    date: 2020
  IANA-CoAP-Content-Formats:
    author:
      org: IANA
    title: CoAP Content-Formats
    target: https://www.iana.org/assignments/core-parameters
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

The Platform Security Architecture (PSA) is a family of hardware and firmware
security specifications, as well as open-source reference implementations, to
help device makers and chip manufacturers build best-practice security into
products. Devices that are PSA compliant are able to produce attestation tokens
as described in this memo, which are the basis for a number of different
protocols, including secure provisioning and network access control.  This
document specifies the PSA attestation token structure and semantics.

At its core, the CWT (COSE Web Token) format is used and populated with a set
of claims in a way similar to EAT (Entity Attestation Token). This
specification describes what claims are used by PSA compliant systems.

--- middle

# Introduction

Trusted execution environments are now present in many devices, which provide a
safe environment to place security sensitive code such as cryptography, secure
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
unmodified.  An example of RoT is an initial bootloader in ROM, which contains
cryptographic functions and credentials, running on a specific hardware
platform.

SPE
: Secure Processing Environment, a platform's processing environment for
software that provides confidentiality and integrity for its runtime state,
from software and hardware, outside of the SPE. Contains trusted code and
trusted hardware.  (Equivalent to Trusted Execution Environment (TEE), or
"secure world".)

NSPE
: Non Secure Processing Environment, the security domain outside of the SPE,
the Application domain, typically containing the application firmware,
operating systems, and general hardware.  (Equivalent to Rich Execution
Environment (REE), or "normal world".)

# PSA Claims
{: #sec-psa-claims }

This section describes the claims to be used in a PSA attestation token.

CDDL {{!RFC8610}} along with text descriptions is used to define each claim
independent of encoding.  The following CDDL type(s) are reused by different
claims:

~~~
{::include cddl/psa-common-types.cddl}
~~~

## Caller Claims

### Auth Challenge

The Auth Challenge claim is an input object from the caller. For example, this
can be a cryptographic nonce, a hash of locally attested data. The length must
be 32, 48, or 64 bytes.

This claim MUST be present in a PSA attestation token.

~~~
{::include cddl/psa-nonce.cddl}
~~~

### Client ID

The Client ID claim represents the security domain of the caller.

In PSA, a security domain is represented by a signed
integer whereby negative values represent callers from the NSPE and where
positive IDs represent callers from the SPE. The value 0 is not permitted.

For an example definition of client IDs, see the PSA Firmware Framework {{PSA-FF}}.

It is essential that this claim is checked in the verification process to
ensure that a security domain, i.e., an attestation endpoint, cannot spoof a
report from another security domain.

This claim MUST be present in a PSA attestation token.

Note that the CDDL label used to be called arm_psa_partition_id.

~~~
{::include cddl/psa-client-id.cddl}
~~~

## Target Identification Claims

### Instance ID

The Instance ID claim represents the unique identifier of the device instance.
It is a 32 bytes hash of the public key corresponding to the Initial
Attestation Key (IAK). If the IAK is a symmetric key then the Instance ID is a
hash of the hash of the IAK itself.  It is encoded as a Universal Entity ID of
type RAND {{?I-D.ietf-rats-eat}}, i.e., prepending a 0x01 type byte to the key
hash. The full definition is in {{PSA-SM}}.

This claim MUST be present in a PSA attestation token.

~~~
{::include cddl/psa-instance-id.cddl}
~~~

### Implementation ID

The Implementation ID claim uniquely identifies the underlying immutable PSA
RoT. A verification service can use this claim to locate the details of the
verification process. Such details include the implementation's origin and
associated certification state. The full definition is in {{PSA-SM}}.

This claim MUST be present in a PSA attestation token.

~~~
{::include cddl/psa-implementation-id.cddl}
~~~

### Hardware Version

The Hardware Version claim provides metadata linking the token to the GDSII
that went to fabrication for this instance. It can be used to link the class of
chip and PSA RoT to the data on a certification website. It MUST be represented
as a thirteen-digit {{EAN-13}}.

~~~
{::include cddl/psa-hardware-version.cddl}
~~~

## Target State Claims

### Security Lifecycle
{: #sec-security-lifecycle }

The Security Lifecycle claim represents the current lifecycle state of the PSA
RoT. The state is represented by an integer that is divided to convey a major
state and a minor state. A major state is mandatory and defined by {{PSA-SM}}.
A minor state is optional and 'IMPLEMENTATION DEFINED'. The PSA security
lifecycle state and implementation state are encoded as follows:

* version\[15:8\] - PSA security lifecycle state, and
* version\[7:0\] - IMPLEMENTATION DEFINED state.

The PSA lifecycle states are illustrated in {{fig-lifecycle-states}}. For PSA,
a remote verifier can only trust reports from the PSA RoT when it is in SECURED
or NON_PSA_ROT_DEBUG major states.

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
{::include cddl/psa-security-lifecycle.cddl}
~~~

### Boot Seed

The Boot Seed claim represents a random value created at system boot time that
will allow differentiation of reports from different boot sessions.

This claim MUST be present in a PSA attestation token.

~~~
{::include cddl/psa-boot-seed.cddl}
~~~

## Software Inventory Claims

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

Note that, as described in {{?I-D.ietf-rats-architecture}}, a relying party
will typically see the result of the verification process from the Verifier in
form of an attestation result, rather than the "naked" PSA token from the
attesting endpoint.  Therefore, a relying party is not expected to understand
the Software Components claim.  Instead, it is for the Verifier to check this
claim against the available endorsements and provide an answer in form of an
"high level" attestation result, which may or may not include the original
Software Components claim.

~~~
{::include cddl/psa-software-components.cddl}
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
state. The value SHOULD be 1.  This claim is intended for devices that are not
compliant with {{PSA-SM}}.

~~~
{::include cddl/psa-no-sw-measurements.cddl}
~~~

## Verification Claims

### Verification Service Indicator

The Verification Service Indicator claim is a hint used by a relying party to
locate a validation service for the token. The value is a text string that can
be used to locate the service or a URL specifying the address of the service. A
verifier may choose to ignore this claim in favor of other information.

~~~
{::include cddl/psa-verification-service-indicator.cddl}
~~~

### Profile Definition

The Profile Definition claim contains the name of a document that describes the
"profile" of the report. The document name may include versioning. The value
for this specification MUST be PSA_IOT_PROFILE_1.

~~~
{::include cddl/psa-profile.cddl}
~~~

# Token Encoding and Signing

The report is encoded as a COSE Web Token (CWT) {{!RFC8392}}, similar to the
Entity Attestation Token (EAT) {{?I-D.ietf-rats-eat}}. The token consists of a
series of claims declaring evidence as to the nature of the instance of
hardware and software. The claims are encoded in CBOR {{!RFC7049}} format.  For
asymmetric key algorithms, the signature structure MUST be COSE_Sign1.  For
symmetric key algorithms, the structure MUST be COSE_Mac0.

# Collated CDDL

~~~
{::include cddl/psa-token.cddl}

{::include cddl/psa-common-types.cddl}

{::include cddl/psa-boot-seed.cddl}

{::include cddl/psa-client-id.cddl}

{::include cddl/psa-hardware-version.cddl}

{::include cddl/psa-implementation-id.cddl}

{::include cddl/psa-instance-id.cddl}

{::include cddl/psa-no-sw-measurements.cddl}

{::include cddl/psa-nonce.cddl}

{::include cddl/psa-profile.cddl}

{::include cddl/psa-security-lifecycle.cddl}

{::include cddl/psa-software-components.cddl}

{::include cddl/psa-verification-service-indicator.cddl}
~~~

# Security and Privacy Considerations

This specification re-uses the CWT and the EAT specification. Hence, the
security and privacy considerations of those specifications apply here as well.

Since CWTs offer different ways to protect the token, this specification
profiles those options and allows signatures based on use of public key
cryptography as well as MAC authentication. The token MUST be signed following
the structure of the COSE specification {{!RFC8152}}.  The COSE type MUST be
COSE_Sign1 for public key signatures or COSE_Mac0 for MAC authentication.  Note
however that use of MAC authentication is NOT RECOMMENDED due to the associated
infrastructure costs for key management and protocol complexities. It may also
restrict the ability to interoperate with third parties.

Attestation tokens contain information that may be unique to a device and
therefore they may allow to single out an individual device for tracking
purposes.  Implementations that have privacy requirements must take appropriate
measures to ensure that the token is only used to provision anonymous/pseudonym
keys.

# Verification

To verify the token, the primary need is to check correct formation and signing
as for any CWT token.  In addition though, the verifier can operate a policy
where values of some of the claims in this profile can be compared to reference
values, registered with the verifier for a given deployment, in order to
confirm that the device is endorsed by the manufacturer supply chain.  The
policy may require that the relevant claims must have a match to a registered
reference value.  All claims may be worthy of additional appraisal.  It is
likely that most deployments would include a policy with appraisal for the
following claims:

* Instance ID - the value of the Instance ID can be used (together with the kid
  in the token COSE header, if present) to assist in locating the public key
  used to verify the token signature.
* Implementation ID - the value of the Implementation ID can be used to
  identify the verification requirements of the deployment.
* Software Component, Measurement Value - this value can uniquely identify a
  firmware release from the supply chain. In some cases, a verifier may
  maintain a record for a series of firmware releases, being patches to an
  original baseline release. A verification policy may then allow this value to
  match any point on that release sequence or expect some minimum level of
  maturity related to the sequence.
* Software Component, Signer ID - where present in a deployment, this could
  allow a verifier to operate a more general policy than that for Measurement
  Value as above, by allowing a token to contain any firmware entries signed by
  a known Signer ID, without checking for a uniquely registered version.

# IANA Considerations


## CBOR Web Token Claims Registration

This specification registers the following claims in the IANA "CBOR Web Token (CWT) 
Claims" registry {{IANA-CWT}}, established by {{!RFC8392}}.

### Auth Challenge Claim

   *  Claim Name: "psa-nonce-claim"

   *  Claim Description: Auth Challenge

   *  JWT Claim Name: "psa-nonce-claim"

   *  Claim Key: [[Proposed: -75008]]

   *  Claim Value Type(s): bytes (32, 48, or 64 bytes in length)

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.1.1 of [[this RFC]

### Client ID Claim

   *  Claim Name: "psa-client-id"

   *  Claim Description: Client ID

   *  JWT Claim Name: "psa-client-id"

   *  Claim Key: [[Proposed: -75001]]

   *  Claim Value Type(s): signed integer

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.1.2 of [[this RFC]]

### Instance ID Claim

   *  Claim Name: "psa-instance-id"

   *  Claim Description: Instance ID

   *  JWT Claim Name: "psa-instance-id"

   *  Claim Key: [[Proposed: -75009]]

   *  Claim Value Type(s): bytes (33 bytes in length)

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.2.1 of [[this RFC]]

### Implementation ID Claim

   *  Claim Name: "psa-implementation-id"

   *  Claim Description: Implementation ID

   *  JWT Claim Name: "psa-implementation-id"

   *  Claim Key: [[Proposed: -75003]]

   *  Claim Value Type(s): bytes (32 bytes in length)

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.2.2 of [[this RFC]]

### Hardware Version Claim

   *  Claim Name: "psa-hardware-version"

   *  Claim Description: Hardware Version

   *  JWT Claim Name: "psa-hardware-version"

   *  Claim Key: [[Proposed: -75005]]

   *  Claim Value Type(s): text

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.2.3 of [[this RFC]]

### Security Lifecycle Claim

   *  Claim Name: "psa-lifecycle"

   *  Claim Description: Security Lifecycle

   *  JWT Claim Name: "psa-lifecycle"

   *  Claim Key: [[Proposed: -75002]]

   *  Claim Value Type(s): unsigned integer 

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.3.1 of [[this RFC]]

### Boot Seed Claim

   *  Claim Name: "psa-boot-seed"

   *  Claim Description: Boot Seed

   *  JWT Claim Name: "psa-boot-seed"

   *  Claim Key: [[Proposed: -75004]]

   *  Claim Value Type(s): bytes (32 bytes in length)

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.3.2 of [[this RFC]]

### Software Components Claim

   *  Claim Name: "psa-software-components"

   *  Claim Description: Software Components

   *  JWT Claim Name: "psa-software-components"

   *  Claim Key: [[Proposed: -75006]]

   *  Claim Value Type(s): array

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.4.1 of [[this RFC]]

### No Software Measurements Claim

   *  Claim Name: "psa-no-sw-measurement"

   *  Claim Description: No Software Measurements

   *  JWT Claim Name: "psa-no-sw-measurement"

   *  Claim Key: [[Proposed: -75007]]

   *  Claim Value Type(s): unsigned integer

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.4.2 of [[this RFC]]

### Verification Service Indicator Claim

   *  Claim Name: "psa-verification-service-indicator"

   *  Claim Description: Verification Service Indicator

   *  JWT Claim Name: "psa-verification-service-indicator"

   *  Claim Key: [[Proposed: -75010]]

   *  Claim Value Type(s): text

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.5.1 of [[this RFC]]


### Profile Definition Claim

   *  Claim Name: "psa-profile"

   *  Claim Description: Profile Definition

   *  JWT Claim Name: "psa-profile"

   *  Claim Key: [[Proposed: -75000]]
   
   *  Claim Value Type(s): text

   *  Change Controller: [[Authors of this RFC]]

   *  Specification Document(s): Section 3.5.2 of [[this RFC]]



## Media Type Registration

IANA is requested to register the "application/psa-attestation-token" media
type {{!RFC2046}} in the "Media Types" registry {{IANA-MediaTypes}} in the
manner described in RFC 6838 {{!RFC6838}}, which can be used to indicate that
the content is a PSA Attestation Token.

* Type name: application
* Subtype name: psa-attestation-token
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary
* Security considerations: See the Security Considerations section
  of [[this RFC]]
* Interoperability considerations: n/a
* Published specification: [[this RFC]]
* Applications that use this media type: Attesters and Relying Parties sending
  PSA attestation tokens over HTTP(S), CoAP(S), and other transports.
* Fragment identifier considerations: n/a
* Additional information:

  * Magic number(s): n/a
  * File extension(s): n/a
  * Macintosh file type code(s): n/a

* Person & email address to contact for further information:
  Hannes Tschofenig, Hannes.Tschofenig@arm.com
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Hannes Tschofenig, Hannes.Tschofenig@arm.com
* Change controller: IESG
* Provisional registration?  No

## CoAP Content-Formats Registration

IANA is requested to register the CoAP Content-Format ID for the
"application/psa-attestation-token" media type in the "CoAP Content-Formats"
registry {{IANA-CoAP-Content-Formats}}.

### Registry Contents

*  Media Type: application/psa-attestation-token
*  Encoding: -
*  Id: [[To-be-assigned by IANA]]
*  Reference: [[this RFC]]

--- back

# Reference Implementation

A reference implementation is provided by the Trusted Firmware project {{TF-M}}.

# Example

The following example shows a PSA attestation token for an hypothetical system
comprising two measured software components (a boot loader and a trusted RTOS).
The attesting device is in a lifecycle state {{sec-security-lifecycle}} of
SECURED.  The attestation has been requested from a client residing in the
SPE:

~~~
{::include cddl/example/psa-token.diag}
~~~

The JWK representation of the IAK used for creating the COSE Sign1 signature
over the PSA token is:

~~~
{::include cddl/example/iak.jwk}
~~~

The resulting COSE object is:

~~~
{::include cddl/example/cose.diag}
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

Thanks to Carsten Bormann for help with the CDDL and Nicholas Wood for ideas
and comments.
