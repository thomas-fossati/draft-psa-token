# Arm's Platform Security Architecture (PSA) Attestation Token

This is the working area for the individual Internet-Draft, "Arm's Platform Security Architecture (PSA) Attestation Token".

* [Editor's Copy](https://thomas-fossati.github.io/draft-psa-token/#go.draft-tschofenig-rats-psa-token.html)
* [Individual Draft](https://tools.ietf.org/html/draft-tschofenig-rats-psa-token)
* [Compare Editor's Copy to Individual Draft](https://thomas-fossati.github.io/draft-psa-token/#go.draft-tschofenig-rats-psa-token.diff)

## Building the Draft

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make -C art && make -C cddl check-example && make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md).

## Submitting the draft

The XML file needs to be "prepped" before submitting it to the datatracker:

```sh
$ make draft-tschofenig-rats-psa-token-NN.xml
$ xml2rfc --v3 --preptool draft-tschofenig-rats-psa-token-NN.xml
```

The resulting `draft-tschofenig-rats-psa-token-NN.prepped.xml` is what needs to be uploaded.

## Running the CDDL tests

To run the CDDL validation tests:

```sh
$ make -C cddl
```

The validation suite depends on `cddl` and `diag2cbor` which can be installed by:
```sh
# gem install cddl cbor-diag

```

## Contributing

See the
[guidelines for contributions](https://github.com/thomas-fossati/draft-psa-token/blob/master/CONTRIBUTING.md).
