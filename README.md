# dcc-info
EU Digital COVID Certificate Reader

## Usage

`python dccinfo.py my_digitial_certificate_qr_code.png`

Prints the contents of the certificate.

The default output is
- Unprotected header
- Protected header 
- Key ID (for lookup of signer in trust list)
- Payload of the COVID Certificate

## Screenshot

If you provide `:screenshot` as image file name, the script will
attempt to take a screenshot and read the QR code from  there.

## Flags and options
`--raw`  print  the raw QR-Code content

`--hashes` print the hashes by which this QR-Code could be identified during revocation

`--cbortag` print the CBOR-Tag object representation

`--no-header` do NOT print the header info and Key ID

`--no-payload` do NOT print the payload

`--verify-signature` verify the signature (using the trust list of the CovPass-Check app)

