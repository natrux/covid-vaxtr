# covid-vaxtr

Small program to display and check vaccination, test and recovery certificates
issued according to the EU Covid certification standard.

## Installation


1. Install the python dependencies:
   `attrs`, `cbor2`, `cryptography`, `ecdsa`, `pyasn1`
1. Clone the repository.
1. Download the submodules:
   ```git submodule update --init```

Additionally, it might be necessary to update the signing keys located in
`signing_keys.json`, since they only represent a snapshot.
The current keys can be found
[at this repository](https://github.com/lovasoa/sanipasse/blob/master/src/assets/Digital_Green_Certificate_Signing_Keys.json)
where they are apparently extracted from an official app on a regular basis.


## Usage

Scan or photograph your QR code.
Then use a barcode scanner to read its contents,
for example

`zbarimg -q --raw your_photo.jpg > your_data.txt`

Then feed the data into the main program:

`./main.py -f your_data.txt`


## Background

Here is some documentation from the EU concerning the data format.

* <https://ec.europa.eu/health/sites/health/files/ehealth/docs/covid-certificate_json_specification_en.pdf>

* <https://ec.europa.eu/health/sites/health/files/ehealth/docs/digital-green-certificates_v3_en.pdf>


## Contributing

Issues and pull requests welcome!

