#!/usr/bin/env python3

import sys
sys.path.append("pycose")
sys.path.append("python-base45")
import base64
import base45
import zlib
import cbor2
import json
import pyasn1.codec.ber.decoder
import time
import os
import cose.messages
import cose.keys



def read_message(cert_text):
	decoded = base45.b45decode(cert_text)
	decompressed = zlib.decompress(decoded)
	cose_message = cose.messages.CoseMessage.decode(decompressed)

	return cose_message


def print_certificate(cert_no, cert_obj, schemas):
	cert_type = "unknown"
	group = None
	if "v" in cert_obj:
		cert_type = "vaccination"
		group = cert_obj["v"][0]
	elif "t" in cert_obj:
		cert_type = "test"
		group = cert_obj["t"][0]
	elif "r" in cert_obj:
		cert_type = "recovery"
		group = cert_obj["r"][0]

	print("== EUDCC #%s (%s certificate) ==" % (cert_no, cert_type))
	print("Version: %s" % cert_obj["ver"])
	if group:
		print("UID: %s" % group["ci"])
		print("Issuer: %s" % group["is"])
		member_state = get_schema_display(schemas, "country-2-codes", group["co"])
		print("Member state: %s" % member_state)
		tg = get_schema_display(schemas, "disease-agent-targeted", group["tg"])
		print("Disease targeted: %s" % tg)
	name = cert_obj["nam"]
	print("Name: %s, %s (%s, %s)" % (name["fn"], name["gn"], name["fnt"], name["gnt"]))
	print("Date of birth: %s" % cert_obj["dob"])
	if "v" in cert_obj:
		print("Date of vaccination: %s" % group["dt"])

		vaccine_type = get_schema_display(schemas, "vaccine-prophylaxis", group["vp"])
		print("Vaccine type: %s" % vaccine_type)

		vaccine_product = get_schema_display(schemas, "vaccine-medicinal-product", group["mp"])
		print("Vaccine product: %s" % vaccine_product)
		vaccine_manufacturer = get_schema_display(schemas, "vaccine-mah-manf", group["ma"])
		print("Vaccine manufacturer: %s" % vaccine_manufacturer)
		print("Dose: %s / %s" % (group["dn"], group["sd"]))
	elif "t" in cert_obj:
		print("Date of sample collection: %s" % group["sc"])
		if "tc" in group:
			print("Testing facility: %s" % group["tc"])

		test_type = get_schema_display(schemas, "test-type", group["tt"])
		print("Test type: %s" % test_type)

		if "nm" in group:
			print("Test name: %s" % group["nm"])
		if "ma" in group:
			test_device = get_schema_display(schemas, "test-manf", group["ma"])
			print("Rapid antigen test device: %s" % test_device)
		test_result = get_schema_display(schemas, "test-result", group["tr"])
		print("Test result: %s" % test_result)
	elif "r" in cert_obj:
		print("Date of first positive result: %s" % group["fr"])
		print("Valid from: %s" % group["df"])
		print("Valid until: %s" % group["du"])
	print("== ==")


def load_keys(file):
	with open(file, "r") as stream:
		text = stream.read()
	return json.loads(text)


def key_to_cose(key_obj):
	curve = key_obj["publicKeyAlgorithm"]["namedCurve"].replace("-", "_")
	kty = key_obj["publicKeyAlgorithm"]["name"]
	if kty == "ECDSA":
		kty = "EC2"
	else:
		raise ValueError("Unknown public key algorithm")

	key_pem_b64 = key_obj["publicKeyPem"]
	key_pem = base64.b64decode(key_pem_b64)
	asn1, _remainder = pyasn1.codec.ber.decoder.decode(key_pem)
	asn1_bytes = asn1[1].asOctets()

	if asn1_bytes[0] != 0x04:
		raise ValueError("EC public key is not an uncompressed point")

	point_length = (len(asn1_bytes) - 1) // 2

	x = asn1_bytes[1:1 + point_length]
	y = asn1_bytes[1+point_length:1+2*point_length]

	dict = {
		"CURVE": curve,
		"KTY": kty,
		"X": x,
		"Y": y,
	}
	return cose.keys.CoseKey.from_dict(dict)


def check_signature(cose_message, signing_keys):
	kid = cose_message.uhdr[cose.headers.KID]
	if kid is None:
		print("Message not signed!")
		return False

	key_id = base64.b64encode(kid).decode()
	print("Signed by key id %s" % key_id)
	#print(json.dumps(key_obj, indent=4))

	if key_id in signing_keys:
		print("Key found in database")
		key_obj = signing_keys[key_id]
		cose_key = key_to_cose(key_obj)
		cose_message.key = cose_key
		if cose_message.verify_signature():
			print("Signature is valid")
			return True
		else:
			print("Signature is invalid!")
			return False
	else:
		print("Key not found in database!")
		return False


def load_schemas(schema_dir):
	result = {}
	for file in os.listdir(schema_dir):
		if file.endswith(".json"):
			path = schema_dir + file
			name = file[:-5]
			with open(path, "r") as stream:
				text = stream.read()
				text_json = json.loads(text)
				result[name] = text_json
	return result


def get_schema_display(schemas, name, key):
	try:
		return schemas[name]["valueSetValues"][key]["display"]
	except ValueError:
		return "<unknown> ('%s')" % key


def normalize(cert_text):
	cert_text = cert_text.strip()
	if cert_text.startswith("HC1:") or cert_text.startswith("HC2:"):
		cert_text = cert_text[4:]

	return cert_text





def input_as_text(cert_text):
	cert_text = normalize(cert_text)

	cose_message = read_message(cert_text)
	cert_json = cbor2.loads(cose_message.payload)
	#print(json.dumps(as_json, indent=4))

	print("Issuer: %s" % cert_json[1])
	print("Issuing Date: %s" % time.ctime(cert_json[6]))
	print("Expiring Date: %s" % time.ctime(cert_json[4]))
	hcert = cert_json[-260]

	schemas = load_schemas("ehn-dcc-schema/valuesets/")
	for (hcert_no, hcert_obj) in hcert.items():
		print_certificate(hcert_no, hcert_obj, schemas)

	signing_keys = load_keys("signing_keys.json")
	check_signature(cose_message, signing_keys)


def input_as_file(path):
	with open(path, "r") as stream:
		cert_text = stream.read()
	input_as_text(cert_text)


def usage(cmd):
	print("Usage:")
	print("\t%s STRING" % cmd)
	print("\t%s -f FILE" % cmd)


if __name__ == "__main__":
	argc = len(sys.argv)
	if argc == 2:
		input_as_text(sys.argv[1])
	elif argc == 3 and sys.argv[1] == "-f":
		input_as_file(sys.argv[2])
	else:
		usage(sys.argv[0])


