# A simple tool to show the contents of a EU Digital COVID Certificate
# This tool does not verify the signature of the DCC
# (extended version for personal debugging)
import sys
import logging
import zlib
import cbor2
from argparse import ArgumentParser
from pprint import pprint
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode
from base45 import b45decode
from cose.messages import Sign1Message
from cose.headers import Algorithm, KID
from datetime import datetime
from base64 import b64encode

def get_kid_b64(cose_data):
    if KID in cose_data.uhdr: 
        kid = cose_data.uhdr[KID]
    elif KID in cose_data.phdr:
        kid = cose_data.phdr[KID]
    else:
        kid = b''

    return b64encode(kid)


def main(args):
    try:
        logging.debug('Opening image file')
        image = Image.open(args.input_file)

        logging.debug('Decoding QR Code')
        qr_code = qr_decode(image)[0]
        qr_code_data =  qr_code.data.decode()

        print('Raw:', qr_code_data,'\n')
        assert qr_code_data.startswith('HC1:')

        logging.debug('Decoding/Decompressing Base45 data')
        decompressed = zlib.decompress(b45decode(qr_code_data[4:]))

        logging.debug('Decoding COSE object')
        try:
            cose_data = Sign1Message.decode(decompressed)
            print(cbor2.loads(decompressed))
            print(f'Unprotected Header: {cose_data.uhdr}')
            print(f'Protected Header: {cose_data.phdr}')
            print(f'KID = {get_kid_b64(cose_data)}')
            payload = cbor2.loads(cose_data.payload)
        except AttributeError:
            # Nonstandard certs issued by certain countries
            cose_data = cbor2.loads(decompressed)
            print(cose_data)
            print(f'KID = {b64encode(cose_data[3][:8])}')
            payload = cbor2.loads(cose_data[2])


        try:
            payload[4] = f'Timestamp({datetime.fromtimestamp(payload[4]).isoformat()})'
            payload[6] = f'Timestamp({datetime.fromtimestamp(payload[6]).isoformat()})'
        except:
            pass
        pprint(payload)

    except AssertionError as a:
        print(f'This does not seem to be a Digital Corona Certificate')
    except Exception as e:
        print(f"Error processing {args.input_file}: {e}")



if __name__ == '__main__':
    parser = ArgumentParser(description='EU Digital Corona Certificate Info')
    parser.add_argument('input_file', type=str , help='QR Code of info file')
    args = parser.parse_args()
    sys.exit(main(args))