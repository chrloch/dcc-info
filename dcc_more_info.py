# A simple tool to show the contents of a EU Digital COVID Certificate
# This tool does not verify the signature of the DCC
# (extended version for personal debugging)
from hashlib import sha256
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
from cose.algorithms import Es256, Ps256

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
        if args.input_file.lower() == ':screenshot':
            logging.debug('Taking screenshot')
            import pyautogui
            image = pyautogui.screenshot()
        else: 
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
            plain_cbor = cbor2.loads(decompressed)
            print('CBOR decoded:', plain_cbor)
            print(f'\nUnprotected Header: {cose_data.uhdr}')
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

        print('\nPossible revocation hashes:')
        signature = plain_cbor.value[3]
        if get_algorithm(plain_cbor) == Es256:
            print('SIGNATURE (EC)  ', get_hash64(signature[:int(len(signature) / 2)]))
        elif get_algorithm(plain_cbor) == Ps256:
            print('SIGNATURE (RSA) ', get_hash64(signature))
        print('UCI             ', get_hash64(bytes(get_uci(payload),'utf-8')))
        print('COUNTRYCODEUCI  ', get_hash64(bytes(payload[1]+get_uci(payload), 'utf-8')))


    except AssertionError as a:
        print(f'This does not seem to be a Digital Corona Certificate')
    except Exception as e:
        print(f"Error processing {args.input_file}: {e}")


def get_hash64(hashed_value):
    return b64encode(sha256(hashed_value).digest()[:16]).decode('utf-8')

def get_algorithm(cose_as_cbor):
    algo_id = cbor2.loads(cose_as_cbor.value[0])[1]
    return Es256 if algo_id == -7 else Ps256 if algo_id == -37 else None

def get_uci(payload):
    data = payload[-260][1]
    return data['v' if 'v' in data.keys() else 't' if 't' in data.keys() else 'r'][0]['ci']

if __name__ == '__main__':
    parser = ArgumentParser(description='EU Digital Corona Certificate Info')
    parser.add_argument('input_file', type=str , help='QR Code of info file')
    args = parser.parse_args()
    sys.exit(main(args))