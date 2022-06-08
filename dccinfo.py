# A simple tool to show the contents of a EU Digital COVID Certificate
# This tool does not verify the signature of the DCC

# Image/QR-Code processing
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode

# Encoding related 
import zlib
import cbor2
from base64 import b64encode
from base45 import b45decode
from hashlib import sha256

# Signature processing
from cose.algorithms import Es256, Ps256
from cose.messages import Sign1Message
from cose.headers import KID

# General 
from datetime import datetime
from argparse import ArgumentParser
from pprint import pprint


def main(args):

    qr_code_data = get_qr_code_contents(args.input_file)
    if args.raw: 
        print('Raw:', qr_code_data,'\n')
    
    assert qr_code_data.startswith('HC1:'), 'QR Code content must start with magic number "HC1:"'

    # Decompress the base45-encoded payload
    decompressed = zlib.decompress(b45decode(qr_code_data[4:]))

    cbor_tag_object = cbor2.loads(decompressed)
    if args.cbortag: 
        print(f'CBOR Tag object: {cbor_tag_object}\n\n') 
    # Decode the decompressed data as COSE object
    try:
        cose_sign1message = Sign1Message.decode(decompressed)
        if not args.no_header:
            print(f'Unprotected Header: {cose_sign1message.uhdr}')
            print(f'Protected Header: {cose_sign1message.phdr}')
            print(f'KID: {get_kid_b64(cose_sign1message)}')
        payload = cbor2.loads(cose_sign1message.payload)
    except AttributeError:
        # Nonstandard certs issued by certain countries
        if not args.no_header:
            print(f'KID: {b64encode(cbor_tag_object[3][:8])}')
        payload = cbor2.loads(cbor_tag_object[2])

        if args.verify_signature: 
            print('ERROR: Signature verification not supported with this kind of DCC')
            args.verify_signature = False

    if not args.no_payload:
        try:
            payload[4] = f'Timestamp({datetime.fromtimestamp(payload[4]).isoformat()})'
            payload[6] = f'Timestamp({datetime.fromtimestamp(payload[6]).isoformat()})'
        except:
            pass
        pprint(payload)

    if args.hashes:
        print('\nPossible revocation hashes:')
        signature = cbor_tag_object.value[3]
        if get_algorithm(cbor_tag_object) == Es256:
            print('SIGNATURE (EC)  ', get_hash64(signature[:int(len(signature) / 2)]))
        elif get_algorithm(cbor_tag_object) == Ps256:
            print('SIGNATURE (RSA) ', get_hash64(signature))
        print('UCI             ', get_hash64(bytes(get_uci(payload),'utf-8')))
        print('COUNTRYCODEUCI  ', get_hash64(bytes(payload[1]+get_uci(payload), 'utf-8')))

    if args.verify_signature:
        from dccsignature import verify_signature
        verify_signature(cose_sign1message, check_extensions=True, silent=False)



def get_qr_code_contents(imagefile, qr_code_nr=0):
    '''Returns the contents of a (default: the first) QR code found in the image file.
       If the image file name is ':screenshot', instead of opening a file, the screen
       will be grabbed'''
    if args.input_file.lower() == ':screenshot':
        import pyautogui
        image = pyautogui.screenshot()
    else: 
        image = Image.open(args.input_file)

    qr_code = qr_decode(image)[qr_code_nr]
    return qr_code.data.decode()

def get_kid_b64(cose_sign1message):
    '''Get the KID in base64 encoding (the lookup format) from the protected or the unprotected header.
       The spec allows it to be in any of the header sections.
    '''
    if KID in cose_sign1message.uhdr: 
        kid = cose_sign1message.uhdr[KID]
    elif KID in cose_sign1message.phdr:
        kid = cose_sign1message.phdr[KID]
    else:
        kid = b''

    return b64encode(kid).decode('utf-8')


def get_hash64(hashed_value):
    return b64encode(sha256(hashed_value).digest()[:16]).decode('utf-8')

def get_algorithm(cose_as_cbor):
    'Return the algorithm class from a cbor encoded cose object'
    algo_id = cbor2.loads(cose_as_cbor.value[0])[1]
    return Es256 if algo_id == -7 else Ps256 if algo_id == -37 else None

def get_uci(payload:dict):
    'Get the UCI from a decoded DCC payload'
    data = payload[-260][1]
    return data['v' if 'v' in data.keys() else 't' if 't' in data.keys() else 'r'][0]['ci']

if __name__ == '__main__':
    parser = ArgumentParser(description='EU Digital Corona Certificate Info')
    parser.add_argument('input_file', type=str , help='image file name or ":screenshot" to grab from screen')
    parser.add_argument('--raw', action='store_true' , help='Print the raw QR code contents')
    parser.add_argument('--hashes', action='store_true' , help='Print hashes for revocation')
    parser.add_argument('--cbortag', action='store_true' , help='Print CBOR Tag representation')
    parser.add_argument('--no-header', action='store_true' , help='Do not print header info')
    parser.add_argument('--no-payload', action='store_true' , help='Do not print payload')
    parser.add_argument('--verify-signature', action='store_true' , help='Verify signature')

    args = parser.parse_args()

    try:
        main(args)
    except AssertionError as a:
        print(f'This does not seem to be a Digital Corona Certificate')
    except Exception as e:
        print(f"Error processing {args.input_file}: {e}")
