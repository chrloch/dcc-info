# A simple tool to show the contents of a EU Digital COVID Certificate
# This tool does not verify the signature of the DCC
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
from datetime import datetime

def main(args):
    try:
        logging.debug('Opening image file')
        image = Image.open(args.input_file)
    
        logging.debug('Decoding QR Code')
        qr_code = qr_decode(image)[0]
        qr_code_data =  qr_code.data.decode()

        assert qr_code_data.startswith('HC1:')

        logging.debug('Decoding/Decompressing Base45 data')
        decompressed = zlib.decompress(b45decode(qr_code_data[4:]))

        logging.debug('Decoding COSE object')
        cose_data = Sign1Message.decode(decompressed)
        payload = cbor2.loads(cose_data.payload)
        logging.debug(f'Payload: {payload}')
        
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