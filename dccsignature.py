
import requests
import json
import cbor2
from cose.keys import CoseKey
from cryptography import x509
from cose.keys.curves import P256
from cose.keys.keyops import VerifyOp
from cryptography.utils import int_to_bytes
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.algorithms import Es256, Ps256
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, RSAKpE, RSAKpN, KpKty, KpKeyOps
from cryptography.hazmat.backends.openssl.backend import backend as OpenSSLBackend

from dccinfo import get_kid_b64

DSC_LIST = 'https://de.dscg.ubirch.com/trustList/DSC/'

DCC_TYPES = {'v': "VAC", 't': "TEST", 'r': "REC"}
EXTENDED_KEY_USAGE_OIDs = {'t':'1.3.6.1.4.1.0.1847.2021.1.1','v':'1.3.6.1.4.1.0.1847.2021.1.2','r':'1.3.6.1.4.1.0.1847.2021.1.3',
                           'T':'1.3.6.1.4.1.1847.2021.1.1',  'V':'1.3.6.1.4.1.1847.2021.1.2',  'R':'1.3.6.1.4.1.1847.2021.1.3'}


def certificates_from_trust_list(): 
    """Downloads and caches the certificates from the acceptance environment
        using  API for CovPass Check app"""
    response = requests.get(DSC_LIST)
    assert response.ok, "Trust list not reachable"
    
    dsc_list = json.loads(response.text[response.text.find('\n'):])
    kid_dict = { dsc['kid'] : dsc['rawData'] for dsc in dsc_list['certificates'] }
    return kid_dict

def key_from_cert(cert):
    'Return  the public key from a certificate'
    if isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
        return CoseKey.from_dict(
            {
                KpKeyOps: [VerifyOp],
                KpKty: KtyEC2,
                EC2KpCurve: P256,
                KpAlg: Es256,      # ECDSA using P-256 and SHA-256
                EC2KpX: int_to_bytes(cert.public_key().public_numbers().x),
                EC2KpY: int_to_bytes(cert.public_key().public_numbers().y),
            }
        )
    elif isinstance(cert.public_key(), rsa.RSAPublicKey):
        return CoseKey.from_dict(
            {
                KpKeyOps: [VerifyOp],
                KpKty: KtyRSA,
                KpAlg: Ps256,  # RSASSA-PSS using SHA-256 and MGF1 with SHA-256
                RSAKpE: int_to_bytes(cert.public_key().public_numbers().e),
                RSAKpN: int_to_bytes(cert.public_key().public_numbers().n),
            }
        )
    else:
        raise ValueError(f'Unsupported certificate agorithm: {cert.signature_algorithm_oid} for verification.')


def verify_signature( sign1Message, check_extensions=True, silent=False ):
    """Verifies the signature of the DCC.
       This requires download of the certificates from the acceptance environment"""

    certs = certificates_from_trust_list()
    
    kid = get_kid_b64(sign1Message)
    cert_base64 = certs.get(kid)
    if cert_base64 is None: 
        if not silent:
            print(f'Certificate with KID {kid} NOT FOUND in  trust list')
        return False

    cert = x509.load_pem_x509_certificate(
        f'-----BEGIN CERTIFICATE-----\n{cert_base64}\n-----END CERTIFICATE-----'.encode(), OpenSSLBackend)

    sign1Message.key = key_from_cert(cert)
    if not sign1Message.verify_signature():
        if not silent:
            print(f"Signature could not be verified with signing certificate {cert_base64}")
        return False


    # The EU DCC standard supports extensions that limit DSC usage, e.g. so  that some issuers 
    # may only sign Vaccinations and others may only sign Tests etc. 
    if check_extensions:
        payload = cbor2.loads(sign1Message.payload)
        extensions = { extension.oid._name:extension for extension in cert.extensions}
        if 'extendedKeyUsage' in extensions.keys():
            allowed_usages = [oid.dotted_string for oid in extensions['extendedKeyUsage'].value._usages]
            if len( set(EXTENDED_KEY_USAGE_OIDs.values()) & set(allowed_usages) ) > 0: # Only check if at least one known OID is used in DSC
                for cert_type in DCC_TYPES.keys():
                    if cert_type in payload[-260][1].keys():
                        # There are 2 versions of extended key usage OIDs in circulation. We simply logged them as upper and lower case
                        # types, but they actually mean the same. So we treat t == T, v == V and r == R
                        if EXTENDED_KEY_USAGE_OIDs[cert_type] not in allowed_usages \
                        and EXTENDED_KEY_USAGE_OIDs[cert_type.upper()] not in allowed_usages:
                            if not silent:
                                print(f"DCC is of type {DCC_TYPES[cert_type]}, DSC allows {allowed_usages} "+\
                                        f"but not {EXTENDED_KEY_USAGE_OIDs[cert_type]} or {EXTENDED_KEY_USAGE_OIDs[cert_type.upper()]}")
                            return False
    
    # All checks have passed
    print('Signature verified')
    return True

