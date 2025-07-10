import base64
import boto3
import collections
import gzip
import hashlib
import os


_encrypted_token_prefix = '{encrypted}:'


def default_kms_key():
    return 'alias/ytsubs-token-encrypt-key'


def data_compress(s, /, *, encoding='utf-8', errors='strict'):
    b = base64._bytes_from_decode_data(s)
    compressed = gzip.compress(b)
    encoded = urlsafe_b64encode(compressed)
    if isinstance(s, str):
        return encoded.decode(encoding=encoding, errors=errors)
    return encoded

def data_decompress(s, /, *, encoding='utf-8', errors='strict'):
    compressed = urlsafe_b64decode(s)
    decompressed = gzip.decompress(compressed)
    if isinstance(s, str):
        return decompressed.decode(encoding=encoding, errors=errors)
    return decompressed


def getenv(key, default=None, /, *, integer=False, string=True):
    """
        Guarantees a returned type from calling `os.getenv`
        The caller can request the integer type,
          or use the default string type.
    """

    args = dict(key=key, default=default, integer=integer, string=string)
    supported_types = dict(zip(args.keys(), (
        (str,), # key
        (
            bool,
            float,
            int,
            str,
            None.__class__,
        ), # default
        (bool,) * (len(args.keys()) - 2),
    )))
    unsupported_type_msg = 'Unsupported type for positional argument, "{}": {}'
    for k, t in supported_types.items():
        v = args[k]
        assert isinstance(v, t), unsupported_type_msg.format(k, type(v))

    d = str(default) if default is not None else None

    r = os.getenv(key, d)
    if r is None:
        if string: r = str()
        if integer: r = int()
    elif integer:
        r = int(float(r))
    return r


def token_decrypt(arg_str, /, *, key=None):
    # not marked as encrypted
    if not arg_str.startswith(_encrypted_token_prefix):
        return arg_str
    # decrypt the string without the prefix
    prefix_len = len(_encrypted_token_prefix)
    arg_bytes = urlsafe_b64decode(arg_str[ prefix_len :])
    kms = boto3.client('kms')
    if key is None:
        response = kms.decrypt(CiphertextBlob=arg_bytes)
    else:
        response = kms.decrypt(CiphertextBlob=arg_bytes, KeyId=key)
    result_bytes = response['Plaintext']
    result_str = result_bytes.decode()
    return result_str


def token_encrypt(arg_str, /, *, key=None):
    o = arg_str
    # already marked as encrypted
    if arg_str.startswith(_encrypted_token_prefix):
        return arg_str
    if key is None:
        key = default_kms_key()
    assert key is not None, 'token_encrypt requires a KMS key identifier'
    arg_bytes = arg_str.encode() if isinstance(arg_str, str) else arg_str
    kms = boto3.client('kms')
    response = kms.encrypt(KeyId=key, Plaintext=arg_bytes)
    encrypted_bytes = response['CiphertextBlob']
    result_bytes = urlsafe_b64encode(encrypted_bytes)
    result_str = result_bytes.decode()
    e = _encrypted_token_prefix + result_str
    # verify that we can decrypt the result
    d = token_decrypt(e, key=key)
    if d == o:
        return e
    return o


def token_hash(arg_str, /):
    arg_bytes = arg_str
    if isinstance(arg_str, str):
        arg_bytes = arg_str.encode()
    return hashlib.sha256(arg_bytes).hexdigest()


def urlsafe_b64decode(s, validate=True):
    b = base64._bytes_from_decode_data(s)
    b = b.translate(base64._urlsafe_decode_translation)
    return base64.b64decode(b, validate=validate)


def urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(s)


GoogleEnvironment = collections.namedtuple(
    'GoogleEnvironment',
    list((
        'client_id',
        'client_secret',
        'redirect_uri',
    )),
    defaults=(
        getenv('GOOGLE_CLIENT_ID'),
        getenv('GOOGLE_CLIENT_SECRET'),
        getenv('GOOGLE_REDIRECT_URI'),
    )
)
EnvGoogle = GoogleEnvironment()

