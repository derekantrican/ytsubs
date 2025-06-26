import base64
import boto3
import collections
import os


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
    arg_bytes = urlsafe_b64decode(arg_str)
    kms = boto3.client('kms')
    if key is None:
        response = kms.decrypt(CiphertextBlob=arg_bytes)
    else:
        response = kms.decrypt(CiphertextBlob=arg_bytes, KeyId=key)
    result_bytes = response['Plaintext']
    result_str = result_bytes.decode()
    return result_str


def token_encrypt(arg_str, /, *, key=None):
    assert key is not None, 'token_encrypt requires a KMS key identifier'
    arg_bytes = arg_str.encode() if isinstance(arg_str, str) else arg_str
    kms = boto3.client('kms')
    response = kms.encrypt(KeyId=key, Plaintext=arg_bytes)
    encrypted_bytes = response['CiphertextBlob']
    result_bytes = urlsafe_b64encode(encrypted_bytes)
    result_str = result_bytes.decode()
    return result_str


def urlsafe_b64decode(s, validate=True):
    b = base64._bytes_from_decode_data(s)
    b = b.translate(base64._urlsafe_decode_translation)
    return base64.b64decode(s, validate=validate)


def urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(s)

