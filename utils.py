import base64
import boto3
import collections
import datetime
import gzip
import hashlib
import json
import os
import textwrap

_encrypted_token_prefix = '{encrypted}:'


def default_kms_key():
    return getenv('YTSUBS_KMS_KEY', 'alias/ytsubs-token-encrypt-key')


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


def dt_from_db(arg_str, /):
    if arg_str.endswith('Z'):
        arg_str = arg_str[:-1] + '+00:00'
    return datetime.datetime.fromisoformat( arg_str )


def dt_now():
    return datetime.datetime.now(tz=datetime.timezone.utc)


def dt_to_db(arg_dt, /):
    return arg_dt.isoformat(timespec='seconds')


def dt_to_json(arg_dt, /):
    return arg_dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def expire_after(arg_dt, /, *args, **kwargs):
    return arg_dt + datetime.timedelta(*args, **kwargs)


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


def newer_than(arg_dt, /, *args, now_dt=None, **kwargs):
    if now_dt is None:
        now_dt = dt_now()
    return now_dt <= expire_after(arg_dt, *args, **kwargs)


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


def truncate(s, /, limit, *, placeholder=' …'):    
    return textwrap.shorten(s, width=limit, placeholder=placeholder)


def urlsafe_b64decode(s, validate=True):
    b = base64._bytes_from_decode_data(s)
    b = b.translate(base64._urlsafe_decode_translation)
    return base64.b64decode(b, validate=validate)


def urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(s)


def compress_and_encode(data):
    cleaned = [ # Removing some "extra" props from the YouTube data structure to save on DB space (etag, kind, & channelId)
        {
            "id": item.get("id"),
            "snippet": {
                "publishedAt": item["snippet"].get("publishedAt"),
                "title": item["snippet"].get("title"),
                "description": item["snippet"].get("description"),
                "resourceId": item["snippet"].get("resourceId"),
                "thumbnails": item["snippet"].get("thumbnails")
            }
        }
        for item in data
    ]
    json_data = json.dumps(cleaned).encode('utf-8')
    compressed = gzip.compress(json_data)
    return urlsafe_b64encode(compressed).decode('utf-8')


def decode_and_decompress(b64_data):
    compressed = urlsafe_b64decode(b64_data)
    json_data = gzip.decompress(compressed)
    return json.loads(json_data)


def _get_duration_components(duration):
    days = duration.days
    seconds = duration.seconds
    microseconds = duration.microseconds

    minutes = seconds // 60
    seconds %= 60

    hours = minutes // 60
    minutes %= 60

    return days, hours, minutes, seconds, microseconds


def duration_iso_string(duration):
    if duration < datetime.timedelta(0):
        sign = "-"
        duration *= -1
    else:
        sign = ""

    days, hours, minutes, seconds, microseconds = _get_duration_components(duration)
    ms = ".{:06d}".format(microseconds) if microseconds else ""
    return "{}P{}DT{:02d}H{:02d}M{:02d}{}S".format(
        sign, days, hours, minutes, seconds, ms
    )


def is_aware(value):
    return value.utcoffset() is not None

class JSONEncoder(json.JSONEncoder):
    item_separator = ','
    key_separator = ':'

    def default(self, obj):
        try:
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        o = obj
        if isinstance(o, datetime.datetime):
            r = o.isoformat()
            if o.microsecond:
                r = r[:23] + r[26:]
            if r.endswith("+00:00"):
                r = r.removesuffix("+00:00") + "Z"
            return r
        elif isinstance(o, datetime.date):
            return o.isoformat()
        elif isinstance(o, datetime.time):
            if is_aware(o):
                raise ValueError("JSON can't represent timezone-aware times.")
            r = o.isoformat()
            if o.microsecond:
                r = r[:12]
            return r
        elif isinstance(o, datetime.timedelta):
            return duration_iso_string(o)
        return super().default(obj)


def json_serial(obj):
    json_encoder = JSONEncoder()
    return json_encoder.default(obj)


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

