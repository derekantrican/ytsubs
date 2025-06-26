import base64
import boto3
import datetime
import os


def default_kms_key():
    return 'alias/ytsubs-token-encrypt-key'


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


def dt_to_ts(arg_dt, /):
    dt = arg_dt
    if arg_dt.utcoffset() is None:
        dt = arg_dt.astimezone(tz=datetime.timezone.utc)
    return dt.timestamp()


def dynamodb_check_ttl(table_name):
    dynamodb = boto3.client('dynamodb')
    expected_responses = frozenset((
        'DISABLED',
        'ENABLED',
    ))
    response = dynamodb.describe_time_to_live(TableName=table_name)
    assert response in expected_responses, f'dynamodb_check_ttl: unexpected response: {response}'
    return 'ENABLED' == response
    
def dynamodb_enable_ttl(table_name, ttl_attribute_name):
    """
    Enables TTL on DynamoDB table for a given attribute name
        on success, returns a status code of 200
        on error, throws an exception

    :param table_name: Name of the DynamoDB table
    :param ttl_attribute_name: The name of the TTL attribute being provided to the table.
    """
    dynamodb = boto3.client('dynamodb')

    # Enable TTL on an existing DynamoDB table
    response = dynamodb.update_time_to_live(
        TableName=table_name,
        TimeToLiveSpecification={
            'Enabled': True,
            'AttributeName': ttl_attribute_name
        }
    )

    # In the returned response, check for a successful status code.
    if 200 == response['ResponseMetadata']['HTTPStatusCode']:
        return True
    else:
        raise Exception(f"Failed to enable TTL, status code {response['ResponseMetadata']['HTTPStatusCode']}")


def expire_after(arg_dt, /, *args, **kwargs):
    return dt_now() + datetime.timedelta(*args, **kwargs)

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


def newer_than(arg_dt, /, *args, **kwargs):
    return arg_dt > (dt_now() - datetime.timedelta(*args, **kwargs))

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
    if key is None:
        key = default_kms_key()
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

