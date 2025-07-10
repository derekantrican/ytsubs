import boto3
import datetime
import json
import logging
import urllib.parse
import urllib.request
from utils import (
    EnvGoogle,
    compress_and_encode, decode_and_decompress, getenv,
    token_decrypt, token_encrypt, token_hash, truncate,
)

# Configure logging to sys.stderr
log = logging.getLogger(__name__)
_handler = logging.StreamHandler()
_handler.setLevel(logging.DEBUG)
log.addHandler(_handler)
del _handler
try:
    # set LOG_LEVEL to the minimum level that you wish to see
    log.setLevel(getenv('LOG_LEVEL', logging.DEBUG))
except ValueError:
    log.setLevel(logging.DEBUG)

dynamodb = boto3.resource('dynamodb')
subs_table = dynamodb.Table('ytsubs_subscriptions_cache')
keys_table = dynamodb.Table('ytsubs_api_keys')

def lambda_handler(event, context):
    query_params = event.get('queryStringParameters') or {}
    api_key = query_params.get('api_key')

    # Calculate the google_user_id_token if google_user_id was provided
    google_user_id_token = query_params.get('google_user_id_token')
    google_user_id = query_params.get('google_user_id')
    if google_user_id:
        google_user_id_token = token_hash(google_user_id)
        log.debug(f'{google_user_id_token=}')
    google_user_id = None

    def now():
        return datetime.datetime.now(tz=datetime.timezone.utc)

    def datetime_from_db(arg_str, /):
        if arg_str.endswith('Z'):
            arg_str = arg_str[:-1] + '+00:00'
        return datetime.datetime.fromisoformat( arg_str )

    def datetime_to_db(arg_dt, /):
        return arg_dt.isoformat(timespec='seconds')

    def datetime_to_json(arg_dt, /):
        return arg_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

    def newer_than(arg_dt, /, *args, **kwargs):
        return arg_dt > (now() - datetime.timedelta(*args, **kwargs))

    if not api_key:
        log.debug('missing api_key')
        return {
            "statusCode": 401,
            "body": "Missing api_key"
        }

    # Look up the user by api_key (or by google_user_id_token if a user cannot be found by api_key)
    user = keys_table.get_item(Key={'api_key': api_key}).get('Item')
    invalid = (
        not user or
        (
            google_user_id_token and
            google_user_id_token != user.get('google_user_id_token')
        )
    )
    if invalid:
        log.debug(f'invalid api_key: {api_key}')
        return {
            "statusCode": 403,
            "body": "Invalid API key"
        }

    # Check if data is cached
    now_dt = now()
    log.debug(f'{now_dt=}')
    log.debug('reading from cache table')
    cache = subs_table.get_item(Key={'api_key': api_key}).get('Item')
    if cache and 'True' != query_params.get('skip_cache', ''):
        log.debug('has a cache entry')
        last_updated = datetime_from_db(cache['last_updated'])
        if newer_than(last_updated, hours=12):
            log.debug('cache entry was fresh')
            # Data is compressed & encoded to save space
            log.debug(f"stored_size={len(str( cache['data'] ))}")
            all_subs = decode_and_decompress(cache['data'])
            subs_count = len(all_subs)
            log.debug(f'{subs_count=}')
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "lastRetrievalDate": datetime_to_json(last_updated),
                    'subscriptions_count': subs_count,
                    "subscriptions": all_subs,
                })
            }

    access_token = token_decrypt(user.get('youtube_access_token'))
    if not access_token:
        log.debug('no access_token available')
        return {
            "statusCode": 401,
            "body": "No YouTube token available for this user"
        }

    def fetch_subs(token):
        all_subs = []
        page = 1
        cache = subs_table.get_item(Key={'api_key': f'{api_key},pages'}).get('Item')
        if cache:
            pages = cache.get('data', 0)
            while page <= pages:
                row = subs_table.get_item(Key={'api_key': f'{api_key},page{page}'}).get('Item')
                json_str = row.get('data')
                if json_str:
                    data = json.loads(json_str)
                    all_subs.extend(data.get('items', []))
                page += 1
            return all_subs
        headers = {
            "Authorization": f"Bearer {token}"
        }
        params = {
            "part": "snippet",
            "mine": "true",
            "maxResults": "50"
        }
        base_url = "https://www.googleapis.com/youtube/v3/subscriptions"
        last_updated = datetime_to_json(now_dt)
        next_page_token = None

        with subs_table.batch_writer() as pages:
          while True:
            query = params.copy()
            if next_page_token:
                query['pageToken'] = next_page_token
            full_url = base_url + "?" + urllib.parse.urlencode(query)
            req = urllib.request.Request(full_url, headers=headers)
            try:
                with urllib.request.urlopen(req) as response:
                    json_str = response.read().decode()
                    pages.put_item(Item={
                        'api_key': f'{api_key},page{page}',
                        'last_updated': last_updated,
                        'expire_at_ts': round((now_dt + datetime.timedelta(hours=12)).timestamp()),
                        'data': json_str,
                    })
                    data = json.loads(json_str)
                    all_subs.extend(data.get('items', []))
                    next_page_token = data.get('nextPageToken')
                    if not next_page_token:
                        pages.put_item(Item={
                            'api_key': f'{api_key},pages',
                            'last_updated': last_updated,
                            'expire_at_ts': round((now_dt + datetime.timedelta(hours=12)).timestamp()),
                            'data': page,
                        })
                        break
                    page += 1
            except urllib.error.HTTPError as e:
                refresh_token = None
                if 401 == e.code:
                    refresh_token = token_decrypt(user.get('youtube_refresh_token'))
                    if not refresh_token:
                        return {
                            "statusCode": 500,
                            "body": json.dumps({
                                "error": "The YouTube refresh token was not accessible. Please visit https://ytsubs.app and sign in again."
                            }),
                            "headers": {"Content-Type": "application/json"}
                        }
                    new_token = refresh_access_token(refresh_token)
                    if new_token:
                        return fetch_subs(new_token)
                    else:
                        return {
                            "statusCode": 403,
                            "body": json.dumps({
                                "error": "Access to YouTube was revoked. Please visit https://ytsubs.app and sign in again."
                            }),
                            "headers": {"Content-Type": "application/json"}
                        }
                elif 403 == e.code:
                    return {
                        "statusCode": 403,
                        "headers": {"Content-Type": "application/json"},
                        "body": json.dumps({
                            "error": "Access to YouTube was denied. Please visit https://ytsubs.app and sign in again, ensuring you grant YouTube access."
                        })
                    }
                raise e
        return all_subs

    def refresh_access_token(refresh_token):
        token_url = "https://oauth2.googleapis.com/token"
        data = urllib.parse.urlencode({
            "client_id": EnvGoogle.client_id,
            "client_secret": EnvGoogle.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }).encode()

        req = urllib.request.Request(token_url, data=data)
        try:
            with urllib.request.urlopen(req) as resp:
                token_data = json.loads(resp.read().decode())
                new_token = token_data.get("access_token")
                if new_token:
                    user['youtube_access_token'] = token_encrypt(new_token)
                    keys_table.put_item(Item=user)
                    return new_token
        except Exception as e:
            log.exception(e)
            log.error('Failed to refresh token')
        return None

    if 'False' == query_params.get('fetch_subs', ''):
        return {
            "statusCode": 200,
            "body": "made it to fetching subscriptions",
        }
    try:
        log.debug('fetching subscriptions')
        all_subs = fetch_subs(access_token)
        if isinstance(all_subs, dict) and "statusCode" in all_subs:
            log.debug("returned {all_subs.get('statusCode', '???')}")
            return all_subs
    except Exception as e:
        log.exception(e)
        body = json.dumps({
            'msg': 'Error fetching from YouTube.',
        })
        try:
            body = json.dumps({
                'msg': 'Error fetching from YouTube.',
                'exc': str(e),
            })
        except Exception as ee:
            log.exception(ee)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": body,
        }

    if 'False1' == query_params.get('save_cache', ''):
        return {
            "statusCode": 200,
            "body": "made it past fetching subscriptions",
        }
    # Save new data to cache
    subs_count = '?'
    try:
        log.debug(f'all_subs_type={type(all_subs)}')
        subs_count = len(all_subs)
        log.info(f"{subs_count} subscriptions grabbed")
    except Exception as e:
        subs_count = f'type={type(all_subs)} {e=}'
    if 'False2' == query_params.get('save_cache', ''):
        return {
            "statusCode": 200,
            "body": "made it past counting subscriptions",
        }
    if 'False3' == query_params.get('save_cache', ''):
        return {
            "statusCode": 200,
            "body": f"{subs_count} subscriptions grabbed",
        }
        #raise Exception(f'save_cache: {subs_count=}')
    try:
        log.debug('storing cached subscriptions')
        if 'False4' == query_params.get('save_cache', ''):
            return {
                "statusCode": 200,
                "body": "made it to cached subscriptions",
            }
        cached_subs = [
            {
                k: {
                    kk: truncate(vv, 256)
                    if kk == 'description' else vv
                    for kk,vv in v.items()
                }
                if 'snippet' == k else v
                for k,v in s.items()
            }
            for s in all_subs
        ]
        if 'False5' == query_params.get('save_cache', ''):
            return {
                "statusCode": 200,
                "body": "made it past cached subscriptions",
            }
        # Data is compressed & encoded to save space
        encoded_data = compress_and_encode(cached_subs)
        if 'False6' == query_params.get('save_cache', ''):
            return {
                "statusCode": 200,
                "body": "made it past encoded subscriptions",
            }
        subs_table.put_item(Item={
            "api_key": api_key,
            "last_updated": datetime_to_json(now_dt),
            "data": encoded_data,
        })
        if 'False7' == query_params.get('save_cache', ''):
            return {
                "statusCode": 200,
                "body": "made it past put encoded subscriptions",
            }
    except Exception as e:
        log.exception(e)
        log.debug('returning 500 and JSON')
        body = json.dumps({
            'msg': 'Error caching subscriptions.',
        })
        if 'False8' == query_params.get('save_cache', ''):
            return {
                "statusCode": 200,
                "body": "made it to try block in exception",
            }
        try:
            body = json.dumps({
                'msg': 'Error caching subscriptions.',
                'subscriptions_count': subs_count,
                'exc': str(e),
            })
        except Exception as ee:
            log.exception(ee)
        if 'False9' == query_params.get('save_cache', ''):
            return {
                "statusCode": 200,
                "body": "made it past try block in exception",
            }
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": body,
        }

    log.debug('returning 200 and JSON')
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "lastRetrievalDate": datetime_to_json(now_dt),
            'subscriptions_count': subs_count,
            "subscriptions": all_subs,
        })
    }
