import boto3
import json
import logging
import urllib.parse
import urllib.request
from utils import (
    EnvGoogle,
    data_compress, data_decompress, # noqa: F401
    dt_from_db, dt_now, dt_to_db, dt_to_json,
    expire_after, newer_than,
    token_decrypt, token_encrypt, token_hash,
    compress_and_encode, decode_and_decompress, getenv, truncate, # noqa: F401
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

    if not api_key:
        log.debug('missing api_key')
        return response(401, dict(error='Missing api_key'))

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
        return response(403, dict(error='Invalid API key'))

    access_token = token_decrypt(user.get('youtube_access_token'))
    if not access_token:
        log.debug('no access_token available')
        msg = 'No YouTube token available for this user'
        return response(401, dict(error=msg))

    try:
        client = boto3.client('dynamodb')
        attr_name = 'expire_at_ts'
        table_name = 'ytsubs_subscriptions_cache'
        users = frozenset((
            '10611d9653d2de37cd6d5c889d28830c9e582e178996660cf78e917fe6684b04',
        ))
        if 'Q' == query_params.get('cache_ttl'):
            return response(
                200,
                dict(user=user.get('google_user_id_token')) | client.describe_time_to_live(TableName=table_name),
            )
        elif 'LT' == query_params.get('cache_ttl'):
            return response(
                200,
                client.list_tables(),
            )
        elif 'DL' == query_params.get('cache_ttl'):
            return response(
                200,
                client.describe_limits(),
            )
        elif 'DT' == query_params.get('cache_ttl'):
            if user.get('google_user_id_token') not in users:
                return response(403, dict(error='Not Authorized'))
            results = dict()
            results['ytsubs_api_keys'] = client.describe_table(
                TableName='ytsubs_api_keys'
            )
            results[table_name] = client.describe_table(
                TableName=table_name
            )
            return response(200, results)
        elif (v := query_params.get('cache_ttl')) in ('C', 'E',):
            if user.get('google_user_id_token') not in users:
                return response(403, dict(error='Not Authorized'))
            return response(
                200,
                client.update_time_to_live(
                    TableName=table_name,
                    TimeToLiveSpecification={
                        'Enabled': True if 'E' == v else False,
                        'AttributeName': attr_name,
                    },
                )
            )
    except Exception as e:
        return response(500, dict(msg='An exception occurred.', exc=str(e)))

    # Check if data is cached
    now_dt = dt_now()
    cache = subs_table.get_item(Key={'api_key': f'{api_key},pages'}).get('Item')
    if cache and 'True' != query_params.get('skip_cache', ''):
        # check that the cache is fresh
        last_updated = dt_from_db(cache['last_updated'])
        if newer_than(last_updated, hours=12, now_dt=now_dt):
            try:
                # this should read the cached pages
                all_subs = fetch_subs(
                    access_token,
                    api_key=api_key,
                    cache=cache,
                    now_dt=now_dt,
                    user=user,
                )
            except Exception as e:
                log.exception(e)
                # get new pages from YouTube later
                pass
            else:
                # send the cached data
                return response(
                    200,
                    {
                        'lastRetrievalDate': dt_to_json(last_updated),
                        'subscriptions_count': len(all_subs),
                        'subscriptions': all_subs,
                    },
                )

    try:
        max_pages = query_params.get('max_pages')
        per_page = query_params.get('per_page', 50)
        all_subs = fetch_subs(
            access_token,
            api_key=api_key,
            cache=None,
            max_pages=int(max_pages) if max_pages else None,
            now_dt=now_dt,
            per_page=int(per_page) if per_page else None,
            user=user,
        )
        log.debug(f'all_subs_type={type(all_subs)}')
        if isinstance(all_subs, dict) and "statusCode" in all_subs:
            log.debug("returned {all_subs.get('statusCode', '???')}")
            return all_subs
    except Exception as e:
        log.exception(e)
        body = dict(msg='Error fetching from YouTube.')
        try:
            json.dumps(body | dict(exc=str(e)))
        except Exception as ee:
            log.exception(ee)
        else:
            body.update(dict(exc=str(e)), **body)
        return response(500, body)

    return response(
        200,
        {
            'lastRetrievalDate': dt_to_json(now_dt),
            'subscriptions_count': len(all_subs),
            'subscriptions': all_subs,
        },
    )

def response(status, arg_dict, /):
    try:
        return {
            'statusCode': int(status),
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(arg_dict),
        }
    except Exception as e:
        log.exception(e)
        msg = 'An exception occurred while generating the response.'
        return response(500, {'msg': msg, 'exc': str(e)})


def refresh_access_token(refresh_token, *, user):
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
        log.error("Failed to refresh token")
    return None


def fetch_subs(token, *, user, api_key, cache=None, max_pages=None, now_dt=None, per_page=None):
    if now_dt is None:
        now_dt = dt_now()

    all_subs = []
    page = 1
    if cache:
        pages = cache.get('data', 0)
        while page <= pages:
            row = subs_table.get_item(Key={'api_key': f'{api_key},page{page}'}).get('Item')
            json_str = row.get('data')
            if json_str:
                if '"' not in json_str:
                    json_str = data_decompress(json_str)
                data = json.loads(json_str)
                all_subs.extend(data.get('items', []))
            page += 1
        subs_count = len(all_subs)
        log.info(f"{subs_count} subscriptions grabbed from the cached pages")
        return all_subs

    headers = {
        "Authorization": f"Bearer {token}"
    }
    params = {
        "part": "snippet",
        "mine": "true",
        "maxResults": str(per_page or 50),
    }
    base_url = "https://www.googleapis.com/youtube/v3/subscriptions"
    expire_at_ts = round(expire_after(now_dt, hours=12).timestamp())
    last_updated = dt_to_db(now_dt)
    next_page_token = None

    with subs_table.batch_writer() as pages:
        while True:
            query = params.copy()
            if next_page_token:
                query['pageToken'] = next_page_token
            full_url = base_url + "?" + urllib.parse.urlencode(query)
            req = urllib.request.Request(full_url, headers=headers)
            try:
                with urllib.request.urlopen(req) as response_obj:
                    json_bytes = response_obj.read()
                    data = json_bytes
                    if len(data) > (200 * 1024):
                        # compress anything close to the limit
                        data = data_compress(json_bytes)
                    pages.put_item(Item={
                        'api_key': f'{api_key},page{page}',
                        'last_updated': last_updated,
                        'expire_at_ts': expire_at_ts,
                        'data': data.decode(),
                    })
                    data = json.loads(json_bytes.decode())
                    all_subs.extend(data.get('items', []))
                    next_page_token = data.get('nextPageToken')
                    if not next_page_token or (max_pages and page >= max_pages):
                        pages.put_item(Item={
                            'api_key': f'{api_key},pages',
                            'last_updated': last_updated,
                            'expire_at_ts': expire_at_ts,
                            'data': page,
                        })
                        break
                    page += 1
            except urllib.error.HTTPError as e:
                refresh_token = None
                if 401 == e.code:
                    refresh_token = token_decrypt(user.get('youtube_refresh_token'))
                    if not refresh_token:
                        msg = (
                            "The YouTube refresh token was not accessible. "
                            "Please visit https://ytsubs.app and sign in again."
                        )
                        return response(500, dict(error=msg))

                    new_token = refresh_access_token(refresh_token, user=user)
                    if new_token:
                        return fetch_subs(
                            new_token,
                            api_key=api_key,
                            cache=None,
                            now_dt=now_dt,
                            user=user,
                        )
                    else:
                        msg = (
                            "Access to YouTube was revoked. "
                            "Please visit https://ytsubs.app and sign in again."
                        )
                        return response(403, dict(error=msg))
                elif 403 == e.code:
                    msg = (
                        "Access to YouTube was denied. "
                        "Please visit https://ytsubs.app and sign in again, "
                        "ensuring you grant YouTube access."
                    )
                    return response(403, dict(error=msg))
                raise e
        subs_count = len(all_subs)
        if per_page is not None and per_page == 11:
            return response(
                200,
                dict(
                    page=page,
                    subs_count=subs_count,
                ),
            )
        #subs_count = len(all_subs)
        log.info(f"{subs_count} subscriptions grabbed from YouTube")
        return all_subs
