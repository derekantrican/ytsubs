import boto3
import datetime
import json
import urllib.parse
import urllib.request
from utils import (
    EnvGoogle,
    data_compress, data_decompress,
    dt_from_db, dt_now, dt_to_json,
    expire_after, newer_than,
    token_decrypt, token_encrypt, token_hash,
)

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
    google_user_id = None

    if not api_key:
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
        return {
            "statusCode": 403,
            "body": "Invalid API key"
        }

    access_token = token_decrypt(user.get('youtube_access_token'))
    if not access_token:
        return {
            "statusCode": 401,
            "body": "No YouTube token available for this user"
        }

    # Check if data is cached
    now_dt = dt_now()
    cache = subs_table.get_item(Key={'api_key': f'{api_key},pages'}).get('Item')
    if cache:
        try:
            # this should read the cached pages
            all_subs = fetch_subs(
                access_token,
                api_key=api_key,
                cache=cache,
                now_dt=now_dt,
                user=user,
            )
        except:
            # get new pages from YouTube later
            pass
        else:
            last_updated = dt_from_db(cache['last_updated'])
            if newer_than(last_updated, hours=12, now_dt=now_dt):
                return {
                    "statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "lastRetrievalDate": dt_to_json(last_updated),
                        "subscriptions": all_subs,
                    }),
                }

    try:
        all_subs = fetch_subs(
            access_token,
            api_key=api_key,
            cache=None,
            now_dt=now_dt,
            user=user,
        )
        if isinstance(all_subs, dict) and all_subs.get("statusCode") == 403:
            return all_subs
    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Error fetching from YouTube: {str(e)}"
        }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "lastRetrievalDate": dt_to_json(now_dt),
            "subscriptions": all_subs
        })
    }


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
        print(f"Failed to refresh token: {e}")
    return None


def fetch_subs(token, *, user, api_key, cache=None, now_dt=None):
    if now_dt is None:
        now_dt = dt_now()

    all_subs = []
    page = 1
    if cache:
        pages = cache.get('data', 0)
        while page <= pages:
            row = subs_table.get_item(Key={'api_key': f'{api_key},page{page}'}).get('Item')
            json_str = data_decompress(row.get('data'))
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
    expire_at_ts = round(expire_after(now_dt, hours=12).timestamp())
    last_updated = dt_to_json(now_dt)
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
                    json_bytes = response.read()
                    pages.put_item(Item={
                        'api_key': f'{api_key},page{page}',
                        'last_updated': last_updated,
                        'expire_at_ts': expire_at_ts,
                        'data': data_compress(json_bytes).decode(),
                    })
                    data = json.loads(json_bytes.decode())
                    all_subs.extend(data.get('items', []))
                    next_page_token = data.get('nextPageToken')
                    if not next_page_token:
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
                        return {
                            "statusCode": 500,
                            "body": json.dumps({
                                "error": "The YouTube refresh token was not accessible. Please visit https://ytsubs.app and sign in again."
                            }),
                            "headers": {"Content-Type": "application/json"}
                        }
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
