import boto3
import json
import os
import queue
import threading
import time
import urllib.parse
import urllib.request
from utils import (
    EnvGoogle,
    data_compress, data_decompress,
    dt_from_db, dt_now, dt_to_db, dt_to_json, dt_to_ts,
    expire_after, newer_than,
    token_decrypt, token_encrypt, token_hash,
)

to_compress = queue.SimpleQueue()
was_compressed = queue.SimpleQueue()

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
            except:
                # get new pages from YouTube later
                pass
            else:
                # send the cached data
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


def add_task(q, *args, attempt=None, **kwargs):
    forced = dict(
        attempt=attempt or 0,
        retry_backoff=kwargs.get('retry_backoff'),
    )
    if float(forced['retry_backoff'] or float()) < 1.1:
        forced['retry_backoff'] = 1.1
    task = dict(
        retries=3,
        retry_delay=0.2,
        retry_backoff=2.25,
    )
    task.update(kwargs, **forced)
    return q.put(task)


def run_task(q_in, q_out, func, /):
    empties = 0
    while empties < 9:
        try:
            task = q.get(timeout=0.1)
            empties = 0
            try:
                q_out.put( func(task) )
            except Exception:
                attempt = task.get('attempt') or 0
                retries = task.get('retries') or 0
                retry_delay = task.get('retry_delay') or 0.1
                attempt += 1
                if retries:
                    retries -= 1
                    task['retries'] = retries
                    task['retry_delay'] = retry_delay * task['retry_backoff']
                    time.sleep(retry_delay)
                    add_task(q_in, attempt=attempt, **task)
        except queue.Empty:
            empties += 1


def start_workers(number=None, /):
    if number is None:
        cpus = len(os.sched_getaffinity(0))
        number = (cpus or 4) // 2
    n = int(number)
    while n > 0:
        n -= 1
        threading.Thread(
            daemon=False,
            target=run_task,
            args=(
                to_compress,
                was_compressed,
                compress_page,
            ),
        ).start()


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


def compress_page(task, /):
    # compress anything close to the limit
    if task['size'] > (100 * 1024):
        json_bytes = task['data']
        task['data'] = data_compress(json_bytes)
    return task


def fetch_subs(token, *, user, api_key, cache=None, now_dt=None):
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
    expire_at_ts = dt_to_ts(expire_after(now_dt, hours=12))
    last_updated = dt_to_db(now_dt)
    next_page_token = None

    with subs_table.batch_writer() as pages:
        start_workers()
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
                    add_task(to_compress, dict(
                        api_key=api_key,
                        page_number=page,
                        page_key=f'{api_key},page{page}',
                        data=data,
                        size=len(data),
                        expires=expire_at_ts,
                    ))
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
        # The earlier call likely still has workers available.
        # But, just in case, we don't want to block because
        # they all exited on an empty queue or miss any waiting tasks.
        start_workers(2)
        while True:
            try:
                completed_task = was_compressed.get()
                data = completed_task['data']
                pages.put_item(Item={
                    'api_key': completed_task['page_key'],
                    'last_updated': last_updated,
                    'expire_at_ts': expire_at_ts,
                    'data': data.decode(),
                })
            except queue.Empty:
                break
    return all_subs
