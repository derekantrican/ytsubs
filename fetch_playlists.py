import json
import urllib.parse
import urllib.request

import boto3

from utils import (
    data_compress,
    data_decompress,
    dt_from_db,
    dt_now,
    dt_to_db,
    dt_to_json,
    dt_to_ts,
    expire_after,
    getLog,
    newer_than,
    refresh_access_token,
    token_decrypt,
    token_hash,
    urlsafe_b64_alphabet,
)

log = getLog(__name__)

dynamodb = boto3.resource('dynamodb')
subs_table = dynamodb.Table('ytsubs_subscriptions_cache')
keys_table = dynamodb.Table('ytsubs_api_keys')

NO_REFRESH_TOKEN_MSG = (
    "The YouTube refresh token was not accessible. "
    "Please visit https://ytsubs.app and sign in again."
)
ACCESS_REVOKED_MSG = (
    "Access to YouTube was revoked. "
    "Please visit https://ytsubs.app and sign in again."
)
ACCESS_DENIED_MSG = (
    "Access to YouTube was denied. "
    "Please visit https://ytsubs.app and sign in again, "
    "ensuring you grant YouTube access."
)


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

    # Check if data is cached
    now_dt = dt_now()
    cache = subs_table.get_item(Key={'api_key': f'{api_key},playlists,pages'}).get('Item')
    if cache and 'True' != query_params.get('skip_cache', ''):
        # check that the cache is fresh
        last_updated = dt_from_db(cache['last_updated'])
        if newer_than(last_updated, hours=12, now_dt=now_dt):
            try:
                # this should read the cached pages
                playlists = fetch_playlists(
                    access_token,
                    api_key=api_key,
                    cache=cache,
                    now_dt=now_dt,
                    user=user,
                )
            except Exception:
                log.exception('Failed to read cached playlists, will refetch')
            else:
                if isinstance(playlists, dict) and "statusCode" in playlists:
                    return playlists
                # send the cached data
                return response(
                    200,
                    {
                        'lastRetrievalDate': dt_to_json(last_updated),
                        'playlists_count': len(playlists),
                        'playlists': playlists,
                    },
                )

    try:
        playlists = fetch_playlists(
            access_token,
            api_key=api_key,
            cache=None,
            now_dt=now_dt,
            user=user,
        )
        if isinstance(playlists, dict) and "statusCode" in playlists:
            return playlists
    except Exception as e:
        msg = 'Error fetching playlists from YouTube'
        log.exception(msg)
        body = dict(msg=msg + '.')
        try:
            json.dumps(body | dict(exc=str(e)))
        except Exception:
            log.exception('Failed to encode exception details')
        else:
            body.update(dict(exc=str(e)), **body)
        return response(500, body)

    return response(
        200,
        {
            'lastRetrievalDate': dt_to_json(now_dt),
            'playlists_count': len(playlists),
            'playlists': playlists,
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
        msg = 'An exception occurred while generating the response'
        log.exception(msg)
        return response(500, {'msg': msg + '.', 'exc': str(e)})


def fetch_playlists(token, *, user, api_key, cache=None, now_dt=None):
    if now_dt is None:
        now_dt = dt_now()

    cache_key = f'{api_key},playlists'
    if cache:
        row = subs_table.get_item(Key={'api_key': f'{cache_key},page1'}).get('Item')
        json_str = row.get('data') if row else None
        entries = []
        if json_str:
            if set(json_str.rstrip('=')).issubset(urlsafe_b64_alphabet):
                json_str = data_decompress(json_str)
            entries = json.loads(json_str)
        log.info(f"{len(entries)} playlists grabbed from the cache")
        return entries

    headers = {
        "Authorization": f"Bearer {token}"
    }
    entries = []

    # "Liked videos" is a special auto-playlist that playlists.list(mine=true)
    # does not return; its id must be resolved via the channel resource.
    channel_url = "https://www.googleapis.com/youtube/v3/channels?" + urllib.parse.urlencode({
        "part": "contentDetails",
        "mine": "true",
    })
    try:
        req = urllib.request.Request(channel_url, headers=headers)
        with urllib.request.urlopen(req) as resp:
            channel_data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        refreshed = handle_youtube_http_error(e, user=user)
        if isinstance(refreshed, str):
            return fetch_playlists(refreshed, api_key=api_key, cache=None, now_dt=now_dt, user=user)
        return refreshed

    channel_items = channel_data.get('items', [])
    likes_id = None
    if channel_items:
        related = channel_items[0].get('contentDetails', {}).get('relatedPlaylists', {})
        likes_id = related.get('likes')
    if likes_id:
        entries.append({
            'id': likes_id,
            'kind': 'liked',
            'title': 'Liked videos',
        })

    # the user's own created/saved playlists
    params = {
        "part": "snippet,contentDetails",
        "mine": "true",
        "maxResults": "50",
    }
    base_url = "https://www.googleapis.com/youtube/v3/playlists"
    next_page_token = None
    while True:
        query = params.copy()
        if next_page_token:
            query['pageToken'] = next_page_token
        full_url = base_url + "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(full_url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            refreshed = handle_youtube_http_error(e, user=user)
            if isinstance(refreshed, str):
                return fetch_playlists(refreshed, api_key=api_key, cache=None, now_dt=now_dt, user=user)
            return refreshed

        for item in data.get('items', []):
            entries.append({
                'id': item.get('id'),
                'kind': 'mine',
                'title': item.get('snippet', {}).get('title'),
                'itemCount': item.get('contentDetails', {}).get('itemCount'),
            })
        next_page_token = data.get('nextPageToken')
        if not next_page_token:
            break

    expire_at_ts = dt_to_ts(expire_after(now_dt, hours=12))
    last_updated = dt_to_db(now_dt)
    json_data = json.dumps(entries).encode('utf-8')
    if len(json_data) > (200 * 1024):
        # compress anything close to the DynamoDB item size limit
        json_data = data_compress(json_data)
    subs_table.put_item(Item={
        'api_key': f'{cache_key},page1',
        'last_updated': last_updated,
        'expire_at_ts': expire_at_ts,
        'data': json_data.decode(),
    })

    log.info(f"{len(entries)} playlists grabbed from YouTube")
    return entries


def handle_youtube_http_error(e, /, *, user):
    """
    Handles a 401/403 from the YouTube API.
    Returns a fresh access token (str) if a refresh succeeded and the caller
    should retry, or a response dict (with statusCode) to return as-is.
    """
    if 401 == e.code:
        refresh_token = token_decrypt(user.get('youtube_refresh_token'))
        if not refresh_token:
            return response(500, dict(error=NO_REFRESH_TOKEN_MSG))
        new_token = refresh_access_token(refresh_token, user=user, keys_table=keys_table, log=log)
        if new_token:
            return new_token
        return response(403, dict(error=ACCESS_REVOKED_MSG))
    elif 403 == e.code:
        return response(403, dict(error=ACCESS_DENIED_MSG))
    raise e
