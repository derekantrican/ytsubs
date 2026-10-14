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
    handle_youtube_http_error,
    newer_than,
    response,
    token_decrypt,
    token_hash,
    urlsafe_b64_alphabet,
)

log = getLog(__name__)

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

    # Check if data is cached. Keyed by the Google account token (not api_key)
    # so the cache survives api_key changes.
    now_dt = dt_now()
    cache_key = f"{user['google_user_id_token']},playlists"
    cache = subs_table.get_item(Key={'api_key': f'{cache_key},pages'}).get('Item')
    if cache and 'True' != query_params.get('skip_cache', ''):
        # check that the cache is fresh
        last_updated = dt_from_db(cache['last_updated'])
        if newer_than(last_updated, hours=1, now_dt=now_dt):
            try:
                # this should read the cached pages
                playlists = fetch_playlists(
                    access_token,
                    cache=cache,
                    cache_key=cache_key,
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
            cache=None,
            cache_key=cache_key,
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


def fetch_playlists(token, *, user, cache_key, cache=None, now_dt=None):
    if now_dt is None:
        now_dt = dt_now()

    entries = []

    if cache:
        pages = cache.get('data', 0)
        page = 1
        while page <= pages:
            row = subs_table.get_item(Key={'api_key': f'{cache_key},page{page}'}).get('Item')
            json_str = row.get('data') if row else None
            if json_str:
                if set(json_str.rstrip('=')).issubset(urlsafe_b64_alphabet):
                    json_str = data_decompress(json_str)
                entries.extend(json.loads(json_str))
            page += 1
        log.info(f"{len(entries)} playlists grabbed from the cached pages")
        return entries

    headers = {
        "Authorization": f"Bearer {token}"
    }

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
        refreshed = handle_youtube_http_error(e, user=user, keys_table=keys_table, log=log)
        if isinstance(refreshed, str):
            return fetch_playlists(refreshed, cache=None, cache_key=cache_key, now_dt=now_dt, user=user)
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

    # The user's own created/saved playlists. playlists.list does not document
    # or guarantee any particular default order, so sort explicitly by the
    # playlist's own creation date (newest first) for a predictable result.
    mine_entries = []
    params = {
        "part": "snippet,contentDetails",
        "mine": "true",
        "maxResults": "50",
    }
    base_url = "https://www.googleapis.com/youtube/v3/playlists"
    next_page_token = False
    while next_page_token is not None:
        query = params.copy()
        if next_page_token:
            query['pageToken'] = next_page_token
        full_url = base_url + "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(full_url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            refreshed = handle_youtube_http_error(e, user=user, keys_table=keys_table, log=log)
            if isinstance(refreshed, str):
                return fetch_playlists(refreshed, cache=None, cache_key=cache_key, now_dt=now_dt, user=user)
            return refreshed

        for item in data.get('items', []):
            mine_entries.append({
                'id': item.get('id'),
                'kind': 'mine',
                'title': item.get('snippet', {}).get('title'),
                'publishedAt': item.get('snippet', {}).get('publishedAt'),
                'itemCount': item.get('contentDetails', {}).get('itemCount'),
            })
        next_page_token = data.get('nextPageToken')

    mine_entries.sort(key=lambda entry: entry.get('publishedAt') or '', reverse=True)
    entries.extend(mine_entries)

    expire_at_ts = dt_to_ts(expire_after(now_dt, hours=1))
    last_updated = dt_to_db(now_dt)
    page = 1
    json_data = json.dumps(entries).encode('utf-8')
    if len(json_data) > (200 * 1024):
        # compress anything close to the DynamoDB item size limit
        json_data = data_compress(json_data)
    with subs_table.batch_writer() as pages:
        pages.put_item(Item={
            'api_key': f'{cache_key},page{page}',
            'last_updated': last_updated,
            'expire_at_ts': expire_at_ts,
            'data': json_data.decode(),
        })
        pages.put_item(Item={
            'api_key': f'{cache_key},pages',
            'last_updated': last_updated,
            'expire_at_ts': expire_at_ts,
            'data': page,
        })

    log.info(f"{len(entries)} playlists grabbed from YouTube")
    return entries
