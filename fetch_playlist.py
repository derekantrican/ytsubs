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
    playlist_id = query_params.get('id')

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

    if not playlist_id:
        log.debug('missing playlist id')
        return response(400, dict(error='Missing id'))

    # Like an RSS feed, only the most-recently-added items are returned by default.
    # Raising this costs nothing extra in YouTube quota once a playlist is cached,
    # since the full sorted list is already fetched/cached regardless.
    count = query_params.get('count', 15)
    try:
        count = int(count)
    except (TypeError, ValueError):
        return response(400, dict(error='count must be an integer'))
    if count < 0:
        return response(400, dict(error='count must not be negative'))

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
    cache = subs_table.get_item(Key={'api_key': f'{api_key},playlist,{playlist_id},pages'}).get('Item')
    if cache and 'True' != query_params.get('skip_cache', ''):
        # check that the cache is fresh
        last_updated = dt_from_db(cache['last_updated'])
        if newer_than(last_updated, hours=12, now_dt=now_dt):
            try:
                # this should read the cached pages
                items = fetch_playlist_items(
                    access_token,
                    api_key=api_key,
                    cache=cache,
                    now_dt=now_dt,
                    playlist_id=playlist_id,
                    user=user,
                )
            except Exception:
                log.exception('Failed to read cached playlist items, will refetch')
            else:
                if isinstance(items, dict) and "statusCode" in items:
                    return items
                items = items[:count]
                # send the cached data
                return response(
                    200,
                    {
                        'lastRetrievalDate': dt_to_json(last_updated),
                        'playlistId': playlist_id,
                        'items_count': len(items),
                        'items': items,
                    },
                )

    try:
        max_pages = query_params.get('max_pages')
        per_page = query_params.get('per_page', 50)
        items = fetch_playlist_items(
            access_token,
            api_key=api_key,
            cache=None,
            max_pages=int(max_pages) if max_pages else None,
            now_dt=now_dt,
            per_page=int(per_page) if per_page else None,
            playlist_id=playlist_id,
            user=user,
        )
        if isinstance(items, dict) and "statusCode" in items:
            return items
    except Exception as e:
        msg = 'Error fetching playlist items from YouTube'
        log.exception(msg)
        body = dict(msg=msg + '.')
        try:
            json.dumps(body | dict(exc=str(e)))
        except Exception:
            log.exception('Failed to encode exception details')
        else:
            body.update(dict(exc=str(e)), **body)
        return response(500, body)

    items = items[:count]
    return response(
        200,
        {
            'lastRetrievalDate': dt_to_json(now_dt),
            'playlistId': playlist_id,
            'items_count': len(items),
            'items': items,
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


def sort_by_added_desc(items):
    # snippet.publishedAt is when the video was ADDED to the playlist, distinct
    # from contentDetails.videoPublishedAt (the video's original upload date).
    # These are consistently-formatted ISO 8601 UTC strings, so a plain string
    # sort is a correct proxy for chronological order.
    return sorted(items, key=lambda item: item.get('snippet', {}).get('publishedAt', ''), reverse=True)


def fetch_playlist_items(token, *, user, api_key, playlist_id, cache=None, max_pages=None, now_dt=None, per_page=None):
    if now_dt is None:
        now_dt = dt_now()

    cache_key = f'{api_key},playlist,{playlist_id}'
    all_items = []
    page = 1
    if cache:
        pages = cache.get('data', 0)
        while page <= pages:
            row = subs_table.get_item(Key={'api_key': f'{cache_key},page{page}'}).get('Item')
            json_str = row.get('data') if row else None
            if json_str:
                if set(json_str.rstrip('=')).issubset(urlsafe_b64_alphabet):
                    json_str = data_decompress(json_str)
                data = json.loads(json_str)
                all_items.extend(data.get('items', []))
            page += 1
        log.info(f"{len(all_items)} playlist items grabbed from the cached pages")
        return sort_by_added_desc(all_items)

    headers = {
        "Authorization": f"Bearer {token}"
    }
    params = {
        "part": "snippet,contentDetails",
        "playlistId": playlist_id,
        "maxResults": str(per_page or 50),
    }
    base_url = "https://www.googleapis.com/youtube/v3/playlistItems"
    expire_at_ts = dt_to_ts(expire_after(now_dt, hours=12))
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
                        'api_key': f'{cache_key},page{page}',
                        'last_updated': last_updated,
                        'expire_at_ts': expire_at_ts,
                        'data': data.decode(),
                    })
                    data = json.loads(json_bytes.decode())
                    all_items.extend(data.get('items', []))
                    next_page_token = data.get('nextPageToken')
                    if not next_page_token or (max_pages and page >= max_pages):
                        pages.put_item(Item={
                            'api_key': f'{cache_key},pages',
                            'last_updated': last_updated,
                            'expire_at_ts': expire_at_ts,
                            'data': page,
                        })
                        break
                    page += 1
            except urllib.error.HTTPError as e:
                if 404 == e.code:
                    return response(404, dict(error=f'Playlist not found: {playlist_id}'))
                refresh_token = None
                if 401 == e.code:
                    refresh_token = token_decrypt(user.get('youtube_refresh_token'))
                    if not refresh_token:
                        return response(500, dict(error=NO_REFRESH_TOKEN_MSG))
                    new_token = refresh_access_token(refresh_token, user=user, keys_table=keys_table, log=log)
                    if new_token:
                        return fetch_playlist_items(
                            new_token,
                            api_key=api_key,
                            cache=None,
                            max_pages=max_pages,
                            now_dt=now_dt,
                            per_page=per_page,
                            playlist_id=playlist_id,
                            user=user,
                        )
                    else:
                        return response(403, dict(error=ACCESS_REVOKED_MSG))
                elif 403 == e.code:
                    return response(403, dict(error=ACCESS_DENIED_MSG))
                raise
        item_count = len(all_items)
        log.info(f"{item_count} playlist items grabbed from YouTube")
        return sort_by_added_desc(all_items)
