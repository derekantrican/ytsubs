import json
import datetime
import urllib.request
import urllib.parse
import boto3
import os

dynamodb = boto3.resource('dynamodb')
subs_table = dynamodb.Table('ytsubs_subscriptions_cache')
keys_table = dynamodb.Table('ytsubs_api_keys')

def lambda_handler(event, context):
    query_params = event.get('queryStringParameters') or {}
    api_key = query_params.get('api_key')
    google_user_id = query_params.get('google_user_id')

    if not api_key or not google_user_id:
        return {
            "statusCode": 401,
            "body": "Missing api_key or google_user_id"
        }

    # Look up the user by api_key and validate google_user_id
    user = keys_table.get_item(Key={'api_key': api_key}).get('Item')
    if not user or user.get('google_user_id') != google_user_id:
        return {
            "statusCode": 403,
            "body": "Invalid API key or google_user_id"
        }

    # Check if data is cached
    now = datetime.datetime.utcnow()
    cache = subs_table.get_item(Key={'api_key': api_key}).get('Item')
    if cache:
        last_updated = datetime.datetime.fromisoformat(cache['last_updated'])
        if (now - last_updated).total_seconds() < 43200:  # 12 hours
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "lastRetrievalDate": last_updated.isoformat(),
                    "subscriptions": json.loads(cache['data'])
                })
            }

    access_token = user.get('youtube_access_token')
    refresh_token = user.get('youtube_refresh_token')
    if not access_token:
        return {
            "statusCode": 401,
            "body": "No YouTube token available for this user"
        }

    def fetch_subs(token):
        headers = {
            "Authorization": f"Bearer {token}"
        }
        params = {
            "part": "snippet",
            "mine": "true",
            "maxResults": "50"
        }
        base_url = "https://www.googleapis.com/youtube/v3/subscriptions"
        all_subs = []
        next_page_token = None

        while True:
            query = params.copy()
            if next_page_token:
                query['pageToken'] = next_page_token
            full_url = base_url + "?" + urllib.parse.urlencode(query)
            req = urllib.request.Request(full_url, headers=headers)
            try:
                with urllib.request.urlopen(req) as response:
                    data = json.loads(response.read().decode())
                    all_subs.extend(data.get('items', []))
                    next_page_token = data.get('nextPageToken')
                    if not next_page_token:
                        break
            except urllib.error.HTTPError as e:
                if e.code == 401 and refresh_token:
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
                raise e
        return all_subs

    def refresh_access_token(refresh_token):
        client_id = os.environ['GOOGLE_CLIENT_ID']
        client_secret = os.environ['GOOGLE_CLIENT_SECRET']
        token_url = "https://oauth2.googleapis.com/token"
        data = urllib.parse.urlencode({
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }).encode()

        req = urllib.request.Request(token_url, data=data)
        try:
            with urllib.request.urlopen(req) as resp:
                token_data = json.loads(resp.read().decode())
                new_token = token_data.get("access_token")
                if new_token:
                    user['youtube_access_token'] = new_token
                    keys_table.put_item(Item=user)
                    return new_token
        except Exception as e:
            print(f"Failed to refresh token: {e}")
        return None

    try:
        all_subs = fetch_subs(access_token)
        if isinstance(all_subs, dict) and all_subs.get("statusCode") == 403:
            return all_subs
    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Error fetching from YouTube: {str(e)}"
        }

    # Save new data to cache
    response_data = json.dumps(all_subs)
    subs_table.put_item(Item={
        "api_key": api_key,
        "last_updated": now.isoformat(),
        "data": response_data
    })

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "lastRetrievalDate": now.isoformat(),
            "subscriptions": all_subs
        })
    }
