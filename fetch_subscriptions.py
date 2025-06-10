import json
import datetime
import urllib.request
import urllib.parse
import boto3

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
    print(f"Query: api_key={api_key}, google_user_id={google_user_id}")
    print(f"Fetched user: {json.dumps(user)}")

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
                "body": cache['data'],
                "headers": {"Content-Type": "application/json"}
            }

    # Fetch new data from YouTube
    access_token = user.get('youtube_access_token')
    if not access_token:
        return {
            "statusCode": 401,
            "body": "No YouTube token available for this user"
        }

    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    params = {
        "part": "snippet",
        "mine": "true",
        "maxResults": "50"
    }
    base_url = "https://www.googleapis.com/youtube/v3/subscriptions"
    all_subs = []
    next_page_token = None

    try:
        while True:
            query = params.copy()
            if next_page_token:
                query['pageToken'] = next_page_token
            full_url = base_url + "?" + urllib.parse.urlencode(query)
            req = urllib.request.Request(full_url, headers=headers)
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                all_subs.extend(data.get('items', []))
                next_page_token = data.get('nextPageToken')
                if not next_page_token:
                    break
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
        "body": response_data,
        "headers": {"Content-Type": "application/json"}
    }
