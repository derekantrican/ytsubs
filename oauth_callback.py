import html
import json
import secrets
import urllib.parse
import urllib.request

import boto3

from utils import EnvGoogle, getLog, token_encrypt, token_hash

log = getLog(__name__)

dynamodb = boto3.resource('dynamodb')
keys_table = dynamodb.Table('ytsubs_api_keys')
mapping_table = dynamodb.Table('ytsubs_user_to_api')
subs_table = dynamodb.Table('ytsubs_subscriptions_cache')

def lambda_handler(event, context):
    params = event.get('queryStringParameters') or {}
    code = params.get('code')
    purge = 'purge' == params.get('state')
    if not code:
        return {
            "statusCode": 400,
            "body": "Missing authorization code"
        }

    # Exchange authorization code for tokens
    data = urllib.parse.urlencode({
        "code": code,
        "client_id": EnvGoogle.client_id,
        "client_secret": EnvGoogle.client_secret,
        "redirect_uri": EnvGoogle.redirect_uri,
        "grant_type": "authorization_code"
    }).encode()

    try:
        req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data)
        with urllib.request.urlopen(req) as resp:
            token_data = json.loads(resp.read().decode())
            granted_scopes = token_data.get("scope", "")
            required_scope = "https://www.googleapis.com/auth/youtube.readonly"

            if not purge and required_scope not in granted_scopes.split():
                return {
                    "statusCode": 400,
                    "headers": {"Content-Type": "text/html"},
                    "body": """
                    <html>
                        <body style="color: white; background-color: #121212; text-align: center; font-family: sans-serif; padding: 2em;">
                            <h1>Authorization Incomplete</h1>
                            <p>You did not grant access to your YouTube subscriptions.</p>
                            <p>Please go back and ensure you check the box for YouTube access during sign-in.</p>
                        </body>
                    </html>
                    """
                }
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode()
        print(f"Error exchanging token: {e} - {error_msg}")
        
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "text/html"},
            "body": '''
            <html>
            <head>
                <link rel="stylesheet" href="https://static.ytsubs.app/callback_expired.css" blocking="render" />
            </head>
            <body>
                <h1>OAuth Link Expired</h1>
                <p>Your authorization link has expired or is invalid.</p>
                <p>Please <a href="https://ytsubs.app">go back to the homepage</a> and try again.</p>
            </body>
            </html>
            '''
        }

    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')

    if not access_token:
        return {
            "statusCode": 500,
            "body": "Access token not received"
        }

    # Get user info from Google
    headers = { "Authorization": f"Bearer {access_token}" }
    try:
        req = urllib.request.Request("https://www.googleapis.com/oauth2/v2/userinfo", headers=headers)
        with urllib.request.urlopen(req) as resp:
            profile = json.loads(resp.read().decode())
    except Exception as e:  # noqa: BLE001 - top-level handler must convert any failure into an HTTP response
        return {
            "statusCode": 500,
            "body": f"Error fetching user profile: {e!s}"
        }

    email = profile.get("email")
    google_user_id = profile.get("id")

    if not google_user_id:
        return {
            "statusCode": 500,
            "body": "Unable to get Google user ID"
        }

    google_user_id_token = token_hash(google_user_id)
    google_user_id = None

    if purge:
        return purge_user_data(google_user_id_token)

    # Check if user already exists
    api_key = None
    try:
        response = mapping_table.get_item(Key={
            'google_user_id_token': google_user_id_token,
        })
        item = response.get('Item', {})
        api_key = item.get('api_key') or None
    except Exception as e:  # noqa: BLE001 - fall through to the keys-table scan on any lookup failure
        log.debug('mapping table lookup failed: %s', e)

    if api_key is None:
        try:
            response = keys_table.scan(
                FilterExpression="google_user_id_token = :u",
                ExpressionAttributeValues={":u": google_user_id_token}
            )
            first_item = response.get("Items", [{}])[0]
            api_key = first_item.get('api_key') or None
        except Exception as e:  # noqa: BLE001 - fall through to generating a new key on any lookup failure
            log.debug('keys table scan failed: %s', e)

    # Generate a new token
    if api_key is None:
        api_key = secrets.token_urlsafe(30)  # 40-ish character random string

    # Create or update user record
    try:
        keys_table.put_item(Item={
            "api_key": api_key,
            "google_user_id_token": google_user_id_token,
            "youtube_access_token": token_encrypt(access_token),
            "youtube_refresh_token": token_encrypt(refresh_token),
        })
    except Exception as e:  # noqa: BLE001 - top-level handler must convert any failure into an HTTP response
        return {
            "statusCode": 500,
            "body": f"Failed to store user in DynamoDB: {e!s}"
        }
    else:
        # Attempt to optimize future lookups
        try:
            mapping_table.put_item(Item={
                "google_user_id_token": google_user_id_token,
                "api_key": api_key,
            })
        except Exception as e:  # noqa: BLE001 - this is a best-effort cache write, not required for correctness
            log.debug('mapping table write failed: %s', e)

    # Return dark-themed HTML with API key and curl command
    document_str = f'''\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link rel="icon" href="https://static.ytsubs.app/favicon.ico" type="image/x-icon" />
        <link rel="stylesheet" href="https://static.ytsubs.app/callback.css" blocking="render" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta charset="UTF-8">
        <title>Your YTSubs: Subscription Exporter API Key</title>
    </head>
    <body>
        <h1>Welcome, {html.escape(email)}</h1>
        <p>Your API key is:</p>
        <code>{html.escape(api_key)}</code>

        <p>You can use it to call the API like this:</p>
        <code>
curl https://ytsubs.app/subscriptions?api_key={html.escape(api_key)}
        </code>
        <p style="margin-top: 2em">Consider supporting this project and helping me develop cool tools:</p>
        <a href='https://ko-fi.com/E1E5RZJY' target='_blank'><img height='36' style='border:0px;height:48px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=6' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
        <footer style="margin-top: 2em;">
          <a href="https://static.ytsubs.app/privacypolicy.html" style="color: cornflowerblue;">Privacy Policy</a>
          &middot;
          <a href="https://ytsubs.app/?purge=1" style="color: cornflowerblue;">Delete my data</a>
        </footer>
    </body>
    </html>
    '''

    return {
        "statusCode": 200,
        "headers": { "Content-Type": "text/html" },
        "body": document_str,
    }


def purge_cached_subscriptions(api_key):
    pages_item = subs_table.get_item(Key={'api_key': f'{api_key},pages'}).get('Item') or {}
    page_count = pages_item.get('data') or 0
    with subs_table.batch_writer() as batch:
        for page in range(1, 1 + page_count):
            batch.delete_item(Key={'api_key': f'{api_key},page{page}'})
        batch.delete_item(Key={'api_key': f'{api_key},pages'})


def purge_user_data(google_user_id_token):
    # Any api_key (old or new) tied to this Google account gets removed, not just
    # the most recent one, in case a prior bug or migration left stale rows behind.
    api_keys = set()

    try:
        item = mapping_table.get_item(Key={'google_user_id_token': google_user_id_token}).get('Item') or {}
        if item.get('api_key'):
            api_keys.add(item['api_key'])
    except Exception as e:  # noqa: BLE001 - fall through to the keys-table scan below regardless
        log.debug('mapping table lookup failed during purge: %s', e)

    try:
        scan_response = keys_table.scan(
            FilterExpression="google_user_id_token = :u",
            ExpressionAttributeValues={":u": google_user_id_token}
        )
        for scanned_item in scan_response.get('Items', []):
            if scanned_item.get('api_key'):
                api_keys.add(scanned_item['api_key'])
    except Exception as e:  # noqa: BLE001 - purge whatever keys were already found rather than aborting
        log.debug('keys table scan failed during purge: %s', e)

    for api_key in api_keys:
        try:
            purge_cached_subscriptions(api_key)
        except Exception as e:  # noqa: BLE001 - still delete the api_key row even if cache cleanup fails
            log.warning('failed to purge cached subscriptions for an api_key: %s', e)
        try:
            keys_table.delete_item(Key={'api_key': api_key})
        except Exception as e:  # noqa: BLE001 - continue purging the remaining keys regardless
            log.warning('failed to delete an api_key during purge: %s', e)

    try:
        mapping_table.delete_item(Key={'google_user_id_token': google_user_id_token})
    except Exception as e:  # noqa: BLE001 - not fatal; the mapping row would just go stale
        log.debug('failed to delete mapping table entry during purge: %s', e)

    document_str = '''\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link rel="icon" href="https://static.ytsubs.app/favicon.ico" type="image/x-icon" />
        <link rel="stylesheet" href="https://static.ytsubs.app/callback.css" blocking="render" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta charset="UTF-8">
        <title>YTSubs: Data Deleted</title>
    </head>
    <body>
        <h1>Your data has been deleted</h1>
        <p>Your API key(s) and cached YouTube subscriptions have been removed from YTSubs.</p>
        <p>To fully revoke YTSubs' access to your Google account, visit your <a href="https://myaccount.google.com/permissions" target="_blank" style="color: cornflowerblue;">Google Account Permissions</a> page and remove access there as well.</p>
    </body>
    </html>
    '''

    return {
        "statusCode": 200,
        "headers": { "Content-Type": "text/html" },
        "body": document_str,
    }
