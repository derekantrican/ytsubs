import json
import urllib.parse
import urllib.request
import boto3
import secrets
from utils import EnvGoogle

dynamodb = boto3.resource('dynamodb')
keys_table = dynamodb.Table('ytsubs_api_keys')
mapping_table = dynamodb.Table('ytsubs_user_to_api')

def lambda_handler(event, context):
    params = event.get('queryStringParameters') or {}
    code = params.get('code')
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

            if required_scope not in granted_scopes.split():
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
            "body": """
            <html>
            <head>
                <style>
                body {
                    background-color: #121212;
                    color: #e0e0e0;
                    font-family: sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    text-align: center;
                }
                a {
                    color: cornflowerblue;
                }
                </style>
            </head>
            <body>
                <h1>OAuth Link Expired</h1>
                <p>Your authorization link has expired or is invalid.</p>
                <p>Please <a href="https://ytsubs.app">go back to the homepage</a> and try again.</p>
            </body>
            </html>
            """
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
    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Error fetching user profile: {str(e)}"
        }

    email = profile.get("email")
    google_user_id = profile.get("id")

    if not google_user_id:
        return {
            "statusCode": 500,
            "body": "Unable to get Google user ID"
        }

    # Check if user already exists
    api_key = None
    try:
        response = mapping_table.get_item(Key={
            'google_user_id': google_user_id,
        })
        item = response.get('Item', {})
        api_key = item.get('api_key') or None
    except:
        try:
            response = keys_table.scan(
                FilterExpression="google_user_id = :u",
                ExpressionAttributeValues={":u": google_user_id}
            )
            first_item = response.get("Items", [{}])[0]
            api_key = first_item.get('api_key') or None
        except Exception as e:
            return {
                "statusCode": 500,
                "body": f"DynamoDB scan failed: {str(e)}"
            }

    if api_key is None:
        api_key = secrets.token_urlsafe(30)  # 40-ish character random string

    # Create or update user record
    try:
        keys_table.put_item(Item={
            "api_key": api_key,
            "google_user_id": google_user_id,
            "email": email,
            "youtube_access_token": access_token,
            "youtube_refresh_token": refresh_token
        })
    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Failed to store user in DynamoDB: {str(e)}"
        }
    else:
        # Attempt to optimize future lookups
        try:
            mapping_table.put_item(Item={
                "google_user_id": google_user_id,
                "api_key": api_key,
            })
        except:
            pass

    # Return dark-themed HTML with API key and curl command
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link rel="icon" href="https://static.ytsubs.app/favicon.ico" type="image/x-icon">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta charset="UTF-8">
        <title>Your YTSubs: Subscription Exporter API Key</title>
        <style>
            body {{
                background-color: #121212;
                color: #e0e0e0;
                font-family: sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                margin: 0;
                text-align: center;
                padding: 1em;
            }}
            h1 {{
                font-size: 1.8em;
                margin-bottom: 0.2em;
                word-wrap: break-word;
                width: 100%;
            }}
            p {{
                font-size: 1.1em;
                margin: 0.5em 0;
            }}
            code {{
                background: #1e1e1e;
                padding: 0.5em;
                border-radius: 5px;
                display: block;
                margin: 1em auto;
                max-width: 90%;
                overflow-x: auto;
                text-align: left;
            }}
        </style>
    </head>
    <body>
        <h1>Welcome, {email}</h1>
        <p>Your API key is:</p>
        <code>{api_key}</code>
        <p>And your Google User ID is:</p>
        <code>{google_user_id}</code>

        <p>You can use them together to call the API like this:</p>
        <code>
curl https://ytsubs.app/subscriptions?api_key={api_key}&google_user_id={google_user_id}
        </code>
        <p style="margin-top: 2em">Consider supporting this project and helping me develop cool tools:</p>
        <a href='https://ko-fi.com/E1E5RZJY' target='_blank'><img height='36' style='border:0px;height:48px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=6' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
        <footer style="margin-top: 2em;">
          <a href="https://static.ytsubs.app/privacypolicy.html" style="color: cornflowerblue;">Privacy Policy</a>
        </footer>
    </body>
    </html>
    """

    return {
        "statusCode": 200,
        "headers": { "Content-Type": "text/html" },
        "body": html
    }
