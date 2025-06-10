import os
import urllib.parse

def lambda_handler(event, context):
    client_id = os.environ['GOOGLE_CLIENT_ID']
    redirect_uri = os.environ['GOOGLE_REDIRECT_URI']
    scope = "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/userinfo.email"

    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urllib.parse.urlencode({
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "access_type": "offline",
            "prompt": "consent"
        })
    )

    return {
        "statusCode": 302,
        "headers": {
            "Location": auth_url
        },
        "body": ""
    }
