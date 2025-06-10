import os
import urllib.parse

def lambda_handler(event, context):
    redirect_uri = os.environ["GOOGLE_REDIRECT_URI"]
    client_id = os.environ["GOOGLE_CLIENT_ID"]
    scope = "openid email https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/youtube.readonly"
    
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent"
    })

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Welcome to YTSubs</title>
        <style>
            body {{
                background-color: #121212;
                color: #e0e0e0;
                font-family: sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
                text-align: center;
            }}
            .logo {{
                margin-bottom: 1em;
                width: 100px;
                height: 100px;
                background: #333;
                border-radius: 50%;
            }}
            h1 {{
                font-size: 2em;
                margin-bottom: 0.2em;
            }}
            p {{
                font-size: 1.1em;
                margin-bottom: 2em;
                max-width: 500px;
            }}
            a.button {{
                display: inline-block;
                padding: 1em 2em;
                background-color: #4285F4;
                color: white;
                text-decoration: none;
                font-size: 1.2em;
                border-radius: 6px;
                transition: background-color 0.3s ease;
            }}
            a.button:hover {{
                background-color: #357ae8;
            }}
        </style>
    </head>
    <body>
        <div class="logo"></div>
        <h1>Welcome to YTSubs</h1>
        <p>A simple service to fetch and cache your YouTube subscriptions using the YouTube Data API.</p>
        <a href="{auth_url}" class="button">Sign in with Google</a>
    </body>
    </html>
    """

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html"},
        "body": html
    }
