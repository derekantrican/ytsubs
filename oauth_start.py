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
        <link rel="icon" href="https://static.ytsubs.app/favicon.ico" type="image/x-icon">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
                margin: 0;
                text-align: center;
                padding: 2em 1em;
            }}
            .logo {{
                width: 150px;
                height: 150px;
            }}
            h1 {{
                font-size: 2em;
                margin-bottom: 0.2em;
            }}
            h2 {{
                margin-top: 2.5em;
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
            code {{
                white-space: pre-wrap;
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
        <img class="logo" src="https://static.ytsubs.app/logo.png"/>
        <h1>Welcome to YTSubs</h1>
        <p>A simple service to fetch and cache your YouTube subscriptions using the YouTube Data API.</p>
        <a href="{auth_url}" class="button">Sign in with Google</a>
        <h2>Example response:</h2>
        <p>The API response with list of the user's subscriptions as they are returned by the <a style="color: cornflowerblue" href="https://developers.google.com/youtube/v3/docs/subscriptions#resource-representation" target="_blank">YouTube API</a> with an additional 'lastRetrievalDate' parameter indicating how old the data is (updated upon a call to the API every 12 hours)</p>
        <code>
&#123;
  "lastRetrievalDate": "2025-06-10T01:32:08.355395",
  "subscriptions": [
    &#123;
      "kind": "youtube#subscription",
      "etag": "mep1K4OBALF4wrTFaXIYU-_xnsU",
      "id": "CWE0Bb1OftIKrp8FAk4EYe_MiDVd-mT-5vdiIOY_LVs",
      "snippet": &#123;
        "publishedAt": "2018-01-03T21:42:30.834186Z",
        "title": "Mark Rober",
        "description": "Former NASA engineer. Current CrunchLabs founder and friend of science...",
        "resourceId": &#123;
          "kind": "youtube#channel",
          "channelId": "UCY1kMZp36IQSyNx_9h4mpCg"
        &#125;,
        "channelId": "UCPJHnEGx82NVaeJCYM_PFJg",
        "thumbnails": &#123;
          "default": &#123;
            "url": "https://yt3.ggpht.com/ytc/AIdro_ksXY2REjZ6gYKSgnWT5jC_zT9mX900vyFtVinR8KbHww=s88-c-k-c0x00ffffff-no-rj"
          &#125;,
          "medium": &#123;
            "url": "https://yt3.ggpht.com/ytc/AIdro_ksXY2REjZ6gYKSgnWT5jC_zT9mX900vyFtVinR8KbHww=s240-c-k-c0x00ffffff-no-rj"
          &#125;,
          "high": &#123;
            "url": "https://yt3.ggpht.com/ytc/AIdro_ksXY2REjZ6gYKSgnWT5jC_zT9mX900vyFtVinR8KbHww=s800-c-k-c0x00ffffff-no-rj"
          &#125;
        &#125;
      &#125;
    &#125;
  ]
&#125;
        </code>
        <a style="margin-top: 2.5em" href='https://ko-fi.com/E1E5RZJY' target='_blank'><img height='36' style='border:0px;height:48px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=6' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
    </body>
    </html>
    """

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html"},
        "body": html
    }
