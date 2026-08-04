import html
import urllib.parse

from utils import EnvGoogle


def lambda_handler(event, context):
    query_params = event.get('queryStringParameters') or {}
    purge = '1' == query_params.get('purge')

    api_auth_base_url = 'https://www.googleapis.com/auth'
    oauth_base_url = 'https://accounts.google.com/o/oauth2/v2/auth'

    scope = ' '.join((
        'openid',
        'email',
        f'{api_auth_base_url}/userinfo.email',
        f'{api_auth_base_url}/youtube.readonly',
    ))

    qsl = [
        ('access_type', 'offline'),
        ('client_id', EnvGoogle.client_id),
        ('prompt', 'consent'),
        ('redirect_uri', EnvGoogle.redirect_uri),
        ('response_type', 'code'),
        ('scope', scope),
    ]
    if purge:
        # round-tripped through Google's OAuth flow so /auth/callback can require
        # a freshly-proven Google login before deleting anything
        qsl.append(('state', 'purge'))
    encoded_qsl = urllib.parse.urlencode(qsl)

    auth_url = f'{oauth_base_url}?{encoded_qsl}'

    if purge:
        heading = 'Delete your YTSubs data'
        intro = 'Sign in with Google again to confirm and permanently delete your API key(s) and cached YouTube subscriptions from YTSubs.'
        button_label = 'Confirm with Google &amp; Delete My Data'
    else:
        heading = 'Welcome to YTSubs: Subscription Exporter'
        intro = 'A simple service to fetch and cache your YouTube subscriptions using the YouTube Data API.'
        button_label = 'Sign in with Google'

    example_response = '''\
{
  "lastRetrievalDate": "2025-06-10T01:32:08.355395Z",
  "subscriptions": [
    {
      "id": "CWE0Bb1OftIKrp8FAk4EYe_MiDVd-mT-5vdiIOY_LVs",
      "snippet": {
        "publishedAt": "2018-01-03T21:42:30.834186Z",
        "title": "Mark Rober",
        "description": "Former NASA engineer. Current CrunchLabs founder and friend of science...",
        "resourceId": {
          "kind": "youtube#channel",
          "channelId": "UCY1kMZp36IQSyNx_9h4mpCg"
        },
        "thumbnails": {
          "default": {
            "url": "https://yt3.ggpht.com/ytc/AIdro_ksXY2REjZ6gYKSgnWT5jC_zT9mX900vyFtVinR8KbHww=s88-c-k-c0x00ffffff-no-rj"
          },
          "medium": {
            "url": "https://yt3.ggpht.com/ytc/AIdro_ksXY2REjZ6gYKSgnWT5jC_zT9mX900vyFtVinR8KbHww=s240-c-k-c0x00ffffff-no-rj"
          },
          "high": {
            "url": "https://yt3.ggpht.com/ytc/AIdro_ksXY2REjZ6gYKSgnWT5jC_zT9mX900vyFtVinR8KbHww=s800-c-k-c0x00ffffff-no-rj"
          }
        }
      }
    }
  ]
}
'''

    example_section = ''
    if not purge:
        example_section = f'''
        <h2>Example response:</h2>
        <p>The API response with list of the user's subscriptions as they are returned by the <a style="color: cornflowerblue" href="https://developers.google.com/youtube/v3/docs/subscriptions#resource-representation" target="_blank">YouTube API</a> with an additional 'lastRetrievalDate' parameter indicating how old the data is (updated upon a call to the API every 12 hours)</p>
        <code>{html.escape(example_response)}</code>
        <a style="margin-top: 2.5em" href='https://ko-fi.com/E1E5RZJY' target='_blank'><img height='36' style='border:0px;height:48px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=6' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
        '''

    document_str = f'''\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link rel="icon" href="https://static.ytsubs.app/favicon.ico" type="image/x-icon" />
        <link rel="stylesheet" href="https://static.ytsubs.app/start.css" blocking="render" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta charset="UTF-8">
        <title>Welcome to YTSubs: Subscription Exporter</title>
    </head>
    <body>
        <img class="logo" src="https://static.ytsubs.app/logo.png"/>
        <h1>{heading}</h1>
        <p>{intro}</p>
        <a href="{html.escape(auth_url)}" class="button">{button_label}</a>
        {example_section}
        <footer style="margin-top: 2em;">
          <a href="https://static.ytsubs.app/privacypolicy.html" style="color: cornflowerblue;">Privacy Policy</a>
        </footer>
    </body>
    </html>
    '''

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html"},
        "body": document_str,
    }
