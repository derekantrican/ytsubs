<p align="center">
  <img height="300" width="300" src="/static/logo.png" alt="YTSubs.app" />
</p>

# YTSubs: YouTube Subscriptions Exporter API Service

YTSubs is a serverless web service that allows users to authenticate with their Google account and securely retrieve a cached list of their YouTube subscriptions. This system is powered by AWS Lambda, API Gateway, DynamoDB, and GitHub Actions for continuous deployment.

This was mostly built with ChatGPT, so please provide feedback where things could be improved.

## Live URL

[https://ytsubs.app](https://ytsubs.app)


## Features

- Google OAuth2 login with YouTube access (`read-only`)
- Serverless infrastructure using AWS Lambda & API Gateway
- Automatic caching of YouTube subscriptions (refreshed every 12 hours)
- User-specific API key authentication (stored in DynamoDB)
- Friendly landing and callback pages
- GitHub Actions CI/CD for Lambda deployment

## AWS Diagram

```mermaid
graph TD
    CF[Cloudflare DNS <br/> ytsubs.app]
    CF -->|CNAME| GW[API Gateway <br/> Custom Domain]
    GW -->|Route: / | LambdaStart[Lambda: oauth_start]
    GW -->|Route: /auth/callback | LambdaCallback[Lambda: oauth_callback]
    GW -->|Route: /subscriptions | LambdaFetch[Lambda: fetch_subscriptions]

    LambdaCallback --> DB[DynamoDB: ytsubs_api_keys]
    LambdaFetch --> DB
    LambdaFetch --> Cache[DynamoDB: ytsubs_subscriptions_cache]
```

## Repo Structure

```
ytsubs-lambdas/
├── fetch_subscriptions.py     # Lambda for /subscriptions
├── oauth_start.py             # Lambda for / (homepage)
├── oauth_callback.py          # Lambda for /auth/callback
├── static/                     # Static sources such as images & privacy policy
└── .github/
   └── workflows/
      └── deploy.yml         # GitHub Actions CI/CD workflow
````


## API Usage

### Get Subscriptions

```bash
curl "https://ytsubs.app/subscriptions?api_key=YOUR_API_KEY"
````

Returns:

```json
{
  "lastRetrievalDate": "2025-06-06T21:04:00Z",
  "subscriptions": [ ... ]
}
```

## Possible future improvements

* CloudFront for caching and rate limiting
* Per-user usage metrics
* Multi-region redundancy
