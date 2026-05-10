# public-cdn-worker

**CDN Worker with hotlink protection** for public buckets (Backblaze B2 / S3).

[![Deploy to Cloudflare](https://img.shields.io/badge/Deploy-Cloudflare-orange?logo=cloudflare)](https://dash.cloudflare.com)
[![Runtime Dependencies](https://img.shields.io/badge/Runtime%20dependencies-0-green)](https://github.com/slymb/public-cdn-worker)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](./LICENSE)
[![Maintained by Slym B.](https://img.shields.io/badge/Maintained%20by-Slym%20B.-111111)](https://github.com/slymb)

---

## Features

- **Hotlink protection** : domain-based, subdomain wildcard auto
- **Anti-bot UA** : blocks curl, python, scrapy, etc.
- **Media wrapper** : anti-right-click, anti-drag, anti-save on direct access
- **Image optimization** : WebP auto, configurable quality, max width
- **Custom errors** : styled 403/404 pages with Ray ID
- **SEO-friendly** : Google, Bing, DuckDuckGo, social media bots always allowed
- **Zero runtime dependency** : single Worker file, Wrangler only for deployment

---

## Setup

This repository is a Cloudflare Worker project designed for Wrangler and Cloudflare Workers Builds.

```bash
npm install
npm run dev
npm run check
npm run deploy
```

Configure runtime values in Cloudflare Dashboard, not in `wrangler.toml`.

`wrangler.toml` intentionally uses `keep_vars = true` and no `[vars]` section. This prevents automatic deploys from overwriting variables created in the Cloudflare Dashboard.

Set secrets from Cloudflare Dashboard or Wrangler:

```bash
npx wrangler secret put B2_ENDPOINT
npx wrangler secret put SIGNING_SECRET
```

`SIGNING_SECRET` is required only when `REQUIRE_SIGNED_URLS = "true"`.

Cloudflare can also deploy this repository from its Git integration.

Local test commands:

```bash
npm run prod:offline
npm run prod:local
```

- `prod:offline` runs the Worker locally with the local runtime. External bucket fetches leave from your machine.
- `prod:local` runs with Cloudflare remote mode. External bucket fetches leave from Cloudflare and are closer to production behavior.
- `npm run check` performs a Wrangler dry run without deploying.

Recommended Workers Builds settings:

```text
Install command: npm ci
Build command: leave empty
Deploy command: npm run deploy
```

For Git-based auto-deploys, create the Dashboard variables before the first production deploy when possible. If the first deploy already happened, add the variables in the Dashboard, then redeploy. Future deploys will preserve them because `keep_vars = true` is enabled.

The repository does not contain production domains, bucket URLs, tokens, or secrets. Runtime configuration belongs in the Cloudflare Dashboard.

---

## Environment Variables

| Variable | Type | Description | Required |
|----------|------|-------------|----------|
| `B2_ENDPOINT` | Secret | Source bucket URL | yes |
| `ALLOWED_DOMAINS` | Plain text | Allowed domains, comma-separated | yes |
| `BLOCK_DIRECT_MEDIA_ACCESS` | Plain text | Block direct media navigation outside allowed domains | recommended |
| `BLOCK_CROSS_SITE_NO_REFERRER` | Plain text | Block cross-site hotlink without referer | recommended |
| `BLOCK_SUSPICIOUS_MEDIA_REQUESTS` | Plain text | Block suspicious media requests | recommended |
| `BLOCK_MEDIA_INDEXING` | Plain text | Add X-Robots-Tag noindex on media | recommended |
| `BLOCK_EMPTY_UA` | Plain text | Block empty User-Agents | recommended |
| `BLOCKED_USER_AGENTS` | Plain text | Blocked UA keywords, comma-separated | recommended |
| `USE_MEDIA_WRAPPER` | Plain text | Anti-click wrapper on direct access | optional |
| `ENABLE_WEBP` | Plain text | Convert to WebP if supported | optional |
| `IMAGE_QUALITY` | Plain text | JPEG/WebP quality, 1-100 | optional |
| `MAX_WIDTH` | Plain text | Max width in pixels | optional |
| `MAIN_SITE_DOMAIN` | Plain text | Main site domain | optional |
| `SITE_NAME` | Plain text | Site name, error footer | optional |
| `SITE_URL` | Plain text | Site URL, error footer | optional |
| `REQUIRE_SIGNED_URLS` | Plain text | Require HMAC signed media URLs | optional |
| `SIGNING_SECRET` | Secret | HMAC secret for signed URLs | only if signed URLs are enabled |
| `SIGNATURE_PARAM` | Plain text | Signature query parameter | optional |
| `EXPIRES_PARAM` | Plain text | Expiration query parameter | optional |
| `CDN_PREFIX` | Plain text | Optional URL prefix | optional |
| `ERROR_TITLE` | Plain text | Custom error page title | optional |
| `ERROR_MESSAGE` | Plain text | Custom error page message | optional |

---

## Example Configuration

```
ALLOWED_DOMAINS=example.com,www.example.com
BLOCK_DIRECT_MEDIA_ACCESS=true
BLOCK_CROSS_SITE_NO_REFERRER=true
BLOCK_SUSPICIOUS_MEDIA_REQUESTS=true
BLOCK_MEDIA_INDEXING=true
BLOCK_EMPTY_UA=true
BLOCKED_USER_AGENTS=python,requests,curl,wget,axios,scrapy,craw
USE_MEDIA_WRAPPER=true
ENABLE_WEBP=true
IMAGE_QUALITY=50
MAX_WIDTH=1200
REQUIRE_SIGNED_URLS=false
SITE_NAME=MySite
SITE_URL=https://example.com
```

`B2_ENDPOINT` must be configured as a secret, not plain text.

## Signed URLs

When `REQUIRE_SIGNED_URLS=true`, each media request must include:

- `exp`: Unix timestamp in seconds
- `sig`: HMAC-SHA256 hex signature

The signature payload is:

```text
pathname?sorted_query_without_sig
```

Example payload:

```text
/images/photo.jpg?exp=1893456000&w=1200
```

The Worker removes `sig` and `exp` before forwarding the request to the origin bucket.

## Security Notes

JavaScript returned to the browser is always visible in DevTools. The anti-click wrapper is only a friction layer, not a security boundary.

Actual protection is enforced at the Worker level:

- allowed domain checks
- suspicious media request blocking
- direct media navigation blocking outside allowed domains
- optional signed URLs
- HTTPS-only origin endpoint
- path traversal rejection
- strict wrapper CSP
- no secret forwarded to the origin

---

## How It Works

```
Request → UA Check → Hotlink Check → Cache Lookup → Bucket Fetch → Response
                                    ↓                ↓
                              Cache Hit →      Image Optimize (optional)
                              Return cached     Security Headers
```

- **Direct navigation** (new tab, pasted URL) to a media file returns an anti-click wrapper
- **Allowed referer/origin** : content served normally
- **Disallowed referer/origin** : returns 404
- **Search engine bots** : always allowed through

---

## Support

- **Issues:** [GitHub Issues](https://github.com/slymb/public-cdn-worker/issues)
- **Sponsor:** [GitHub Sponsors](https://github.com/sponsors/slymb)
- **Support the project:** [Buy Me a Coffee](https://buymeacoffee.com/slym)

## License

This project is licensed under [AGPL-3.0-or-later](./LICENSE).

Commercial licensing is available for teams that need different terms, closed-source redistribution, or private integration without AGPL obligations.
