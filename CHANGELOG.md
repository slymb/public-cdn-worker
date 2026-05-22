# Changelog

All notable public changes to this project are documented in this file.

This project follows semantic versioning.

## [1.0.2] - 2026-05-23

### Changed

- Switched the public project license from AGPL-3.0-or-later to Apache-2.0.

## [1.0.1] - 2026-05-10

### Changed

- Added README header artwork.
- Updated Wrangler to `4.90.0` to support the current Worker compatibility date in local development.

## [1.0.0] - 2026-05-10

### Added

- Initial public Cloudflare Worker CDN for protected media delivery from S3-compatible buckets.
- Domain-based hotlink protection with allowed origin and referer checks.
- Optional HMAC signed URLs for protected media requests.
- Optional media wrapper for direct media navigation.
- Image optimization controls for WebP, quality, and maximum width.
- Custom HTML error pages with strict security headers.
- Explicit Wrangler commands for development, dry-run checks, deployment, and log tailing.
- Local and remote development modes for clearer Cloudflare Worker testing.

### Changed

- Updated the Cloudflare Workers compatibility date.
- Tightened ignored local development files and Wrangler logs.

### Fixed

- Fixed CDN error responses so HTTP status codes match the actual error type.

### Security

- Runtime secrets and production values are not included in the repository.
- Runtime configuration remains managed through Cloudflare Dashboard.
