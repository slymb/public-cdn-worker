/**
 * public-cdn-worker
 * Protected media delivery for public buckets.
 * Author: Slym B.
 * Repository: https://github.com/slymb/public-cdn-worker
 * License: AGPL-3.0-or-later
 *
 * ENV VARIABLES:
 * - ALLOWED_DOMAINS: allowed domains, comma-separated
 * - B2_ENDPOINT: source bucket URL, Cloudflare secret
 * - IMAGE_QUALITY: JPEG/WebP quality, default 50
 * - MAX_WIDTH: max image width, no limit by default
 * - ENABLE_WEBP: convert to WebP when supported
 * - BLOCKED_USER_AGENTS: blocked User-Agent keywords, comma-separated
 * - BLOCK_EMPTY_UA: block empty User-Agent requests
 * - BLOCK_SUSPICIOUS_MEDIA_REQUESTS: block non-browser or suspicious media requests
 * - BLOCK_CROSS_SITE_NO_REFERRER: block cross-site hotlinks without Referer/Origin
 * - BLOCK_DIRECT_MEDIA_ACCESS: block direct media navigation outside allowed domains
 * - REQUIRE_SIGNED_URLS: require HMAC signatures for media URLs
 * - SIGNING_SECRET: HMAC SHA-256 secret for signed URLs
 * - SIGNATURE_PARAM: signature query parameter, default "sig"
 * - EXPIRES_PARAM: expiration query parameter, default "exp"
 *
 * FLOW:
 * - Direct navigation can return a protective media wrapper
 * - Allowed Referer/Origin is served normally
 * - Disallowed Referer/Origin receives 404
 * - Search and social bots are allowed through
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response(null, {
        status: 405,
        headers: {
          'Allow': 'GET, HEAD',
          'Cache-Control': 'no-store'
        }
      });
    }

    // ============================================================
    //          REQUEST METADATA + USER-AGENT FILTER
    // ============================================================

    const reqMeta = buildRequestMeta(request, url);

    if (isUserAgentBlocked(reqMeta.userAgent, env) && !reqMeta.isBot) {
      return generateErrorResponse(env, request, 'forbidden');
    }

    if (!isValidOriginEndpoint(env.B2_ENDPOINT)) {
      return generateErrorResponse(env, request, 'error');
    }

    if (reqMeta.isLikelyMedia && !(await hasValidRequestSignature(request, env))) {
      return generate404Response(request);
    }

    // ============================================================
    //          HOTLINK PROTECTION
    // ============================================================

    const allowedDomains = parseList(env.ALLOWED_DOMAINS);
    const referer = request.headers.get('Referer');
    const hasAllowedOriginOrReferer = hasAllowedOriginOrRefererContext(request, allowedDomains);
    const hasDisallowedOriginOrReferer = hasDisallowedOriginOrRefererContext(request, allowedDomains);
    const hasAllowedContext = isAllowedRequestContext(request, allowedDomains, reqMeta.secFetchSite);

    if (allowedDomains.length && !reqMeta.isBot && reqMeta.isLikelyMedia) {
      if (env.BLOCK_DIRECT_MEDIA_ACCESS !== 'false' && reqMeta.isNavigation && !hasAllowedOriginOrReferer) {
        return generateErrorResponse(env, request, 'forbidden');
      }

      if (reqMeta.secFetchSite === 'cross-site' && !hasAllowedContext) {
        return generate404Response(request);
      }

      if (hasDisallowedOriginOrReferer) {
        return generate404Response(request);
      }

      if (
        env.BLOCK_CROSS_SITE_NO_REFERRER === 'true' &&
        !referer &&
        reqMeta.isLikelyMedia &&
        reqMeta.secFetchSite === 'cross-site' &&
        !hasAllowedOriginOrReferer
      ) {
        return generate404Response(request);
      }
    }

    if (
      env.BLOCK_SUSPICIOUS_MEDIA_REQUESTS === 'true' &&
      reqMeta.isLikelyMedia &&
      !reqMeta.isBot &&
      isSuspiciousMediaRequest(reqMeta) &&
      !hasAllowedContext &&
      !hasAllowedOriginOrReferer
    ) {
      return generate404Response(request);
    }

    const shouldWrap = !reqMeta.isBot &&
                       reqMeta.isLikelyMedia &&
                       shouldUseMediaWrapper(reqMeta) &&
                       reqMeta.secFetchSite === 'cross-site' &&
                       !hasDisallowedOriginOrReferer &&
                       !hasAllowedContext;

    if (shouldWrap) {
      const nonce = generateNonce();
      const html = generateMediaWrapper(url.toString(), reqMeta.isLikelyVideo, nonce);
      return new Response(html, {
        status: 200,
        headers: buildWrapperHeaders(nonce)
      });
    }

    // ============================================================
    //          CDN FETCH AND CACHE
    // ============================================================

    let cleanPath = url.pathname;
    if (env.CDN_PREFIX) {
      const prefix = env.CDN_PREFIX.startsWith('/') ? env.CDN_PREFIX : '/' + env.CDN_PREFIX;
      if (cleanPath.startsWith(prefix)) {
        cleanPath = cleanPath.substring(prefix.length);
        if (!cleanPath.startsWith('/')) cleanPath = '/' + cleanPath;
      }
    }

    const safePath = normalizeSafePath(cleanPath);
    if (!safePath) {
      return generate404Response(request);
    }

    const sourceUrl = `${env.B2_ENDPOINT}${safePath}${buildForwardedSearch(url, env)}`;

    const cache = caches.default;
    const quality = parseImageQuality(env.IMAGE_QUALITY, 50);
    const maxWidth = parsePositiveInt(env.MAX_WIDTH);
    const requestedFormat = getRequestedFormat(request, env.ENABLE_WEBP !== 'false');
    const cacheKeyUrl = buildCacheKeyUrl(url, {
      version: '2',
      format: requestedFormat,
      quality,
      width: maxWidth
    });
    const cacheKey = new Request(cacheKeyUrl, request);
    let response = await cache.match(cacheKey);

    if (!response) {
      try {
        const acceptsWebp = requestedFormat === 'webp';
        const shouldOptimize = reqMeta.isLikelyImage && !isSvgPath(url.pathname);
        const imageOptions = shouldOptimize
          ? buildImageOptions({
              quality,
              maxWidth,
              acceptsWebp,
              enableWebp: env.ENABLE_WEBP !== 'false'
            })
          : null;

        response = await fetch(sourceUrl, {
          cf: {
            cacheTtl: 604800,
            cacheEverything: true,
            ...(imageOptions ? { image: imageOptions } : {})
          }
        });

        if (!response.ok && imageOptions) {
          const rawResponse = await fetch(sourceUrl, {
            cf: { cacheTtl: 604800, cacheEverything: true }
          });
          if (rawResponse.ok) {
            response = rawResponse;
          }
        }

        if (!response.ok) {
          const errorType = response.status === 404 ? 'notfound' : 'error';
          return generateErrorResponse(env, request, errorType);
        }

        const contentType = response.headers.get('Content-Type') || '';
        const isMedia = contentType.startsWith('image/') || contentType.startsWith('video/');

        response = applySecurityHeaders(response, env, isMedia);

        if (imageOptions?.format === 'webp') {
          response.headers.set('Vary', 'Accept');
        }

        ctx.waitUntil(cache.put(cacheKey, response.clone()));

      } catch (error) {
        response = await fetch(sourceUrl, {
          cf: { cacheTtl: 604800, cacheEverything: true }
        });

        if (!response.ok) {
          const errorType = response.status === 404 ? 'notfound' : 'error';
          return generateErrorResponse(env, request, errorType);
        }

        const contentType = response.headers.get('Content-Type') || '';
        const isMedia = contentType.startsWith('image/') || contentType.startsWith('video/');

        response = applySecurityHeaders(response, env, isMedia);
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
      }
    }

    // ============================================================
    //          DIRECT MEDIA WRAPPER
    // ============================================================

    const contentType = response.headers.get("Content-Type") || "";
    const isMedia = contentType.startsWith("image/") || contentType.startsWith("video/");

    if (isMedia && env.USE_MEDIA_WRAPPER === "true") {
      const accept = request.headers.get("Accept") || "";
      const wantsHtml = accept.includes("text/html");
      const isImageRequest = reqMeta.secFetchDest === "image";
      const isVideoRequest = reqMeta.secFetchDest === "video";
      const isDirectOpen = !isImageRequest && !isVideoRequest && (wantsHtml || reqMeta.secFetchDest === "document");

      if (isDirectOpen) {
        const nonce = generateNonce();
        const html = generateMediaWrapper(url.toString(), contentType.startsWith('video/'), nonce);
        return new Response(html, {
          status: 200,
          headers: buildWrapperHeaders(nonce)
        });
      }
    }

    return response;
  }
};


// ===================================================
// MEDIA WRAPPER
// ===================================================

function generateMediaWrapper(mediaUrl, isVideo, nonce) {
  const safeMediaUrl = escapeHtmlAttribute(mediaUrl);
  const mediaTag = isVideo
    ? `<video id="media" src="${safeMediaUrl}" controls controlsList="nodownload nofullscreen noremoteplayback" disablePictureInPicture playsinline></video>`
    : `<img id="media" src="${safeMediaUrl}" alt="" draggable="false">`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>Media</title>
  <style nonce="${nonce}">
    * {
      margin: 0; padding: 0; box-sizing: border-box;
      -webkit-user-select: none !important;
      user-select: none !important;
      -webkit-touch-callout: none !important;
      -webkit-user-drag: none !important;
      user-drag: none !important;
    }
    html, body {
      width: 100%; height: 100%; overflow: hidden;
      background: transparent; position: fixed;
    }
    body { display: flex; align-items: center; justify-content: center; }
    #media {
      max-width: 100%; max-height: 100%; object-fit: contain;
      pointer-events: ${isVideo ? 'auto' : 'none'};
    }
  </style>
</head>
<body>
  ${mediaTag}
  <script nonce="${nonce}">
  (function() {
    const m = document.getElementById('media');
    const stop = e => { e.preventDefault(); e.stopPropagation(); return false; };
    document.addEventListener('contextmenu', stop, true);
    ['dragstart','drag','drop','dragenter','dragleave','dragover','copy','cut','paste','selectstart']
      .forEach(t => document.addEventListener(t, stop, true));
    document.addEventListener('keydown', e => {
      if ((e.ctrlKey||e.metaKey) && 'sScCuUaA'.includes(e.key)) return stop(e);
      if (e.key==='F12'||(e.ctrlKey&&e.shiftKey&&'IiJjCc'.includes(e.key))) return stop(e);
      if (e.key==='PrintScreen'||e.key==='Print') return stop(e);
    }, true);
  })();
  </script>
</body>
</html>`;
}

function buildWrapperHeaders(nonce) {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': `default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';`,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store'
  };
}

function generateNonce() {
  return crypto.randomUUID().replace(/-/g, '');
}

function escapeHtmlAttribute(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ===================================================
// CACHE, IMAGE AND SECURITY HELPERS
// ===================================================

function buildCacheKeyUrl(url, { version, format, quality, width }) {
  const cacheUrl = new URL(url.toString());
  if (version) cacheUrl.searchParams.set('__cfv', version);
  if (format) cacheUrl.searchParams.set('__fmt', format);
  if (Number.isFinite(quality)) cacheUrl.searchParams.set('__q', String(quality));
  if (Number.isFinite(width)) cacheUrl.searchParams.set('__w', String(width));
  return cacheUrl.toString();
}

function buildRequestMeta(request, url) {
  const secFetchDest = request.headers.get('Sec-Fetch-Dest') || '';
  const secFetchMode = request.headers.get('Sec-Fetch-Mode') || '';
  const secFetchSite = request.headers.get('Sec-Fetch-Site') || '';
  const accept = request.headers.get('Accept') || '';
  const userAgent = request.headers.get('User-Agent') || '';
  const isBot = isSearchBot(userAgent);
  const hasBrowserFetchHeaders = secFetchMode !== '' && secFetchDest !== '';

  const isNavigation = secFetchMode === 'navigate' || secFetchDest === 'document';
  const isLikelyImage = isLikelyImageRequest(url.pathname, secFetchDest);
  const isLikelyVideo = isLikelyVideoRequest(url.pathname, secFetchDest);

  return {
    secFetchDest,
    secFetchMode,
    secFetchSite,
    accept,
    userAgent,
    isBot,
    hasBrowserFetchHeaders,
    isNavigation,
    isLikelyImage,
    isLikelyVideo,
    isLikelyMedia: isLikelyImage || isLikelyVideo
  };
}

function parseList(value) {
  if (!value) return [];
  return value
    .split(',')
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);
}

function isUserAgentBlocked(userAgent, env) {
  const ua = (userAgent || '').toLowerCase();
  if (!ua && env.BLOCK_EMPTY_UA === 'true') return true;

  const blockedAgents = parseList(env.BLOCKED_USER_AGENTS);
  if (!blockedAgents.length) return false;

  return blockedAgents.some(token => ua.includes(token));
}

function isSuspiciousMediaRequest(reqMeta) {
  const suspiciousUA = /curl|wget|python|httpie|postman|insomnia|axios|node-fetch|got\//i.test(reqMeta.userAgent);
  return !reqMeta.hasBrowserFetchHeaders || suspiciousUA;
}

function shouldUseMediaWrapper(reqMeta) {
  const isNavigating = reqMeta.secFetchMode === 'navigate';
  const isDocument = reqMeta.secFetchDest === 'document';
  const wantsHtml = reqMeta.accept.includes('text/html');

  return (
    isDocument ||
    (isNavigating &&
      (
        reqMeta.secFetchDest === '' ||
        reqMeta.secFetchDest === 'empty' ||
        reqMeta.secFetchDest === 'image' ||
        reqMeta.secFetchDest === 'video'
      )) ||
    (isNavigating && wantsHtml)
  );
}

function isAllowedRequestContext(request, allowedDomains, secFetchSite) {
  if (!allowedDomains.length) return true;

  if (secFetchSite === 'same-origin' || secFetchSite === 'same-site' || secFetchSite === 'none') {
    return true;
  }

  if (hasAllowedOriginOrRefererContext(request, allowedDomains)) {
    return true;
  }

  if (secFetchSite === 'cross-site' && hasDisallowedOriginOrRefererContext(request, allowedDomains)) {
    return false;
  }

  return true;
}

function hasAllowedOriginOrRefererContext(request, allowedDomains) {
  const originHost = getNormalizedHttpHost(request.headers.get('Origin'));
  const refererHost = getNormalizedHttpHost(request.headers.get('Referer'));

  if (originHost && isDomainAllowed(originHost, allowedDomains)) return true;
  if (refererHost && isDomainAllowed(refererHost, allowedDomains)) return true;
  return false;
}

function hasDisallowedOriginOrRefererContext(request, allowedDomains) {
  const originHost = getNormalizedHttpHost(request.headers.get('Origin'));
  const refererHost = getNormalizedHttpHost(request.headers.get('Referer'));
  let hasVerifiableHost = false;

  if (originHost) {
    hasVerifiableHost = true;
    if (isDomainAllowed(originHost, allowedDomains)) return false;
  }
  if (refererHost) {
    hasVerifiableHost = true;
    if (isDomainAllowed(refererHost, allowedDomains)) return false;
  }

  return hasVerifiableHost;
}

function getNormalizedHttpHost(urlValue) {
  if (!urlValue) return null;
  try {
    const parsed = new URL(urlValue);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.hostname.toLowerCase();
  } catch (_) {
    return null;
  }
}

function getRequestedFormat(request, enableWebp) {
  if (!enableWebp) return 'source';
  const accept = request.headers.get('Accept') || '';
  return accept.includes('image/webp') ? 'webp' : 'source';
}

function parsePositiveInt(value) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function parseImageQuality(value, fallback) {
  if (value == null || value === '') return fallback;
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(100, Math.max(1, parsed));
}

function isValidOriginEndpoint(value) {
  if (!value) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.hostname.length > 0 && !parsed.search && !parsed.hash;
  } catch (_) {
    return false;
  }
}

function normalizeSafePath(pathname) {
  if (!pathname || pathname === '/') return null;

  const normalizedSegments = [];
  for (const rawSegment of pathname.split('/')) {
    if (!rawSegment) continue;

    let segment;
    try {
      segment = decodeURIComponent(rawSegment);
    } catch (_) {
      return null;
    }

    if (
      segment === '.' ||
      segment === '..' ||
      segment.includes('/') ||
      segment.includes('\\') ||
      /[\u0000-\u001f\u007f]/.test(segment)
    ) {
      return null;
    }

    normalizedSegments.push(encodeURIComponent(segment));
  }

  return normalizedSegments.length ? `/${normalizedSegments.join('/')}` : null;
}

function buildForwardedSearch(url, env) {
  const searchParams = new URLSearchParams(url.search);

  if (env.REQUIRE_SIGNED_URLS === 'true') {
    searchParams.delete(getSignatureParam(env));
    searchParams.delete(getExpiresParam(env));
  }

  const search = searchParams.toString();
  return search ? `?${search}` : '';
}

async function hasValidRequestSignature(request, env) {
  if (env.REQUIRE_SIGNED_URLS !== 'true') return true;
  if (!env.SIGNING_SECRET) return false;

  const url = new URL(request.url);
  const signatureParam = getSignatureParam(env);
  const expiresParam = getExpiresParam(env);
  const providedSignature = url.searchParams.get(signatureParam);
  const expiresValue = url.searchParams.get(expiresParam);

  if (!providedSignature || !expiresValue) return false;
  if (!/^[a-f0-9]{64}$/i.test(providedSignature)) return false;

  const expiresAt = Number.parseInt(expiresValue, 10);
  if (!Number.isSafeInteger(expiresAt)) return false;
  if (expiresAt < Math.floor(Date.now() / 1000)) return false;

  const expectedSignature = await hmacSha256Hex(
    env.SIGNING_SECRET,
    buildSignaturePayload(url, signatureParam)
  );

  return timingSafeEqualHex(providedSignature, expectedSignature);
}

function getSignatureParam(env) {
  return env.SIGNATURE_PARAM || 'sig';
}

function getExpiresParam(env) {
  return env.EXPIRES_PARAM || 'exp';
}

function buildSignaturePayload(url, signatureParam) {
  const searchParams = new URLSearchParams(url.search);
  searchParams.delete(signatureParam);
  searchParams.sort();

  const search = searchParams.toString();
  return search ? `${url.pathname}?${search}` : url.pathname;
}

async function hmacSha256Hex(secret, payload) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return [...new Uint8Array(signature)]
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

function timingSafeEqualHex(left, right) {
  if (left.length !== right.length) return false;

  let diff = 0;
  for (let i = 0; i < left.length; i++) {
    diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }

  return diff === 0;
}

function buildImageOptions({ quality, maxWidth, acceptsWebp, enableWebp }) {
  const options = {};

  if (Number.isFinite(quality)) {
    options.quality = quality;
  }
  if (Number.isFinite(maxWidth)) {
    options.width = maxWidth;
    options.fit = 'inside';
  }
  if (enableWebp && acceptsWebp) {
    options.format = 'webp';
  }

  return Object.keys(options).length ? options : null;
}

function isSvgPath(pathname) {
  return pathname.toLowerCase().endsWith('.svg');
}

function isLikelyImageRequest(pathname, secFetchDest) {
  if (secFetchDest === 'image') return true;
  return /\.(avif|webp|png|jpe?g|gif|bmp|tiff?|ico|svg)$/i.test(pathname);
}

function isLikelyVideoRequest(pathname, secFetchDest) {
  if (secFetchDest === 'video') return true;
  return /\.(mp4|webm|mov|m4v|ogv|avi)$/i.test(pathname);
}

function applySecurityHeaders(response, env, isMedia) {
  const secured = new Response(response.body, response);
  secured.headers.set('Cache-Control', 'public, max-age=604800');
  secured.headers.set('X-Content-Type-Options', 'nosniff');
  secured.headers.set('X-Frame-Options', 'SAMEORIGIN');
  secured.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (isMedia) {
    secured.headers.set('Content-Disposition', 'inline');

    if (env.BLOCK_MEDIA_INDEXING === 'true') {
      secured.headers.set('X-Robots-Tag', 'noindex, nofollow');
    }

    secured.headers.set('X-Image-Protection', 'enabled');
    secured.headers.set('X-Permitted-Cross-Domain-Policies', 'none');
  }

  return secured;
}


// ===================================================
// ERROR RESPONSES
// ===================================================

function generateErrorResponse(env, request, errorType) {
  const status = getErrorStatus(errorType);

  if (shouldReturnImageCompatibleError(request)) {
    return generateImageCompatibleErrorResponse(status);
  }

  const rayId = request.headers.get('cf-ray') || 'Unknown';
  const countryCode = request.headers.get('cf-ipcountry') || 'Unknown';

  let displayTitle = env.ERROR_TITLE || 'Content unavailable';
  let displayMessage = env.ERROR_MESSAGE || 'The requested content is unavailable';

  if (!env.ERROR_TITLE || !env.ERROR_MESSAGE) {
    if (errorType === 'notfound') {
      displayTitle = 'Resource not found';
      displayMessage = 'The requested content does not exist';
    } else if (errorType === 'error') {
      displayTitle = 'Server error';
      displayMessage = 'An error occurred';
    } else if (errorType === 'forbidden') {
      displayTitle = 'Access denied';
      displayMessage = 'This content is protected';
    }
  }

  const siteName = escapeHtml(env.SITE_NAME || 'Site');
  const siteUrl = escapeHtmlAttribute(getSafeSiteUrl(env.SITE_URL));
  const nonce = generateNonce();
  const safeDisplayTitle = escapeHtml(displayTitle);
  const safeDisplayMessage = escapeHtml(displayMessage);
  const safeRayId = escapeHtml(rayId);
  const safeCountryCode = escapeHtml(countryCode);

  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex, nofollow">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${safeDisplayTitle}</title>
  <style nonce="${nonce}">
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      font-family: Inter, system-ui, sans-serif;
      background: hsl(0 0% 3.9%);
      color: hsl(0 0% 98%);
      display: grid;
      place-items: center;
      padding: 1.5rem;
    }
    .container {
      text-align: center;
      padding: 2rem 1.5rem;
      border: 1px solid hsl(0 0% 14.9%);
      border-radius: 0.9rem;
      max-width: 28rem;
      width: 100%;
      background: hsl(0 0% 4%);
      box-shadow: 0 25px 50px -12px rgba(0,0,0,.35);
    }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem; }
    .code { font-size: 0.75rem; color: hsl(0 0% 60%); margin-bottom: 1.25rem; }
    .message { font-size: 0.95rem; opacity: 0.85; margin-bottom: 1.5rem; line-height: 1.6; }
    .info {
      margin-top: 1.5rem;
      padding: 0.75rem 1rem;
      background: hsl(0 0% 8%);
      border: 1px solid hsl(0 0% 14.9%);
      border-radius: 0.75rem;
      display: grid;
      gap: 0.5rem;
    }
    .row {
      display: grid;
      grid-template-columns: 1fr auto;
      padding: 0.5rem 0;
      border-bottom: 1px dashed hsl(0 0% 15%);
    }
    .row:last-child { border-bottom: 0; }
    .label { color: hsl(0 0% 65%); font-size: 0.85rem; text-align: left; }
    .value { font-size: 0.85rem; font-family: monospace; }
    .footer {
      margin-top: 1.5rem;
      padding-top: 1rem;
      border-top: 1px solid hsl(0 0% 14.9%);
      font-size: 0.75rem;
      opacity: 0.5;
    }
    a { color: hsl(0 0% 98%); text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${safeDisplayTitle}</h1>
    <div class="code">${status} ${getErrorLabel(status)}</div>
    <p class="message">${safeDisplayMessage}</p>
    <div class="info">
      <div class="row"><div class="label">Country</div><div class="value">${safeCountryCode}</div></div>
      <div class="row"><div class="label">Ray ID</div><div class="value">${safeRayId}</div></div>
    </div>
    <div class="footer">
      <a href="${siteUrl}">${siteName}</a>
    </div>
  </div>
</body>
</html>`, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';`,
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    }
  });
}

function getErrorStatus(errorType) {
  if (errorType === 'notfound') return 404;
  if (errorType === 'error') return 502;
  return 403;
}

function getErrorLabel(status) {
  if (status === 404) return 'NOT FOUND';
  if (status === 502) return 'BAD GATEWAY';
  return 'FORBIDDEN';
}


// ===================================================
// DOMAIN ALLOWLIST
// ===================================================

function isDomainAllowed(refererDomain, allowedDomains) {
  for (const allowed of allowedDomains) {
    if (refererDomain === allowed) {
      return true;
    }
    if (refererDomain.endsWith('.' + allowed)) {
      return true;
    }
  }
  return false;
}

function isSearchBot(userAgent) {
  const ua = userAgent.toLowerCase();
  const bots = [
    'googlebot',
    'bingbot',
    'slurp',
    'duckduckbot',
    'baiduspider',
    'yandexbot',
    'facebot',
    'twitterbot',
    'linkedinbot',
    'whatsapp',
    'telegrambot',
    'discordbot',
    'slackbot',
  ];
  return bots.some(bot => ua.includes(bot));
}

function generate404Response(request) {
  if (shouldReturnImageCompatibleError(request)) {
    return generateImageCompatibleErrorResponse(404);
  }

  const rayId = request.headers.get('cf-ray') || 'Unknown';
  const nonce = generateNonce();
  const safeRayId = escapeHtml(rayId);

  return new Response(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex, nofollow">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 - Not Found</title>
  <style nonce="${nonce}">
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      font-family: Inter, system-ui, sans-serif;
      background: hsl(0 0% 3.9%);
      color: hsl(0 0% 98%);
      display: grid;
      place-items: center;
      padding: 1.5rem;
    }
    .container {
      text-align: center;
      padding: 2rem 1.5rem;
      border: 1px solid hsl(0 0% 14.9%);
      border-radius: 0.9rem;
      max-width: 28rem;
      width: 100%;
      background: hsl(0 0% 4%);
      box-shadow: 0 25px 50px -12px rgba(0,0,0,.35);
    }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem; }
    .code { font-size: 0.75rem; color: hsl(0 0% 60%); margin-bottom: 1.25rem; }
    .message { font-size: 0.95rem; opacity: 0.85; line-height: 1.6; }
    .footer {
      margin-top: 1.5rem;
      padding-top: 1rem;
      border-top: 1px solid hsl(0 0% 14.9%);
      font-size: 0.7rem;
      opacity: 0.3;
      font-family: monospace;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Not Found</h1>
    <div class="code">404</div>
    <p class="message">The requested resource could not be found.</p>
    <div class="footer">${safeRayId}</div>
  </div>
</body>
</html>`, {
    status: 404,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';`,
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    }
  });
}

function shouldReturnImageCompatibleError(request) {
  const url = new URL(request.url);
  const secFetchDest = request.headers.get('Sec-Fetch-Dest') || '';
  const secFetchMode = request.headers.get('Sec-Fetch-Mode') || '';
  const accept = request.headers.get('Accept') || '';

  if (secFetchMode === 'navigate' || secFetchDest === 'document' || accept.includes('text/html')) {
    return false;
  }

  return secFetchDest === 'image' || isLikelyImageRequest(url.pathname, secFetchDest);
}

function generateImageCompatibleErrorResponse(status) {
  const transparentSvg =
    '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1" viewBox="0 0 1 1"></svg>';

  return new Response(transparentSvg, {
    status,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    }
  });
}

function escapeHtml(value) {
  return escapeHtmlAttribute(value).replace(/'/g, '&#39;');
}

function getSafeSiteUrl(value) {
  if (!value) return '#';
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : '#';
  } catch (_) {
    return '#';
  }
}
