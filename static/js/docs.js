// Swagger UI initialisation.
//
// This lives in a file rather than an inline <script> because the app's
// Content-Security-Policy is `default-src 'self'` with no 'unsafe-inline', so
// an inline script body would be blocked outright.
//
// The plain bundle is used rather than the standalone preset: the preset's top
// bar carries a spec-URL input, which would let a visitor point try-it-out at
// an arbitrary host.
window.addEventListener('DOMContentLoaded', function () {
  SwaggerUIBundle({
    // Relative to <base>, so requests go to whatever origin/prefix served this page.
    url: 'api/v1/openapi.json',
    dom_id: '#swagger-ui',
    presets: [SwaggerUIBundle.presets.apis],
    layout: 'BaseLayout',
    deepLinking: true,
    tryItOutEnabled: true,
    // The endpoints are simple enough that a schema dump underneath each
    // one is not needed.
    defaultModelsExpandDepth: -1,
    // The spec declares no securitySchemes, so the Authorize dialog never
    // appears and this is already the default; set explicitly so it stays off
    // if a securityScheme is ever added. It governs only that dialog's
    // credentials -- it says nothing about, and does not persist, the request
    // bodies (including plaintext passwords) submitted via try-it-out.
    persistAuthorization: false,
  });
});
