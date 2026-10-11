# AuthAPI

Personal license-key API and dashboard.

## Run locally

1. Install Node.js 18 or newer.
2. Install dependencies with `npm install`.
3. Set the environment variables described below.
4. Start the API with `npm start`.
5. Open `http://localhost:10000`.

## Environment variables

Set secrets in the hosting provider's environment-variable settings. Do not commit real values.

- `JWT_SECRET`: a long, random secret used to sign authentication tokens.
- `HMAC_SECRET`: a long, random secret used to sign license keys. Keep it stable or existing key signatures will no longer validate.
- `DASHBOARD_USERNAME`: the private dashboard login username.
- `DASHBOARD_PASSWORD`: a strong, private dashboard login password. Never commit it to the repository.

Set both dashboard credentials in the hosting provider's private environment-variable settings. The server checks them without exposing their values in the page or API responses.

The Get UDID page is served directly from the API at `/get-key`; `/udid.html` redirects to this friendly path. Public key-verification, app-package-check, Get UDID flow, profile callback, and device-registration endpoints remain available to client apps.

When the dashboard's **Thiết bị** tab is open, its UDID list refreshes automatically every two seconds so newly captured devices appear without a manual refresh.

Optional AI provider credentials:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

AI features remain unavailable when their provider credential is not configured.

## App package checks

Create and manage app packages in the dashboard's **Gói ứng dụng** tab after signing in with the private dashboard username and password. Package-management APIs require the same credentials; public app package lookup remains available to client apps. Assign each license key to its intended package when creating the key. The app can start a Get Key registration with `POST /api/udid/start` and JSON `{ "key": "<issued-key>", "packageId": "<package-id>" }`. On success, open the returned `registrationUrl` in Safari. The URL uses the friendly `/get-key` path and contains a random, one-time flow token, not the key; the flow expires after 10 minutes. The page installs the UDID profile, then verifies and links the key to that device automatically. Successful `POST /api/verify-key` calls also link any previously captured UDID to the verified key. Duplicate captures of the same UDID are consolidated into one device record. On iPhone/iPad the page captures the actual UDID. The key list shows captured model and iOS details when available. The app should call `POST /api/app/check-package` with its package ID and key when it starts and periodically while running. It must send that same package ID to `POST /api/verify-key`.

When a package is disabled, the check endpoint returns `allowed: false` with a configured message and optional update URL. The app should show the message and safely block protected features; it should not crash.

Keys can be created with a fixed duration or set to **Vĩnh viễn**. Permanent keys are stored with `is_permanent: true` and `expires_at: null`; verification, app-package checks, device lookups, statistics, and expired-key cleanup treat them as active without an expiration date. `POST /api/key-info` returns the key type, package, creation and expiration details, activation count/limit, and verification status for the app to display after successful validation.

The key list's three-dot menu can edit a key's type, package, device limit, and expiration, or disable, re-enable, and delete that key. `PATCH /api/admin/keys/:keyCode` accepts `type`, `packageId`, `allowed_devices`, `expiresAt`, and/or `is_disabled`; use `expiresAt: null` for a permanent key. Disabled keys are rejected by key verification, app-package checks, and Get Key/device registration. Dashboard management endpoints require the private dashboard credentials; client verification and Get Key endpoints remain public.
