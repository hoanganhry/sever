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

## Keep data across Render restarts

Render's default filesystem is temporary. To keep keys, packages, users, devices, UDID records, and backups after a restart or deploy, attach a persistent disk to the web service (available on paid Render instance plans).

If the current service already has data, migrate it before switching directories:

1. Wait for this version to deploy, then open `https://sever-1niw.onrender.com/admin/data-migration` and download the JSON backup while the old data is still available.
2. In Render, open the `sever-1niw` web service and add a persistent disk with mount path `/var/data` (requires a paid instance plan).
3. In the service's Environment settings, set `DATA_DIR` to `/var/data`, save, and wait for the deploy to finish.
4. Open the data migration page again, select the downloaded JSON file, and restore it into the new empty disk. Keep the backup file private; it contains application data and configuration.
5. Confirm the key, package, and device lists are present before resuming normal use.

The server stores its JSON data files and backups under `DATA_DIR`. The UDID callback uses the same directory. Setting `DATA_DIR` without attaching a persistent disk does not preserve files. A newly mounted disk starts empty, and the old temporary files are not copied automatically. The import tool refuses to overwrite a data directory that already contains records.

## Encrypted private Git backup

The service can also encrypt and sync its data snapshot to the private repository `hoanganhry/sever-data-backup`. This is a backup/restore fallback; a Render persistent disk remains preferable for primary storage.

1. Create a fine-grained GitHub token limited to `hoanganhry/sever-data-backup`, with **Contents: Read and write** permission.
2. In Render's service Environment settings, add:
   - `GITHUB_DATA_REPO` = `hoanganhry/sever-data-backup`
   - `GITHUB_DATA_BRANCH` = `main`
   - `GITHUB_DATA_TOKEN` = the fine-grained token
   - `GITHUB_DATA_ENCRYPTION_KEY` = a newly generated 64-character hexadecimal key, for example from `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
3. Keep a separate offline copy of the encryption key. The private Git backup cannot be decrypted without it. Never commit either secret to a repository.
4. Save the environment settings and wait for Render to redeploy. On startup the service restores an encrypted Git snapshot before creating empty JSON files and confirms a baseline snapshot before accepting requests. When Git backup is configured, each successful local data write waits for GitHub sync; if sync fails, the API reports an error instead of claiming that the data was safely backed up.
5. Check backup health with the authenticated `GET /api/admin/data-store/status` endpoint. It reports whether backup is enabled, the latest sync/restore times, and any last error; it never returns the GitHub token or encryption key.

The backup is AES-256-GCM encrypted before it is sent to GitHub. If the token or encryption key is missing or invalid, the service logs a clear warning or startup error instead of silently replacing an unreadable backup with empty data. A Git backup is not a substitute for keeping the repository private or for an offline copy of its encryption key.

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
