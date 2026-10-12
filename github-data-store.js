const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const FILES = [
  ['keys', 'keys.json', 'array'],
  ['packages', 'packages.json', 'array'],
  ['users', 'users.json', 'array'],
  ['config', 'config.json', 'object'],
  ['devices', 'devices.json', 'array'],
  ['udidRecords', 'udid_log.json', 'array'],
  ['activityLogs', 'activity_logs.json', 'array'],
  ['aiLogs', 'ai_logs.json', 'array']
];

const repository = process.env.GITHUB_DATA_REPO || '';
const token = process.env.GITHUB_DATA_TOKEN || '';
const branch = process.env.GITHUB_DATA_BRANCH || 'main';
const encryptionKeyHex = process.env.GITHUB_DATA_ENCRYPTION_KEY || '';
const filePath = 'data/authapi-data.json.enc';
const apiUrl = `https://api.github.com/repos/${repository}/contents/${filePath}`;

let encryptionKey;
let syncTimer = null;
let syncInProgress = null;
let syncAgain = false;
const state = {
  status: 'disabled',
  lastAttemptAt: null,
  lastSuccessAt: null,
  lastRestoreAt: null,
  lastError: null
};

if (token || repository || encryptionKeyHex) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository) || !token || !/^[a-f0-9]{64}$/i.test(encryptionKeyHex)) {
    throw new Error('Configure GITHUB_DATA_REPO, GITHUB_DATA_TOKEN, and a 64-character hex GITHUB_DATA_ENCRYPTION_KEY together.');
  }
  encryptionKey = Buffer.from(encryptionKeyHex, 'hex');
}

function isConfigured() {
  return Boolean(encryptionKey);
}

function getStatus() {
  return {
    ...state,
    enabled: isConfigured(),
    repository: isConfigured() ? repository : null,
    branch: isConfigured() ? branch : null
  };
}

function headers() {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json'
  };
}

async function readLocalData(dataDir) {
  const data = {};
  for (const [key, filename, type] of FILES) {
    let value;
    try {
      const contents = await fs.readFile(path.join(dataDir, filename), 'utf8');
      value = JSON.parse(contents);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      value = type === 'array' ? [] : {};
    }
    if (type === 'array' && !Array.isArray(value)) {
      throw new Error(`${filename} must contain a JSON array before backup.`);
    }
    if (type === 'object' && (!value || typeof value !== 'object' || Array.isArray(value))) {
      throw new Error(`${filename} must contain a JSON object before backup.`);
    }
    data[key] = value;
  }
  return data;
}

function hasLocalRecords(data) {
  return ['keys', 'packages', 'users', 'devices', 'udidRecords']
    .some(key => data[key].length > 0);
}

function encrypt(data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify({ version: 1, data }), 'utf8'),
    cipher.final()
  ]);
  return Buffer.from(JSON.stringify({
    version: 1,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  }), 'utf8');
}

function decrypt(value) {
  const envelope = JSON.parse(value.toString('utf8'));
  if (envelope.version !== 1 || !envelope.iv || !envelope.tag || !envelope.ciphertext) {
    throw new Error('Private Git data backup has an invalid encrypted format.');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final()
  ]).toString('utf8');
  const snapshot = JSON.parse(plaintext);
  if (snapshot.version !== 1 || !snapshot.data || typeof snapshot.data !== 'object') {
    throw new Error('Private Git data backup payload is invalid.');
  }

  for (const [key, filename, type] of FILES) {
    const item = snapshot.data[key];
    if (type === 'array' && !Array.isArray(item)) {
      throw new Error(`Private Git data backup has invalid ${filename}.`);
    }
    if (type === 'object' && (!item || typeof item !== 'object' || Array.isArray(item))) {
      throw new Error(`Private Git data backup has invalid ${filename}.`);
    }
  }
  return snapshot.data;
}

async function getRemoteFile() {
  const response = await fetch(`${apiUrl}?ref=${encodeURIComponent(branch)}`, {
    headers: headers(),
    signal: AbortSignal.timeout(15000)
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`GitHub data backup read failed (HTTP ${response.status}).`);
  }
  const result = await response.json();
  if (!result.sha || typeof result.content !== 'string') {
    throw new Error('GitHub data backup response did not contain file content and SHA.');
  }
  return {
    sha: result.sha,
    content: Buffer.from(result.content.replace(/\s/g, ''), 'base64')
  };
}

async function restore(dataDir) {
  if (!isConfigured()) {
    state.status = 'disabled';
    state.lastError = 'Git backup credentials are not configured.';
    console.warn('[Git data] Persistence is disabled; configure the private Git backup environment variables.');
    return false;
  }

  state.status = 'restoring';
  state.lastError = null;
  try {
    const localData = await readLocalData(dataDir);
    if (hasLocalRecords(localData)) {
      state.status = 'local-data-preserved';
      console.warn('[Git data] Local records already exist; preserving them instead of restoring over them.');
      return false;
    }

    const remote = await getRemoteFile();
    if (!remote) {
      state.status = 'no-backup';
      console.info('[Git data] No backup exists yet; starting with the current data directory.');
      return false;
    }

    const restoredData = decrypt(remote.content);
    const stagingDir = path.join(dataDir, `.git-data-restore-${crypto.randomUUID()}`);
    await fs.mkdir(stagingDir, { recursive: false });
    const installed = [];

    try {
      for (const [key, filename] of FILES) {
        const stagedFile = path.join(stagingDir, filename);
        await fs.writeFile(stagedFile, JSON.stringify(restoredData[key], null, 2), 'utf8');
      }

      for (const [key, filename] of FILES) {
        const destination = path.join(dataDir, filename);
        const stagedFile = path.join(stagingDir, filename);
        const previousFile = path.join(stagingDir, `${filename}.previous`);
        let hadPrevious = true;
        try {
          await fs.access(destination);
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
          hadPrevious = false;
        }
        const fileState = { destination, previousFile, hadPrevious, installed: false };
        installed.push(fileState);
        if (hadPrevious) await fs.rename(destination, previousFile);
        await fs.rename(stagedFile, destination);
        fileState.installed = true;
      }
      state.status = 'restored';
      state.lastRestoreAt = new Date().toISOString();
      console.info('[Git data] Restored encrypted data backup from the private repository.');
      return true;
    } catch (error) {
      for (const fileState of installed.reverse()) {
        try {
          if (fileState.installed) await fs.rm(fileState.destination, { force: true });
          if (fileState.hadPrevious) {
            try {
              await fs.access(fileState.previousFile);
              await fs.rename(fileState.previousFile, fileState.destination);
            } catch (restoreError) {
              if (restoreError.code !== 'ENOENT') throw restoreError;
            }
          }
        } catch (rollbackError) {
          console.error('[Git data] Restore rollback failed:', rollbackError.message);
        }
      }
      throw error;
    } finally {
      await fs.rm(stagingDir, { recursive: true, force: true });
    }
  } catch (error) {
    state.status = 'error';
    state.lastError = error.message;
    console.error('[Git data] Restore failed:', error.message);
    throw error;
  }
}

async function pushSnapshot(dataDir) {
  const data = await readLocalData(dataDir);
  const current = await getRemoteFile();
  if (current && JSON.stringify(decrypt(current.content)) === JSON.stringify(data)) {
    return false;
  }
  const content = encrypt(data);

  const requestBody = {
    message: 'Sync encrypted service data',
    content: content.toString('base64'),
    branch
  };
  if (current) requestBody.sha = current.sha;

  const response = await fetch(apiUrl, {
    method: 'PUT',
    headers: headers(),
    body: JSON.stringify(requestBody),
    signal: AbortSignal.timeout(20000)
  });
  if (response.status === 409 || response.status === 422) {
    throw new Error(`GitHub data backup update conflicted (HTTP ${response.status}); retrying.`);
  }
  if (!response.ok) {
    throw new Error(`GitHub data backup update failed (HTTP ${response.status}).`);
  }
  return true;
}

async function syncNow(dataDir) {
  if (!isConfigured()) {
    state.status = 'disabled';
    state.lastError = 'Git backup credentials are not configured.';
    return false;
  }
  if (syncInProgress) {
    syncAgain = true;
    return syncInProgress;
  }

  state.status = 'syncing';
  state.lastAttemptAt = new Date().toISOString();
  state.lastError = null;
  syncInProgress = (async () => {
    let changed = false;
    try {
      do {
        syncAgain = false;
        for (let attempt = 1; attempt <= 3; attempt++) {
          try {
            changed = (await pushSnapshot(dataDir)) || changed;
            break;
          } catch (error) {
            if (attempt === 3) throw error;
            console.warn(`[Git data] Sync attempt ${attempt} failed: ${error.message}`);
            await new Promise(resolve => setTimeout(resolve, attempt * 1000));
          }
        }
      } while (syncAgain);
      state.status = 'synced';
      state.lastSuccessAt = new Date().toISOString();
      if (changed) console.info('[Git data] Encrypted data backup updated.');
      return changed;
    } catch (error) {
      state.status = 'error';
      state.lastError = error.message;
      console.error('[Git data] Backup failed:', error.message);
      throw error;
    } finally {
      syncInProgress = null;
    }
  })();
  return syncInProgress;
}

function scheduleSync(dataDir, reason = 'data update') {
  if (!isConfigured()) return;
  if (syncTimer) clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    syncTimer = null;
    syncNow(dataDir).catch(error => {
      console.error(`[Git data] Backup failed after ${reason}:`, error.message);
    });
  }, 3000);
  syncTimer.unref?.();
}

module.exports = { getStatus, isConfigured, restore, scheduleSync, syncNow };
