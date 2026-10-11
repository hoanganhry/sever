// udid-routes.js (đã sửa)
// Luồng: GET /api/udid/profile -> iOS cài -> iOS POST CMS chứa UDID về /api/udid/callback
//        -> server lưu UDID -> trả HTTP 301 về trang /get-key -> trang hoàn tất liên kết key.
// Yêu cầu: npm install node-forge uuid

const express = require('express');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const GET_KEY_FLOW_TTL_MS = 10 * 60 * 1000;
const getKeyFlows = new Map();
const failedSessions = new Map(); // session -> lý do lỗi (chỉ để báo cho trang)

// Dùng cùng DATA_DIR với server.js để dữ liệu nằm trên Persistent Disk (nếu có)
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB_FILE = path.join(DATA_DIR, 'udid_log.json');
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');

const SESSION_RE = /^[A-Za-z0-9-]{8,128}$/;

function loadRecords() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return []; }
}

function mergeDuplicateUdids(records) {
  const merged = [];
  const indexByUdid = new Map();
  records.forEach(record => {
    if (!record.udid) { merged.push(record); return; }
    const existingIndex = indexByUdid.get(record.udid);
    if (existingIndex === undefined) {
      indexByUdid.set(record.udid, merged.length);
      merged.push(record);
      return;
    }
    const existing = merged[existingIndex];
    merged[existingIndex] = {
      ...existing,
      ...record,
      linkedKey: record.linkedKey || existing.linkedKey,
      linkedAt: record.linkedAt || existing.linkedAt
    };
  });
  return merged;
}

function saveRecord(record) {
  let records = mergeDuplicateUdids(loadRecords());
  if (record.udid) {
    const previous = [...records].reverse().find(item => item.udid === record.udid);
    if (previous) {
      record.linkedKey = previous.linkedKey || record.linkedKey;
      record.linkedAt = previous.linkedAt || record.linkedAt;
    }
    records = records.filter(item => item.udid !== record.udid);
  }
  records.push(record);
  fs.writeFileSync(DB_FILE, JSON.stringify(mergeDuplicateUdids(records), null, 2));
}

function findRecord(session) {
  return loadRecords().find(r => r.session === session && r.udid);
}

function updateRecordByUdid(udid, patch, session = null) {
  const records = mergeDuplicateUdids(loadRecords());
  for (let i = records.length - 1; i >= 0; i--) {
    if (records[i].udid === udid && (!session || records[i].session === session)) {
      Object.assign(records[i], patch);
      fs.writeFileSync(DB_FILE, JSON.stringify(records, null, 2));
      return records[i];
    }
  }
  return null;
}

function linkDeviceToKey(udid, key) {
  return updateRecordByUdid(udid, { linkedKey: key, linkedAt: new Date().toISOString() });
}

function pruneGetKeyFlows() {
  const now = Date.now();
  for (const [flowId, flow] of getKeyFlows) {
    if (flow.expiresAt <= now) getKeyFlows.delete(flowId);
  }
}

function createGetKeyFlow(key, packageId) {
  pruneGetKeyFlows();
  const flowId = crypto.randomBytes(32).toString('hex');
  getKeyFlows.set(flowId, {
    key,
    packageId: packageId || '',
    expiresAt: Date.now() + GET_KEY_FLOW_TTL_MS
  });
  return flowId;
}

function getGetKeyFlow(flowId) {
  pruneGetKeyFlows();
  return getKeyFlows.get(flowId) || null;
}

function completeGetKeyFlow(flowId) {
  return getKeyFlows.delete(flowId);
}

function xmlEscape(value) {
  return String(value).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]
  ));
}

function extractPlistString(xml, key) {
  const re = new RegExp(`<key>${key}</key>\\s*<string>(.*?)</string>`, 's');
  const m = xml.match(re);
  return m ? m[1].trim() : null;
}

// Lấy plist XML từ body iOS gửi về (CMS/PKCS7 có chứa plist dạng text, hoặc plist thô)
function extractPlistFromBody(buf) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return null;
  const asText = buf.toString('latin1');
  const xmlStart = asText.indexOf('<?xml');
  const xmlEnd = asText.indexOf('</plist>');
  if (xmlStart !== -1 && xmlEnd !== -1) {
    return asText.substring(xmlStart, xmlEnd + '</plist>'.length);
  }
  // Dự phòng: giải mã CMS bằng node-forge
  try {
    const p7Asn1 = forge.asn1.fromDer(forge.util.createBuffer(buf.toString('binary')));
    const p7 = forge.pkcs7.messageFromAsn1(p7Asn1);
    const contentAsn1 = p7.rawCapture.content;
    const rawValue = Array.isArray(contentAsn1.value)
      ? contentAsn1.value.map(v => v.value).join('')
      : contentAsn1.value;
    return forge.util.decodeUtf8(rawValue);
  } catch (err) {
    console.error('[UDID] forge parse error:', err.message);
    return null;
  }
}

module.exports = function udidRoutes(publicBaseUrl, getUdidPageUrl) {
  // Nếu bạn KHÔNG đặt PUBLIC_BASE_URL trên Render, tự suy ra từ request (ép https).
  function resolveBase(req) {
    if (process.env.PUBLIC_BASE_URL) return publicBaseUrl;
    const proto = (req.get('x-forwarded-proto') || 'https').split(',')[0].trim();
    return `${proto === 'http' ? 'https' : proto}://${req.get('host')}`;
  }

  // Log mọi request /api/udid/* (router này nằm TRƯỚC logger chung của server.js nên nếu không có dòng này sẽ không thấy log)
  router.use('/api/udid', (req, res, next) => {
    console.info(`[UDID] ${req.method} ${req.path} ct=${req.get('content-type') || '-'}`);
    next();
  });

  // Bước 1: file cấu hình để thiết bị cài
  router.get('/api/udid/profile', (req, res) => {
    const requested = typeof req.query.session === 'string' ? req.query.session : '';
    const session = SESSION_RE.test(requested) ? requested : uuidv4();
    const callbackUrl = `${resolveBase(req)}/api/udid/callback?session=${session}`;
    console.info('[UDID] callbackUrl =', callbackUrl);

    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <dict>
    <key>URL</key>
    <string>${xmlEscape(callbackUrl)}</string>
    <key>DeviceAttributes</key>
    <array>
      <string>UDID</string>
      <string>VERSION</string>
      <string>PRODUCT</string>
    </array>
  </dict>
  <key>PayloadOrganization</key>
  <string>AuthAPI</string>
  <key>PayloadDisplayName</key>
  <string>Xac thuc thiet bi</string>
  <key>PayloadDescription</key>
  <string>Cai profile nay de lay UDID thiet bi</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadUUID</key>
  <string>${uuidv4().toUpperCase()}</string>
  <key>PayloadIdentifier</key>
  <string>com.authapi.profileservice.${session}</string>
  <key>PayloadType</key>
  <string>Profile Service</string>
</dict>
</plist>`;

    res.set({
      'Content-Type': 'application/x-apple-aspen-config',
      'Content-Disposition': 'attachment; filename="udid.mobileconfig"',
      'Cache-Control': 'no-store'
    });
    res.send(plist);
  });

  // Bước 2: iOS POST UDID về đây. Cần raw body.
  router.post('/api/udid/callback', express.raw({ type: () => true, limit: '2mb' }), (req, res) => {
    const requested = typeof req.query.session === 'string' ? req.query.session : '';
    const session = SESSION_RE.test(requested) ? requested : 'unknown';
    const bodyBytes = Buffer.isBuffer(req.body) ? req.body.length : 0;
    console.info(`[UDID] Callback received (${bodyBytes} bytes)`);

    let udid = null;
    try {
      const plistXml = extractPlistFromBody(req.body);
      if (plistXml) {
        udid = extractPlistString(plistXml, 'UDID');
        if (udid) {
          saveRecord({
            session,
            udid,
            product: extractPlistString(plistXml, 'PRODUCT'),
            version: extractPlistString(plistXml, 'VERSION'),
            capturedAt: new Date().toISOString(),
            ip: req.ip
          });
        }
      }
    } catch (err) {
      console.error('[UDID] callback error:', err.message);
    }
    console.info(`[UDID] UDID ${udid ? 'captured' : 'MISSING'} (session ${session.slice(0, 8)}…)`);
    if (!udid) failedSessions.set(session, 'Không đọc được UDID từ thiết bị.');

    // Apple yêu cầu server trả 301 để Safari tiếp tục mở trang kết quả.
    const target = new URL(getUdidPageUrl);
    if (process.env.PUBLIC_BASE_URL === undefined) {
      const base = new URL(resolveBase(req));
      target.protocol = base.protocol;
      target.host = base.host;
    }
    const flow = getGetKeyFlow(session);
    if (flow) {
      target.searchParams.set('flow', session);
      if (flow.packageId) target.searchParams.set('packageId', flow.packageId);
    } else {
      target.searchParams.set('session', session);
    }
    return res.redirect(301, target.toString());
  });

  // Bước 3: trang poll để lấy kết quả
  router.get('/api/udid/status', (req, res) => {
    res.set('Cache-Control', 'no-store');
    const session = typeof req.query.session === 'string' ? req.query.session : '';
    const record = findRecord(session);
    if (record) return res.json({ found: true, ...record });
    if (failedSessions.has(session)) return res.json({ found: false, failed: true, message: failedSessions.get(session) });
    res.json({ found: false });
  });

  router.get('/api/udid/my-key', (req, res) => {
    const udid = req.query.udid;
    if (!udid) return res.status(400).json({ success: false, message: 'Thiếu udid' });
    const records = loadRecords().filter(r => r.udid === udid && r.linkedKey);
    if (records.length === 0) return res.json({ success: true, linked: false });
    const latest = records[records.length - 1];
    res.json({ success: true, linked: true, key: latest.linkedKey, linkedAt: latest.linkedAt });
  });

  router.get('/api/udid/flow', (req, res) => {
    const flowId = typeof req.query.session === 'string' ? req.query.session : '';
    const flow = getGetKeyFlow(flowId);
    res.set('Cache-Control', 'no-store');
    if (!flow) {
      return res.status(404).json({ success: false, message: 'Phiên Get Key không hợp lệ hoặc đã hết hạn. Hãy bắt đầu lại.' });
    }
    res.json({
      success: true,
      key: flow.key,
      packageId: flow.packageId,
      expiresAt: new Date(flow.expiresAt).toISOString()
    });
  });

  // Danh sách UDID (đã được dashboardPasswordAuth bảo vệ trong server.js)
  router.get('/api/udid/list', (req, res) => {
    try {
      const sourceRecords = loadRecords();
      const mergedRecords = mergeDuplicateUdids(sourceRecords);
      if (mergedRecords.length !== sourceRecords.length) {
        fs.writeFileSync(DB_FILE, JSON.stringify(mergedRecords, null, 2));
      }
      const records = mergedRecords.filter(r => r.udid).reverse();
      res.json({ success: true, count: records.length, devices: records });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  router.post('/api/udid/link-key', express.json(), (req, res) => {
    const { udid, key, flowId } = req.body || {};
    if (!udid || !key) {
      return res.status(400).json({ success: false, message: 'Thiếu udid hoặc key' });
    }
    if (flowId) {
      const flow = getGetKeyFlow(flowId);
      if (!flow || flow.key !== key) {
        return res.status(403).json({ success: false, message: 'Phiên Get Key không hợp lệ hoặc đã hết hạn. Hãy bắt đầu lại.' });
      }
    }
    const updated = updateRecordByUdid(
      udid,
      { linkedKey: key, linkedAt: new Date().toISOString() },
      flowId || null
    );
    if (!updated) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy UDID này trong danh sách đã capture' });
    }
    if (flowId) completeGetKeyFlow(flowId);
    res.json({ success: true, device: updated });
  });

  router.getDeviceRecords = () => mergeDuplicateUdids(loadRecords()).filter(record => record.udid);
  router.linkDeviceToKey = linkDeviceToKey;
  router.createGetKeyFlow = createGetKeyFlow;
  router.getGetKeyFlow = getGetKeyFlow;

  return router;
};
