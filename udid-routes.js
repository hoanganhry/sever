// udid-routes.js
// Luồng lấy UDID thật của iPhone/iPad qua Configuration Profile (Profile Service).
// Cách hoạt động:
//   1) GET  /api/udid/profile   -> trả về file .mobileconfig, thiết bị tải & cài
//   2) Khi cài, iOS tự POST một gói CMS (ký) chứa UDID về /api/udid/callback
//   3) Server giải mã CMS, lưu UDID, rồi trả profile hoàn tất có chữ ký CMS
//   4) GET  /api/udid/status?session=xxx -> frontend poll để lấy UDID vừa capture
//
// Yêu cầu: npm install node-forge uuid
// Yêu cầu: server phải chạy HTTPS với chứng chỉ hợp lệ (Render đã có sẵn) —
//          iOS sẽ từ chối gửi UDID về nếu domain không phải HTTPS thật.

const express = require('express');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const GET_KEY_FLOW_TTL_MS = 10 * 60 * 1000;
const getKeyFlows = new Map();

const DB_FILE = path.join(__dirname, 'udid_log.json');
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');
let profileSigningIdentity = null;

function loadRecords() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return []; }
}

function mergeDuplicateUdids(records) {
  const merged = [];
  const indexByUdid = new Map();
  records.forEach(record => {
    if (!record.udid) {
      merged.push(record);
      return;
    }
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
  return loadRecords().find(r => r.session === session);
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

// đơn giản: đọc <key>X</key><string>Y</string> từ plist XML thô, khỏi cần thư viện plist
function extractPlistString(xml, key) {
  const re = new RegExp(`<key>${key}</key>\\s*<string>(.*?)</string>`, 's');
  const m = xml.match(re);
  return m ? m[1] : null;
}

function createSignedProfile(profile) {
  if (!profileSigningIdentity) {
    const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    const certificate = forge.pki.createCertificate();
    certificate.publicKey = keys.publicKey;
    certificate.serialNumber = crypto.randomBytes(16).toString('hex');
    certificate.validity.notBefore = new Date(Date.now() - 60_000);
    certificate.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    certificate.setSubject([
      { name: 'commonName', value: 'AuthAPI Profile Service' },
      { name: 'organizationName', value: 'AuthAPI' }
    ]);
    certificate.setIssuer(certificate.subject.attributes);
    certificate.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true }
    ]);
    certificate.sign(keys.privateKey, forge.md.sha256.create());
    profileSigningIdentity = { certificate, privateKey: keys.privateKey };
  }

  const signedData = forge.pkcs7.createSignedData();
  signedData.content = forge.util.createBuffer(profile, 'utf8');
  signedData.addSigner({
    key: profileSigningIdentity.privateKey,
    certificate: profileSigningIdentity.certificate,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() }
    ]
  });
  signedData.sign();
  return Buffer.from(forge.asn1.toDer(signedData.toAsn1()).getBytes(), 'binary');
}

module.exports = function udidRoutes(publicBaseUrl, getUdidPageUrl) {

  // Bước 1: sinh file cấu hình để thiết bị cài
  router.get('/api/udid/profile', (req, res) => {
    console.info('[UDID] Profile Service profile requested');
    const session = req.query.session || uuidv4();
    const callbackUrl = `${publicBaseUrl}/api/udid/callback?session=${session}`;
    const payloadUUID = uuidv4().toUpperCase();

    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <dict>
    <key>URL</key>
    <string>${callbackUrl}</string>
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
  <string>${payloadUUID}</string>
  <key>PayloadIdentifier</key>
  <string>com.authapi.profileservice.${session}</string>
  <key>PayloadType</key>
  <string>Profile Service</string>
</dict>
</plist>`;

    res.set('Content-Type', 'application/x-apple-aspen-config');
    res.send(plist);
  });

  // Bước 2: iOS POST CMS (DER, ký) chứa UDID về đây. Cần raw body, KHÔNG qua body-parser JSON.
  router.post('/api/udid/callback', express.raw({ type: '*/*', limit: '2mb' }), (req, res) => {
    const bodyBytes = Buffer.isBuffer(req.body) ? req.body.length : 0;
    console.info(`[UDID] Callback received (${bodyBytes} bytes; ${req.get('content-type') || 'unknown content type'})`);
    res.on('finish', () => {
      console.info(`[UDID] Callback finished with HTTP ${res.statusCode}`);
    });

    const session = req.query.session || 'unknown';
    let plistXml = null;

    // Bước 2a: đọc dữ liệu thiết bị gửi về (không được để lỗi này làm mất phản hồi)
    try {
      const buf = req.body;
      const asText = buf.toString('utf8');
      const xmlStart = asText.indexOf('<?xml');
      const xmlEnd = asText.indexOf('</plist>');

      if (xmlStart !== -1 && xmlEnd !== -1) {
        // Trường hợp phổ biến: profile chưa ký -> iOS gửi thẳng plist XML dạng text
        plistXml = asText.substring(xmlStart, xmlEnd + '</plist>'.length);
      } else {
        // Trường hợp profile đã ký -> dữ liệu là CMS/PKCS7 nhị phân
        const p7Asn1 = forge.asn1.fromDer(forge.util.createBuffer(buf.toString('binary')));
        const p7 = forge.pkcs7.messageFromAsn1(p7Asn1);
        const contentAsn1 = p7.rawCapture.content;
        const rawValue = Array.isArray(contentAsn1.value)
          ? contentAsn1.value.map(v => v.value).join('')
          : contentAsn1.value;
        plistXml = forge.util.decodeUtf8(rawValue);
      }
    } catch (err) {
      console.error('UDID callback parse error:', err.message);
      plistXml = null;
    }

    // Bước 2b: lưu log (không được để lỗi ghi file làm mất phản hồi cho thiết bị)
    try {
      const record = {
        session,
        udid: plistXml ? extractPlistString(plistXml, 'UDID') : null,
        product: plistXml ? extractPlistString(plistXml, 'PRODUCT') : null,
        version: plistXml ? extractPlistString(plistXml, 'VERSION') : null,
        capturedAt: new Date().toISOString(),
        ip: req.ip
      };
      saveRecord(record);
      console.info(`[UDID] Callback parsed; UDID ${record.udid ? 'captured' : 'missing'}`);
    } catch (err) {
      console.error('UDID callback save error:', err.message);
    }

    // Bước 2c: LUÔN trả lời thiết bị bằng 1 profile hợp lệ, dù bước trên có lỗi hay không.
    // QUAN TRỌNG: PayloadContent không được để rỗng, nếu không iOS báo
    // "Cài đặt hồ sơ thất bại - Hồ sơ trống". Dùng 1 payload Restrictions
    // không đặt khóa giới hạn nào -> hợp lệ nhưng không thay đổi gì trên máy.
    try {
      const finalUUID = uuidv4().toUpperCase();
      const payloadUUID = uuidv4().toUpperCase();
      // Restrictions (com.apple.applicationaccess) bị iOS đời mới chặn khi cài thủ công
      // trên máy chưa "supervised". Dùng Web Clip thay thế - loại payload này luôn được
      // phép cài thủ công, chỉ tạo 1 icon nhỏ trên màn hình chính, có thể xóa bất cứ lúc nào.
      const finalPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.webClip.managed</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.authapi.webclip.${session}</string>
      <key>PayloadUUID</key>
      <string>${payloadUUID}</string>
      <key>PayloadDisplayName</key>
      <string>AuthAPI</string>
      <key>Label</key>
      <string>AuthAPI</string>
      <key>URL</key>
      <string>${getUdidPageUrl}</string>
      <key>IsRemovable</key>
      <true/>
      <key>FullScreen</key>
      <false/>
      <key>Precomposed</key>
      <true/>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>Dang ky thiet bi hoan tat</string>
  <key>PayloadIdentifier</key>
  <string>com.authapi.complete.${session}</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${finalUUID}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadRemovalDisallowed</key>
  <false/>
</dict>
</plist>`;
      res.status(200)
        .set('Content-Type', 'application/x-apple-aspen-config')
        .send(createSignedProfile(finalPlist));
    } catch (err) {
      // Không trả thành công giả khi không thể tạo profile đã ký.
      console.error('UDID callback final response error:', err.message);
      const fallbackPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.webClip.managed</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>com.authapi.webclip.fallback</string>
<key>PayloadUUID</key><string>${uuidv4().toUpperCase()}</string>
<key>PayloadDisplayName</key><string>AuthAPI</string>
<key>Label</key><string>AuthAPI</string>
<key>URL</key><string>${getUdidPageUrl}</string>
<key>IsRemovable</key><true/>
</dict></array><key>PayloadDisplayName</key><string>Hoan tat</string>
<key>PayloadIdentifier</key><string>com.authapi.complete.fallback</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>${uuidv4().toUpperCase()}</string>
<key>PayloadVersion</key><integer>1</integer></dict></plist>`;
      res.status(500).json({ success: false, message: 'Không thể tạo profile hoàn tất cho thiết bị.' });
    }
  });

  // Bước 3: frontend poll để lấy kết quả
  router.get('/api/udid/status', (req, res) => {
    const record = findRecord(req.query.session);
    if (!record) return res.json({ found: false });
    res.json({ found: true, ...record });
  });

  // Thiết bị tự tra key ĐANG liên kết với chính UDID của nó (chỉ cần biết UDID của mình,
  // không thấy được UDID/key của thiết bị khác vì phải khớp đúng chuỗi UDID)
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

  // Danh sách toàn bộ UDID đã lấy được (mới nhất trước), kèm key đã liên kết (nếu có)
  // -> dùng cho trang quản trị index.html, không public trong udid.html
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

  // Ghi lại UDID này đang dùng key nào (gọi sau khi verify-key ở server chính thành công)
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
