// udid-routes.js
// Luồng lấy UDID thật của iPhone/iPad qua Configuration Profile (Profile Service).
// Cách hoạt động:
//   1) GET  /api/udid/profile   -> trả về file .mobileconfig, thiết bị tải & cài
//   2) Khi cài, iOS tự POST một gói CMS (ký) chứa UDID về /api/udid/callback
//   3) Server giải mã CMS, lấy UDID, lưu lại, trả về 1 profile "hoàn tất" rỗng
//   4) GET  /api/udid/status?session=xxx -> frontend poll để lấy UDID vừa capture
//
// Yêu cầu: npm install node-forge uuid
// Yêu cầu: server phải chạy HTTPS với chứng chỉ hợp lệ (Render đã có sẵn) —
//          iOS sẽ từ chối gửi UDID về nếu domain không phải HTTPS thật.

const express = require('express');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const router = express.Router();

const DB_FILE = path.join(__dirname, 'udid_log.json');
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');

function loadRecords() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return []; }
}
function saveRecord(record) {
  const records = loadRecords();
  records.push(record);
  fs.writeFileSync(DB_FILE, JSON.stringify(records, null, 2));
}
function findRecord(session) {
  return loadRecords().find(r => r.session === session);
}

// đơn giản: đọc <key>X</key><string>Y</string> từ plist XML thô, khỏi cần thư viện plist
function extractPlistString(xml, key) {
  const re = new RegExp(`<key>${key}</key>\\s*<string>(.*?)</string>`, 's');
  const m = xml.match(re);
  return m ? m[1] : null;
}

module.exports = function udidRoutes(publicBaseUrl) {

  // Bước 1: sinh file cấu hình để thiết bị cài
  router.get('/api/udid/profile', (req, res) => {
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
    res.set('Content-Disposition', 'attachment; filename="register.mobileconfig"');
    res.send(plist);
  });

  // Bước 2: iOS POST CMS (DER, ký) chứa UDID về đây. Cần raw body, KHÔNG qua body-parser JSON.
  router.post('/api/udid/callback', express.raw({ type: '*/*', limit: '2mb' }), (req, res) => {
    const session = req.query.session || 'unknown';
    let plistXml = null;

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

    const record = {
      session,
      udid: plistXml ? extractPlistString(plistXml, 'UDID') : null,
      product: plistXml ? extractPlistString(plistXml, 'PRODUCT') : null,
      version: plistXml ? extractPlistString(plistXml, 'VERSION') : null,
      capturedAt: new Date().toISOString(),
      ip: req.ip
    };
    saveRecord(record);

    // QUAN TRỌNG: PayloadContent không được để rỗng, nếu không iOS báo
    // "Cài đặt hồ sơ thất bại - Hồ sơ trống". Dùng 1 payload Restrictions
    // không đặt khóa giới hạn nào -> hợp lệ nhưng không thay đổi gì trên máy.
    const finalUUID = uuidv4().toUpperCase();
    const payloadUUID = uuidv4().toUpperCase();
    const finalPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.applicationaccess</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.authapi.restrictions.${session}</string>
      <key>PayloadUUID</key>
      <string>${payloadUUID}</string>
      <key>PayloadDisplayName</key>
      <string>Hoan tat dang ky</string>
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
    res.set('Content-Type', 'application/x-apple-aspen-config');
    res.send(finalPlist);
  });

  // Bước 3: frontend poll để lấy kết quả
  router.get('/api/udid/status', (req, res) => {
    const record = findRecord(req.query.session);
    if (!record) return res.json({ found: false });
    res.json({ found: true, ...record });
  });

  return router;
};
