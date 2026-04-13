// worker.js — File-to-JPG Converter + IONOS S3 Uploader
// Wrangler secrets to set:
//   S3_ENDPOINT      e.g. https://s3-eu-central-1.ionoscloud.com
//   S3_BUCKET        e.g. my-bucket
//   S3_ACCESS_KEY    your IONOS access key
//   S3_SECRET_KEY    your IONOS secret key
//   S3_REGION        e.g. eu-central-1

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return new Response(HTML, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    if (request.method === "POST" && url.pathname === "/convert") {
      return handleConvert(request, env);
    }

    if (request.method === "POST" && url.pathname === "/upload") {
      return handleUpload(request, env);
    }

    return new Response("Not found", { status: 404 });
  }
};

// ─── /convert: Fetch the file from URL and return it as binary ───────────────
async function handleConvert(request, env) {
  let body;
  try { body = await request.json(); } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const { fileUrl } = body;
  if (!fileUrl) return json({ error: "Missing fileUrl" }, 400);

  let res;
  try { res = await fetch(fileUrl); } catch (e) {
    return json({ error: `Fetch failed: ${e.message}` }, 502);
  }

  if (!res.ok) return json({ error: `Remote returned ${res.status}` }, 502);

  const contentType = res.headers.get("content-type") || "application/octet-stream";
  const buffer = await res.arrayBuffer();

  return new Response(buffer, {
    headers: {
      "Content-Type": contentType,
      "X-Original-Content-Type": contentType,
      "Access-Control-Allow-Origin": "*",
    }
  });
}

// ─── /upload: Receive { jpgBase64, originalBase64, originalName } and put to S3
async function handleUpload(request, env) {
  let body;
  try { body = await request.json(); } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const { jpgBase64, originalBase64, originalName } = body;
  if (!jpgBase64 || !originalBase64 || !originalName) {
    return json({ error: "Missing fields" }, 400);
  }

  // Check S3 config
  if (!env.S3_ENDPOINT || !env.S3_BUCKET || !env.S3_ACCESS_KEY || !env.S3_SECRET_KEY) {
    return json({ error: "S3 credentials not configured. Set S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION as Worker secrets." }, 500);
  }

  const timestamp = Date.now();
  const baseName = originalName.replace(/\.[^.]+$/, "");
  const jpgKey = `${timestamp}_${baseName}.jpg`;
  const origKey = `${timestamp}_${originalName}`;

  try {
    const jpgBytes = base64ToBytes(jpgBase64);
    const origBytes = base64ToBytes(originalBase64);

    const [jpgUrl, origUrl] = await Promise.all([
      s3Put(env, jpgKey, jpgBytes, "image/jpeg"),
      s3Put(env, origKey, origBytes, "application/octet-stream"),
    ]);

    return json({ jpgUrl, origUrl, jpgKey, origKey });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ─── S3 helpers ──────────────────────────────────────────────────────────────
async function s3Put(env, key, bytes, contentType) {
  const region = env.S3_REGION || "eu-central-1";
  const endpoint = env.S3_ENDPOINT.replace(/\/$/, "");
  const bucket = env.S3_BUCKET;
  const url = `${endpoint}/${bucket}/${key}`;

  const now = new Date();
  const dateStamp = now.toISOString().slice(0, 10).replace(/-/g, "");
  const amzDate = now.toISOString().replace(/[:-]/g, "").replace(/\.\d+/, "");

  const payloadHash = await sha256Hex(bytes);

  const headers = {
    "host": new URL(url).host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    "content-type": contentType,
    "content-length": String(bytes.byteLength),
  };

  const signedHeaders = "content-length;content-type;host;x-amz-content-sha256;x-amz-date";

  const canonicalHeaders = Object.entries(headers)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}:${v}\n`)
    .join("");

  const canonicalRequest = [
    "PUT",
    `/${bucket}/${key}`,
    "",
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(new TextEncoder().encode(canonicalRequest)),
  ].join("\n");

  const signingKey = await getSigningKey(env.S3_SECRET_KEY, dateStamp, region, "s3");
  const signature = await hmacHex(signingKey, stringToSign);

  const authorization = `AWS4-HMAC-SHA256 Credential=${env.S3_ACCESS_KEY}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(url, {
    method: "PUT",
    headers: { ...headers, authorization },
    body: bytes,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`S3 upload failed (${res.status}): ${text}`);
  }

  return url;
}

async function getSigningKey(secret, dateStamp, region, service) {
  const keyDate = await hmacBytes(`AWS4${secret}`, dateStamp);
  const keyRegion = await hmacBytesFromKey(keyDate, region);
  const keyService = await hmacBytesFromKey(keyRegion, service);
  return hmacBytesFromKey(keyService, "aws4_request");
}

async function hmacBytes(key, data) {
  const keyBytes = typeof key === "string" ? new TextEncoder().encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

async function hmacBytesFromKey(key, data) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

async function hmacHex(key, data) {
  const buf = await hmacBytesFromKey(await key, data);
  return bufToHex(buf);
}

async function sha256Hex(data) {
  const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? new TextEncoder().encode(data) : data);
  return bufToHex(buf);
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
}

// ─── Embedded UI ─────────────────────────────────────────────────────────────
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>file → jpg</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #0d0d0d;
    --surface: #141414;
    --border: #252525;
    --text: #e8e8e8;
    --muted: #555;
    --accent: #c8ff00;
    --accent-dim: rgba(200,255,0,0.08);
    --danger: #ff4d4d;
    --radius: 6px;
    --font: 'JetBrains Mono', monospace;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem 1rem;
  }

  .card {
    width: 100%;
    max-width: 540px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 2rem;
  }

  .header {
    margin-bottom: 2rem;
  }

  .header h1 {
    font-size: 13px;
    font-weight: 500;
    color: var(--accent);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 4px;
  }

  .header p {
    font-size: 11px;
    color: var(--muted);
  }

  .field {
    margin-bottom: 1rem;
  }

  label {
    display: block;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 0.05em;
    margin-bottom: 6px;
  }

  input[type="text"] {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-family: var(--font);
    font-size: 12px;
    padding: 10px 12px;
    outline: none;
    transition: border-color 0.15s;
  }

  input[type="text"]:focus { border-color: var(--accent); }
  input[type="text"]::placeholder { color: var(--muted); }

  .btn {
    width: 100%;
    background: var(--accent);
    color: #000;
    border: none;
    border-radius: var(--radius);
    font-family: var(--font);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.08em;
    padding: 11px;
    cursor: pointer;
    text-transform: uppercase;
    transition: opacity 0.15s, transform 0.1s;
    margin-top: 0.5rem;
  }

  .btn:hover:not(:disabled) { opacity: 0.88; }
  .btn:active:not(:disabled) { transform: scale(0.99); }
  .btn:disabled { opacity: 0.35; cursor: not-allowed; }

  .btn-secondary {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
    margin-top: 8px;
  }

  .status {
    margin-top: 1.5rem;
    font-size: 11px;
    min-height: 18px;
  }

  .status-line {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: var(--radius);
    margin-bottom: 6px;
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--border);
  }

  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .dot.pending { background: var(--muted); }
  .dot.active { background: var(--accent); animation: pulse 1s infinite; }
  .dot.done { background: var(--accent); }
  .dot.error { background: var(--danger); }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .result-box {
    margin-top: 1.5rem;
    display: none;
  }

  .result-box.visible { display: block; }

  .preview-wrap {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 1rem;
    background: #000;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 120px;
  }

  .preview-wrap img {
    max-width: 100%;
    max-height: 320px;
    display: block;
  }

  .links {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .link-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 8px 12px;
    font-size: 11px;
  }

  .link-row span { color: var(--muted); }

  .link-row a {
    color: var(--accent);
    text-decoration: none;
    font-weight: 500;
  }

  .link-row a:hover { text-decoration: underline; }

  .error-msg {
    color: var(--danger);
    font-size: 11px;
    margin-top: 0.75rem;
    padding: 8px 10px;
    background: rgba(255,77,77,0.07);
    border: 1px solid rgba(255,77,77,0.2);
    border-radius: var(--radius);
    display: none;
  }

  .error-msg.visible { display: block; }

  canvas { display: none; }
</style>
</head>
<body>

<div class="card">
  <div class="header">
    <h1>file → jpg</h1>
    <p>Paste a URL to a PDF or image. Converts to JPG and uploads both files to S3.</p>
  </div>

  <div class="field">
    <label>File URL</label>
    <input type="text" id="urlInput" placeholder="https://example.com/document.pdf" />
  </div>

  <button class="btn" id="convertBtn" onclick="startConvert()">Convert + Upload</button>

  <div class="status" id="statusArea"></div>

  <div class="error-msg" id="errorMsg"></div>

  <div class="result-box" id="resultBox">
    <div class="preview-wrap">
      <img id="previewImg" src="" alt="Preview" />
    </div>
    <div class="links" id="linksArea"></div>
    <a class="btn btn-secondary" id="downloadBtn" download="converted.jpg" href="#">Download JPG</a>
  </div>
</div>

<canvas id="canvas"></canvas>

<!-- pdf.js -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script>
pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

let jpgDataUrl = null;
let originalBase64 = null;
let originalName = null;

function setStatus(steps) {
  const area = document.getElementById('statusArea');
  area.innerHTML = steps.map(s =>
    \`<div class="status-line">
      <div class="dot \${s.state}"></div>
      <span>\${s.text}</span>
    </div>\`
  ).join('');
}

function showError(msg) {
  const el = document.getElementById('errorMsg');
  el.textContent = msg;
  el.classList.add('visible');
}

function clearError() {
  document.getElementById('errorMsg').classList.remove('visible');
}

async function startConvert() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;

  clearError();
  document.getElementById('resultBox').classList.remove('visible');
  document.getElementById('convertBtn').disabled = true;

  setStatus([
    { state: 'active', text: 'Fetching file...' },
    { state: 'pending', text: 'Converting to JPG...' },
    { state: 'pending', text: 'Uploading to S3...' },
  ]);

  try {
    // Step 1: Fetch via worker proxy
    const fetchRes = await fetch('/convert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileUrl: url })
    });

    if (!fetchRes.ok) {
      const err = await fetchRes.json();
      throw new Error(err.error || 'Fetch failed');
    }

    const contentType = fetchRes.headers.get('Content-Type') || '';
    const buffer = await fetchRes.arrayBuffer();

    setStatus([
      { state: 'done', text: 'File fetched.' },
      { state: 'active', text: 'Converting to JPG...' },
      { state: 'pending', text: 'Uploading to S3...' },
    ]);

    // Derive filename from URL
    originalName = url.split('/').pop().split('?')[0] || 'file';

    // Store original as base64
    originalBase64 = arrayBufferToBase64(buffer);

    // Step 2: Convert
    if (contentType.includes('pdf')) {
      jpgDataUrl = await pdfToJpg(buffer);
    } else if (contentType.startsWith('image/')) {
      jpgDataUrl = await imageToJpg(buffer, contentType);
    } else {
      throw new Error(\`Unsupported file type: \${contentType}\`);
    }

    setStatus([
      { state: 'done', text: 'File fetched.' },
      { state: 'done', text: 'Converted to JPG.' },
      { state: 'active', text: 'Uploading to S3...' },
    ]);

    // Step 3: Upload
    const jpgBase64 = jpgDataUrl.split(',')[1];
    const uploadRes = await fetch('/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jpgBase64, originalBase64, originalName })
    });

    const uploadData = await uploadRes.json();
    if (!uploadRes.ok) throw new Error(uploadData.error || 'Upload failed');

    setStatus([
      { state: 'done', text: 'File fetched.' },
      { state: 'done', text: 'Converted to JPG.' },
      { state: 'done', text: 'Uploaded to S3.' },
    ]);

    // Show result
    document.getElementById('previewImg').src = jpgDataUrl;
    document.getElementById('downloadBtn').href = jpgDataUrl;
    document.getElementById('downloadBtn').download = originalName.replace(/\\.[^.]+$/, '') + '.jpg';

    const links = document.getElementById('linksArea');
    links.innerHTML = \`
      <div class="link-row">
        <span>JPG</span>
        <a href="\${uploadData.jpgUrl}" target="_blank">\${uploadData.jpgKey}</a>
      </div>
      <div class="link-row">
        <span>Original</span>
        <a href="\${uploadData.origUrl}" target="_blank">\${uploadData.origKey}</a>
      </div>
    \`;

    document.getElementById('resultBox').classList.add('visible');

  } catch (e) {
    showError('Error: ' + e.message);
    setStatus([]);
  } finally {
    document.getElementById('convertBtn').disabled = false;
  }
}

async function pdfToJpg(buffer) {
  const pdf = await pdfjsLib.getDocument({ data: buffer }).promise;
  const page = await pdf.getPage(1);
  const viewport = page.getViewport({ scale: 2.0 });
  const canvas = document.getElementById('canvas');
  canvas.width = viewport.width;
  canvas.height = viewport.height;
  const ctx = canvas.getContext('2d');
  await page.render({ canvasContext: ctx, viewport }).promise;
  return canvas.toDataURL('image/jpeg', 0.92);
}

async function imageToJpg(buffer, contentType) {
  return new Promise((resolve, reject) => {
    const blob = new Blob([buffer], { type: contentType });
    const objectUrl = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      const canvas = document.getElementById('canvas');
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(objectUrl);
      resolve(canvas.toDataURL('image/jpeg', 0.92));
    };
    img.onerror = () => reject(new Error('Failed to load image'));
    img.src = objectUrl;
  });
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startConvert();
});
</script>
</body>
</html>
`;
