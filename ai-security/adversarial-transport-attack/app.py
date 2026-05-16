"""
Adversarial Transport Attack — Dashboard & API
===============================================
Interactive web dashboard for demonstrating adversarial attacks on
transport AI systems in real-time.

Run locally:
    pip install torch fastapi uvicorn
    uvicorn app:app --reload
    Open: http://localhost:8000/
"""

import json
import time
import base64
import struct
import zlib
from collections import deque
from datetime import datetime

import torch
import torch.nn as nn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from src.model import TransportCNN, class_name, GTSRB_CLASSES
from src.attacks import FGSM, PGD
from src.evaluator import AttackEvaluator
from src.atlas import ATLAS_MAPPINGS

# ── App init ────────────────────────────────────────────────────
app = FastAPI(
    title="Adversarial Transport Attack — Dashboard",
    description="Real-time FGSM/PGD adversarial attacks on transport CV systems. MITRE ATLAS AML.T0043.",
    version="1.0.0",
)

# ── Model (singleton) ───────────────────────────────────────────
torch.manual_seed(42)
_model = TransportCNN(n_classes=43)
_model.eval()

# ── Audit log ───────────────────────────────────────────────────
_audit_log: deque = deque(maxlen=50)


# ── Helper: tensor → PNG base64 ─────────────────────────────────
def _tensor_to_png_b64(t: torch.Tensor, scale: float = 1.0) -> str:
    """Convert a (3, H, W) float tensor [0,1] to a base64 PNG string."""
    t = (t.detach().clamp(0, 1) * 255 * scale).clamp(0, 255).byte()
    c, h, w = t.shape
    # Build raw PNG from scratch (no PIL needed)
    rows = []
    for y in range(h):
        row = bytearray([0])  # filter type = None
        for x in range(w):
            row += bytes([t[0, y, x].item(), t[1, y, x].item(), t[2, y, x].item()])
        rows.append(bytes(row))

    def _chunk(name: bytes, data: bytes) -> bytes:
        c_data = name + data
        return struct.pack(">I", len(data)) + c_data + struct.pack(">I", zlib.crc32(c_data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = b"".join(rows)
    idat = zlib.compress(raw)

    png = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
    return "data:image/png;base64," + base64.b64encode(png).decode()


# ── Request / Response models ────────────────────────────────────
class AttackRequest(BaseModel):
    attack: str = "FGSM"          # "FGSM" | "PGD"
    epsilon: float = 0.03
    pgd_steps: int = 40
    image_size: int = 32          # 32 or 64


class SweepRequest(BaseModel):
    n_samples: int = 5
    pgd_steps: int = 20


# ── HTML Dashboard ───────────────────────────────────────────────
_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Adversarial Transport Attack — Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
      --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
      --safe:#3fb950;--warn:#d29922;--high:#f85149;--critical:#bc8cff;
      --r:8px;
    }
    body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;padding:24px 20px}
    h1{font-size:1.6rem;font-weight:700;letter-spacing:-.5px}
    h1 span{color:var(--accent)}
    .sub{color:var(--muted);font-size:.85rem;margin-top:6px}
    .badge{display:inline-block;background:#1f2937;border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:.72rem;color:var(--accent);margin-top:8px;margin-right:6px}

    /* Grid layout */
    .grid{display:grid;gap:16px;margin-top:24px}
    .grid-2{grid-template-columns:1fr 1fr}
    .grid-3{grid-template-columns:1fr 1fr 1fr}
    @media(max-width:900px){.grid-2,.grid-3{grid-template-columns:1fr}}

    .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:20px}
    .card-title{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:14px}

    /* Controls */
    label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:5px;margin-top:12px}
    label:first-child{margin-top:0}
    select,input[type=range]{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text);padding:8px 10px;font-size:.875rem;outline:none}
    select:focus{border-color:var(--accent)}
    input[type=range]{padding:6px 0;accent-color:var(--accent)}
    .range-row{display:flex;justify-content:space-between;font-size:.78rem;color:var(--muted);margin-top:3px}

    .btn{margin-top:16px;width:100%;padding:11px;background:var(--accent);color:#0d1117;font-weight:700;font-size:.9rem;border:none;border-radius:var(--r);cursor:pointer;transition:opacity .15s;letter-spacing:.02em}
    .btn:hover{opacity:.85}
    .btn:disabled{opacity:.4;cursor:not-allowed}
    .btn-sweep{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
    .btn-sweep:hover{border-color:var(--accent);color:var(--accent)}

    /* Results */
    .result-hidden{display:none}
    .risk-badge{display:inline-block;padding:5px 14px;border-radius:20px;font-weight:700;font-size:.85rem;letter-spacing:.05em}
    .SAFE{background:rgba(63,185,80,.15);color:var(--safe);border:1px solid var(--safe)}
    .SUSPICIOUS{background:rgba(210,153,34,.15);color:var(--warn);border:1px solid var(--warn)}
    .HIGH_RISK{background:rgba(248,81,73,.15);color:var(--high);border:1px solid var(--high)}
    .CRITICAL{background:rgba(188,140,255,.15);color:var(--critical);border:1px solid var(--critical)}

    .info-row{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
    .info-box{flex:1;min-width:120px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:10px 12px}
    .ib-label{font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
    .ib-value{font-size:.95rem;font-weight:600}

    /* Images */
    .img-row{display:flex;gap:12px;margin-top:14px}
    .img-box{flex:1;text-align:center}
    .img-box .il{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
    .img-box img{width:100%;image-rendering:pixelated;border:1px solid var(--border);border-radius:4px;max-width:200px}
    .img-box .pred{font-size:.8rem;margin-top:6px;color:var(--muted)}
    .img-box .pred span{font-weight:600;color:var(--text)}

    /* Chart */
    .chart-wrap{position:relative;height:260px}

    /* ATLAS table */
    .atlas-table{width:100%;border-collapse:collapse;font-size:.8rem}
    .atlas-table th{text-align:left;padding:8px 10px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}
    .atlas-table td{padding:8px 10px;border-bottom:1px solid rgba(48,54,61,.5);vertical-align:top}
    .atlas-table tr:last-child td{border-bottom:none}
    .tech-id{font-family:monospace;color:var(--accent);font-size:.78rem}
    .tactic-pill{display:inline-block;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.25);border-radius:4px;padding:1px 7px;font-size:.7rem;color:var(--accent)}

    /* Audit log */
    .audit-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(48,54,61,.5);font-size:.8rem}
    .audit-row:last-child{border-bottom:none}
    .audit-time{color:var(--muted);font-size:.72rem;font-family:monospace}
    .audit-badge{padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600}
    .audit-ok{background:rgba(63,185,80,.15);color:var(--safe)}
    .audit-fail{background:rgba(248,81,73,.15);color:var(--high)}

    /* Stat cards */
    .stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:24px}
    @media(max-width:700px){.stats-row{grid-template-columns:repeat(2,1fr)}}
    .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:16px;text-align:center}
    .stat-val{font-size:1.8rem;font-weight:700;color:var(--accent)}
    .stat-label{font-size:.72rem;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.06em}

    footer{margin-top:40px;color:var(--muted);font-size:.75rem;text-align:center}
    footer a{color:var(--accent);text-decoration:none}
  </style>
</head>
<body>

<header>
  <h1>Adversarial <span>Transport</span> Attack</h1>
  <p class="sub">Real-time FGSM &amp; PGD adversarial attacks on transport CV systems</p>
  <span class="badge">OWASP ML01</span>
  <span class="badge">MITRE ATLAS AML.T0043</span>
  <span class="badge">43-class GTSRB</span>
</header>

<!-- Stats row -->
<div class="stats-row" id="statsRow">
  <div class="stat-card"><div class="stat-val" id="statAttacks">0</div><div class="stat-label">Attacks Run</div></div>
  <div class="stat-card"><div class="stat-val" id="statSuccess">—</div><div class="stat-label">Success Rate</div></div>
  <div class="stat-card"><div class="stat-val" id="statPatterns">43</div><div class="stat-label">Sign Classes</div></div>
  <div class="stat-card"><div class="stat-val" id="statAvgDrop">—</div><div class="stat-label">Avg Conf Drop</div></div>
</div>

<div class="grid grid-2" style="margin-top:16px">

  <!-- Attack Controls -->
  <div class="card">
    <div class="card-title">Attack Simulator</div>

    <label>Attack Type</label>
    <select id="attackType">
      <option value="FGSM">FGSM — Fast Gradient Sign Method (single step)</option>
      <option value="PGD">PGD — Projected Gradient Descent (iterative)</option>
    </select>

    <label>Epsilon (ε) — perturbation budget: <strong id="epsVal">0.03</strong></label>
    <input type="range" id="epsilon" min="0.001" max="0.5" step="0.001" value="0.03" oninput="document.getElementById('epsVal').textContent=parseFloat(this.value).toFixed(3)"/>
    <div class="range-row"><span>0.001 (invisible)</span><span>0.5 (visible)</span></div>

    <label id="pgdLabel">PGD Steps: <strong id="stepsVal">40</strong></label>
    <input type="range" id="pgdSteps" min="5" max="100" step="5" value="40" oninput="document.getElementById('stepsVal').textContent=this.value"/>

    <button class="btn" id="runBtn" onclick="runAttack()">⚡ Run Attack</button>
    <button class="btn btn-sweep" id="sweepBtn" onclick="runSweep()" style="margin-top:8px">📊 Run Epsilon Sweep</button>
  </div>

  <!-- Attack Results -->
  <div class="card">
    <div class="card-title">Attack Result</div>
    <div id="resultEmpty" style="color:var(--muted);font-size:.875rem;padding:40px 0;text-align:center">
      Run an attack to see results
    </div>
    <div id="resultPanel" class="result-hidden">
      <div style="display:flex;align-items:center;gap:12px">
        <div class="risk-badge" id="riskBadge">—</div>
        <div>
          <div style="font-size:.78rem;color:var(--muted)" id="attackLabel">—</div>
          <div style="font-size:.9rem;font-weight:600" id="successLabel">—</div>
        </div>
      </div>

      <div class="info-row">
        <div class="info-box"><div class="ib-label">Original Class</div><div class="ib-value" id="origClass">—</div></div>
        <div class="info-box"><div class="ib-label">Adversarial Class</div><div class="ib-value" id="advClass">—</div></div>
        <div class="info-box"><div class="ib-label">Conf Drop</div><div class="ib-value" id="confDrop">—</div></div>
        <div class="info-box"><div class="ib-label">‖δ‖∞</div><div class="ib-value" id="pertNorm">—</div></div>
      </div>

      <div class="img-row" id="imgRow">
        <div class="img-box">
          <div class="il">Original</div>
          <img id="imgOrig" src="" alt="original"/>
          <div class="pred">Pred: <span id="predOrig">—</span></div>
          <div class="pred" style="font-size:.72rem" id="confOrig">—</div>
        </div>
        <div class="img-box">
          <div class="il">Adversarial</div>
          <img id="imgAdv" src="" alt="adversarial"/>
          <div class="pred">Pred: <span id="predAdv">—</span></div>
          <div class="pred" style="font-size:.72rem" id="confAdv">—</div>
        </div>
        <div class="img-box">
          <div class="il">Perturbation ×10</div>
          <img id="imgDelta" src="" alt="perturbation"/>
          <div class="pred" style="font-size:.72rem;margin-top:6px">Amplified 10× for visibility</div>
        </div>
      </div>
    </div>
  </div>

</div>

<!-- Epsilon Sweep Chart -->
<div class="card" style="margin-top:16px">
  <div class="card-title">Epsilon Sweep — Attack Success Rate vs Perturbation Budget</div>
  <div class="chart-wrap">
    <canvas id="sweepChart"></canvas>
  </div>
  <p style="font-size:.75rem;color:var(--muted);margin-top:8px">
    Click "Run Epsilon Sweep" above to populate. PGD consistently outperforms FGSM — especially at low ε where precision matters most.
  </p>
</div>

<!-- MITRE ATLAS + Audit -->
<div class="grid grid-2" style="margin-top:16px">

  <div class="card">
    <div class="card-title">MITRE ATLAS Threat Mapping</div>
    <table class="atlas-table" id="atlasTable">
      <thead><tr><th>Technique ID</th><th>Technique</th><th>Tactic</th></tr></thead>
      <tbody id="atlasTbody"></tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">Live Audit Log</div>
    <div id="auditLog" style="color:var(--muted);font-size:.85rem;text-align:center;padding:20px 0">No attacks run yet</div>
  </div>

</div>

<footer style="margin-top:32px">
  <a href="/docs" target="_blank">API Docs</a> ·
  <a href="/api/atlas" target="_blank">ATLAS JSON</a> ·
  <a href="/api/audit" target="_blank">Audit Log</a> ·
  <a href="/health" target="_blank">Health</a>
</footer>

<script>
// ── State ──────────────────────────────────────────────────────
let totalAttacks = 0, totalSuccess = 0, totalConfDrop = 0;
let sweepChart = null;

// ── Init Chart ────────────────────────────────────────────────
const ctx = document.getElementById('sweepChart').getContext('2d');
sweepChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      {
        label: 'FGSM Success Rate',
        data: [],
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,0.1)',
        tension: 0.3,
        fill: true,
        pointRadius: 4,
      },
      {
        label: 'PGD Success Rate',
        data: [],
        borderColor: '#bc8cff',
        backgroundColor: 'rgba(188,140,255,0.08)',
        tension: 0.3,
        fill: true,
        pointRadius: 4,
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { title: { display: true, text: 'Epsilon (ε)', color: '#8b949e' }, ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
      y: { title: { display: true, text: 'Success Rate', color: '#8b949e' }, ticks: { color: '#8b949e', callback: v => (v*100).toFixed(0)+'%' }, grid: { color: '#30363d' }, min: 0, max: 1 }
    },
    plugins: { legend: { labels: { color: '#e6edf3', font: { size: 12 } } } }
  }
});

// ── Load ATLAS ────────────────────────────────────────────────
fetch('/api/atlas').then(r => r.json()).then(data => {
  const tbody = document.getElementById('atlasTbody');
  data.forEach(e => {
    const sub = e.subtechnique_id ? `<br><span style="color:var(--muted);font-size:.7rem">${e.subtechnique_id} — ${e.subtechnique}</span>` : '';
    tbody.innerHTML += `<tr>
      <td><span class="tech-id">${e.technique_id}</span>${sub}</td>
      <td style="color:var(--text)">${e.technique}</td>
      <td><span class="tactic-pill">${e.tactic}</span></td>
    </tr>`;
  });
});

// ── Run Attack ────────────────────────────────────────────────
async function runAttack() {
  const btn = document.getElementById('runBtn');
  btn.disabled = true; btn.textContent = 'Running…';

  const payload = {
    attack: document.getElementById('attackType').value,
    epsilon: parseFloat(document.getElementById('epsilon').value),
    pgd_steps: parseInt(document.getElementById('pgdSteps').value),
  };

  try {
    const res = await fetch('/api/attack', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Attack failed');
    renderResult(data);
    updateStats(data);
    addAuditRow(data);
  } catch(e) {
    alert('Error: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = '⚡ Run Attack';
  }
}

function renderResult(d) {
  document.getElementById('resultEmpty').style.display = 'none';
  document.getElementById('resultPanel').style.display = 'block';

  const level = d.risk_level;
  const badge = document.getElementById('riskBadge');
  badge.className = 'risk-badge ' + level;
  badge.textContent = level.replace('_',' ');

  document.getElementById('attackLabel').textContent = `${d.attack_name} · ε=${d.epsilon.toFixed(3)}`;
  document.getElementById('successLabel').textContent = d.attack_success
    ? '✓ Prediction flipped — attack succeeded'
    : '✗ Prediction held — model resisted';
  document.getElementById('successLabel').style.color = d.attack_success ? 'var(--high)' : 'var(--safe)';

  document.getElementById('origClass').textContent = d.original_class;
  document.getElementById('advClass').textContent = d.adversarial_class;
  document.getElementById('advClass').style.color = d.attack_success ? 'var(--high)' : 'var(--safe)';
  document.getElementById('confDrop').textContent = ((d.original_confidence - d.adversarial_confidence)*100).toFixed(1) + '%';
  document.getElementById('pertNorm').textContent = d.perturbation_norm.toFixed(4);

  document.getElementById('imgOrig').src = d.image_original;
  document.getElementById('imgAdv').src = d.image_adversarial;
  document.getElementById('imgDelta').src = d.image_delta;

  document.getElementById('predOrig').textContent = `[${d.original_pred}] ${d.original_class}`;
  document.getElementById('predAdv').textContent = `[${d.adversarial_pred}] ${d.adversarial_class}`;
  document.getElementById('confOrig').textContent = `Confidence: ${(d.original_confidence*100).toFixed(1)}%`;
  document.getElementById('confAdv').textContent = `Confidence: ${(d.adversarial_confidence*100).toFixed(1)}%`;
}

function updateStats(d) {
  totalAttacks++;
  if (d.attack_success) totalSuccess++;
  totalConfDrop += d.original_confidence - d.adversarial_confidence;

  document.getElementById('statAttacks').textContent = totalAttacks;
  document.getElementById('statSuccess').textContent = (totalSuccess/totalAttacks*100).toFixed(0)+'%';
  document.getElementById('statAvgDrop').textContent = (totalConfDrop/totalAttacks*100).toFixed(1)+'%';
}

function addAuditRow(d) {
  const log = document.getElementById('auditLog');
  if (log.textContent === 'No attacks run yet') log.innerHTML = '';
  const time = new Date().toLocaleTimeString();
  const cls = d.attack_success ? 'audit-fail' : 'audit-ok';
  const label = d.attack_success ? 'EVADED' : 'BLOCKED';
  log.innerHTML = `<div class="audit-row">
    <span>${d.attack_name} ε=${d.epsilon.toFixed(3)} · ${d.original_class} → ${d.adversarial_class}</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="audit-badge ${cls}">${label}</span>
      <span class="audit-time">${time}</span>
    </span>
  </div>` + log.innerHTML;
}

// ── Epsilon Sweep ─────────────────────────────────────────────
async function runSweep() {
  const btn = document.getElementById('sweepBtn');
  btn.disabled = true; btn.textContent = 'Sweeping…';
  try {
    const res = await fetch('/api/sweep', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({n_samples: 5, pgd_steps: 20})
    });
    const data = await res.json();

    const labels = data.epsilons.map(e => e.toFixed(3));
    sweepChart.data.labels = labels;
    sweepChart.data.datasets[0].data = data.fgsm_success;
    sweepChart.data.datasets[1].data = data.pgd_success;
    sweepChart.update();
  } catch(e) {
    alert('Sweep error: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = '📊 Run Epsilon Sweep';
  }
}
</script>
</body>
</html>"""


# ── API endpoints ────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    return _HTML


@app.post("/api/attack")
async def api_attack(req: AttackRequest):
    """Run a single FGSM or PGD attack and return full result with images."""
    if req.epsilon <= 0 or req.epsilon > 1:
        raise HTTPException(status_code=422, detail="epsilon must be in (0, 1]")
    if req.attack not in ("FGSM", "PGD"):
        raise HTTPException(status_code=422, detail="attack must be FGSM or PGD")

    size = max(16, min(req.image_size, 64))
    torch.manual_seed(int(time.time() * 1000) % 10000)
    x = torch.rand(1, 3, size, size)
    with torch.no_grad():
        y = _model(x).argmax(dim=1)

    if req.attack == "FGSM":
        attacker = FGSM(_model, epsilon=req.epsilon)
    else:
        attacker = PGD(_model, epsilon=req.epsilon, n_steps=req.pgd_steps)

    result = attacker.attack(x, y)

    # Determine risk level
    conf_drop = result.original_confidence - result.adversarial_confidence
    if result.attack_success and conf_drop > 0.5:
        risk_level = "CRITICAL"
    elif result.attack_success:
        risk_level = "HIGH_RISK"
    elif conf_drop > 0.2:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    # Generate PNG images
    orig_3d = result.original if result.original.dim() == 3 else result.original.squeeze(0)
    adv_3d = result.adversarial if result.adversarial.dim() == 3 else result.adversarial.squeeze(0)
    delta = (adv_3d - orig_3d).abs()

    img_orig = _tensor_to_png_b64(orig_3d)
    img_adv = _tensor_to_png_b64(adv_3d)
    img_delta = _tensor_to_png_b64(delta, scale=10.0)

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "attack_name": result.attack_name,
        "epsilon": result.epsilon,
        "original_pred": result.original_pred,
        "adversarial_pred": result.adversarial_pred,
        "original_class": class_name(result.original_pred),
        "adversarial_class": class_name(result.adversarial_pred),
        "original_confidence": round(result.original_confidence, 4),
        "adversarial_confidence": round(result.adversarial_confidence, 4),
        "perturbation_norm": round(result.perturbation_norm, 6),
        "attack_success": result.attack_success,
        "risk_level": risk_level,
        "image_original": img_orig,
        "image_adversarial": img_adv,
        "image_delta": img_delta,
    }
    _audit_log.appendleft(entry)
    return entry


@app.post("/api/sweep")
async def api_sweep(req: SweepRequest):
    """Run epsilon sweep for FGSM and PGD. Returns data for the chart."""
    epsilons = [0.005, 0.01, 0.02, 0.03, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5]
    torch.manual_seed(42)
    images = [torch.rand(1, 3, 32, 32) for _ in range(req.n_samples)]
    labels = []
    with torch.no_grad():
        for img in images:
            labels.append(_model(img).argmax(dim=1))

    evaluator = AttackEvaluator(_model, epsilons=epsilons, pgd_steps=req.pgd_steps)
    report = evaluator.evaluate(images, labels)

    return {
        "epsilons": epsilons,
        "fgsm_success": [r.success_rate for r in report.get("FGSM", [])],
        "pgd_success": [r.success_rate for r in report.get("PGD", [])],
        "fgsm_conf_drop": [r.avg_confidence_drop for r in report.get("FGSM", [])],
        "pgd_conf_drop": [r.avg_confidence_drop for r in report.get("PGD", [])],
    }


@app.get("/api/atlas")
async def api_atlas():
    """Return all MITRE ATLAS mappings as JSON."""
    return [e.to_dict() for e in ATLAS_MAPPINGS]


@app.get("/api/audit")
async def api_audit(limit: int = 20):
    """Return recent attack audit log."""
    entries = list(_audit_log)[:limit]
    # Strip image data for audit endpoint (keep it light)
    clean = [{k: v for k, v in e.items() if not k.startswith("image_")} for e in entries]
    return {"total": len(_audit_log), "entries": clean}


@app.get("/health")
async def health():
    """Health check."""
    params = sum(p.numel() for p in _model.parameters())
    return {
        "status": "ok",
        "model": "TransportCNN",
        "classes": 43,
        "parameters": params,
        "attacks_available": ["FGSM", "PGD"],
    }


if __name__ == "__main__":
    import uvicorn
    print("Adversarial Transport Attack Dashboard")
    print("Dashboard: http://localhost:8000/")
    print("API docs:  http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
