/* IntelFusion dashboard — boot sequence, particles, 3D globe, API rendering */
import * as THREE from "three";

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
const SEV_COLOR = { critical: 0xff2d78, high: 0xff6b35, medium: 0xffb300, low: 0x00e5ff };
const SEV_CSS = { critical: "#ff2d78", high: "#ff6b35", medium: "#ffb300", low: "#00e5ff" };

/* ---------------- boot sequence ---------------- */
const BOOT_LINES = [
  "INTELFUSION v1.0.0 — threat-intelligence correlation engine",
  "[*] initializing SQLite store .............. OK",
  "[*] loading indicator database ............. OK",
  "[*] connecting feed: urlhaus ............... OK",
  "[*] connecting feed: alienvault-otx ......... OK",
  "[*] connecting feed: abuseipdb .............. OK",
  "[*] correlating local logs ................. OK",
  "[+] dashboard online. monitoring threats.",
];
async function boot() {
  const term = $("boot-term");
  for (const line of BOOT_LINES) {
    const div = document.createElement("div");
    term.appendChild(div);
    for (let i = 0; i <= line.length; i += 3) {
      div.textContent = line.slice(0, i) + "▊";
      await new Promise((r) => setTimeout(r, 12));
    }
    div.textContent = line;
  }
  await new Promise((r) => setTimeout(r, 500));
  $("boot").classList.add("done");
}

/* ---------------- particle background ---------------- */
function particles() {
  const c = $("particles"), ctx = c.getContext("2d");
  const resize = () => { c.width = innerWidth; c.height = innerHeight; };
  resize(); addEventListener("resize", resize);
  const pts = Array.from({ length: 110 }, () => ({
    x: Math.random() * c.width, y: Math.random() * c.height,
    vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
    r: Math.random() * 1.6 + 0.4, a: Math.random() * 0.5 + 0.15,
  }));
  (function tick() {
    ctx.clearRect(0, 0, c.width, c.height);
    for (const p of pts) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = c.width; if (p.x > c.width) p.x = 0;
      if (p.y < 0) p.y = c.height; if (p.y > c.height) p.y = 0;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7);
      ctx.fillStyle = `rgba(0,229,255,${p.a})`; ctx.fill();
    }
    requestAnimationFrame(tick);
  })();
}

/* ---------------- clock ---------------- */
setInterval(() => {
  $("clock").textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
}, 1000);

/* ---------------- API rendering ---------------- */
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

function renderFeeds(data) {
  $("feeds").innerHTML = data.feeds.map((f) => `
    <div class="feed">
      <div class="row">
        <span class="name">${esc(f.feed)}</span>
        <span class="st ${esc(f.status)}">${esc(f.status.toUpperCase())}</span>
      </div>
      <div class="row" style="margin-top:6px">
        <span class="count">${f.ioc_count}</span>
        <span class="meta">indicators</span>
      </div>
      <div class="meta">${f.fetched_at ? "last fetch " + esc(f.fetched_at.slice(0, 19).replace("T", " ")) + "Z" : "never fetched"}</div>
      ${f.error ? `<div class="meta" style="color:#ff2d78">${esc(f.error)}</div>` : ""}
    </div>`).join("");
}

function renderStats(data) {
  const b = data.by_level;
  $("stats").innerHTML = `
    <div class="stat"><div class="v">${data.total_iocs}</div><div class="k">indicators</div></div>
    <div class="stat"><div class="v">${data.total_alerts}</div><div class="k">alerts</div></div>
    <div class="stat crit"><div class="v">${b.critical || 0}</div><div class="k">critical</div></div>
    <div class="stat"><div class="v">${b.high || 0}</div><div class="k">high</div></div>`;
}

function renderTimeline(data) {
  const el = $("timeline");
  if (!data.alerts.length) {
    el.innerHTML = `<div class="empty">no alerts yet — run a scan</div>`;
    return;
  }
  el.innerHTML = data.alerts.slice(0, 40).map((a) => `
    <div class="alert ${esc(a.level)}" data-id="${a.id}">
      <div class="t">${esc(a.matched_at.slice(0, 19).replace("T", " "))}Z</div>
      <div class="ioc">${esc(a.ioc_value)}</div>
      <span class="chip ${esc(a.level)}">${esc(a.level)} · ${a.severity}</span>
    </div>`).join("");
  el.querySelectorAll(".alert").forEach((n) =>
    n.addEventListener("click", () => openModal(n.dataset.id))
  );
}

let allIocs = [];
function renderIocs(data) {
  allIocs = data.iocs;
  $("ioc-count").textContent = `(${data.total} total)`;
  drawIocRows($("ioc-search").value);
}
function drawIocRows(filter) {
  const q = filter.trim().toLowerCase();
  const rows = allIocs.filter((i) => !q || i.value.toLowerCase().includes(q)).slice(0, 150);
  $("ioc-rows").innerHTML = rows.map((i) => `
    <tr>
      <td class="val">${esc(i.value)}</td>
      <td>${esc(i.ioc_type)}</td>
      <td>${i.feeds.map((f) => `<span class="ftag">${esc(f)}</span>`).join("")}</td>
      <td><span class="chip ${esc(i.level)}">${i.severity}</span></td>
      <td class="dim">${esc(i.first_seen.slice(0, 10))}</td>
    </tr>`).join("");
}
$("ioc-search").addEventListener("input", (e) => drawIocRows(e.target.value));

async function openModal(id) {
  const a = await api(`/api/alerts/${id}`);
  $("modal-body").innerHTML = `
    <div class="kv">
      <div class="k">indicator</div><div class="v">${esc(a.ioc_value)}</div>
      <div class="k">type</div><div class="v">${esc(a.ioc_type)}</div>
      <div class="k">feeds</div><div class="v">${esc(a.feeds)}</div>
      <div class="k">severity</div><div class="v"><span class="chip ${esc(a.level)}">${esc(a.level)} · ${a.severity}/100</span></div>
      <div class="k">log file</div><div class="v">${esc(a.log_file)}</div>
      <div class="k">matched</div><div class="v">${esc(a.matched_at)}</div>
    </div>
    <div class="k mono dim" style="font-size:11px;letter-spacing:2px">MATCHED LOG LINE</div>
    <pre class="logline">${esc(a.log_line)}</pre>`;
  $("modal").classList.remove("hidden");
}
$("modal-close").addEventListener("click", () => $("modal").classList.add("hidden"));
$("modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") $("modal").classList.add("hidden");
});

$("scan-btn").addEventListener("click", async () => {
  $("scan-msg").textContent = "scanning logs…";
  try {
    const r = await api("/api/scan", { method: "POST" });
    $("scan-msg").textContent = `scan complete — ${r.new_alerts} new alert(s)`;
    await loadAll();
  } catch (e) {
    $("scan-msg").textContent = "scan failed: " + e.message;
  }
});

/* ---------------- 3D globe ---------------- */
let arcGroup, pulses = [], markers = [];
function latLonToVec3(lat, lon, r) {
  const phi = ((90 - lat) * Math.PI) / 180;
  const theta = ((lon + 180) * Math.PI) / 180;
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta)
  );
}

function initGlobe() {
  const canvas = $("globe"), wrap = $("globe-wrap");
  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
  camera.position.z = 2.9;

  const globe = new THREE.Group();
  scene.add(globe);

  // dot-matrix sphere
  const N = 1400, pos = new Float32Array(N * 3), R = 1;
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < N; i++) {
    const y = 1 - (i / (N - 1)) * 2;
    const rad = Math.sqrt(1 - y * y), th = golden * i;
    pos[i * 3] = Math.cos(th) * rad * R;
    pos[i * 3 + 1] = y * R;
    pos[i * 3 + 2] = Math.sin(th) * rad * R;
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
  globe.add(new THREE.Points(geo, new THREE.PointsMaterial({
    color: 0x00e5ff, size: 0.011, transparent: true, opacity: 0.55,
  })));

  // faint shell for depth
  globe.add(new THREE.Mesh(
    new THREE.SphereGeometry(R * 0.985, 32, 32),
    new THREE.MeshBasicMaterial({ color: 0x0a1a3a, transparent: true, opacity: 0.5 })
  ));

  arcGroup = new THREE.Group();
  globe.add(arcGroup);

  function resize() {
    const w = wrap.clientWidth, h = wrap.clientHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  resize(); addEventListener("resize", resize);

  const clock = new THREE.Clock();
  (function animate() {
    requestAnimationFrame(animate);
    const t = clock.getElapsedTime();
    globe.rotation.y += 0.0016;
    for (const p of pulses) {
      p.t += p.speed;
      if (p.t > 1) p.t = 0;
      p.mesh.position.copy(p.curve.getPoint(p.t));
      const s = 0.02 + 0.012 * Math.sin(t * 6 + p.t * 20);
      p.mesh.scale.setScalar(s / 0.02);
    }
    for (const m of markers) m.scale.setScalar(1 + 0.35 * Math.sin(t * 3 + m.userData.ph));
    renderer.render(scene, camera);
  })();

  window.__setArcs = (arcs) => {
    while (arcGroup.children.length) arcGroup.remove(arcGroup.children[0]);
    pulses = []; markers = [];
    for (const a of arcs) {
      const p1 = latLonToVec3(a.from.lat, a.from.lon, R);
      const p2 = latLonToVec3(a.to.lat, a.to.lon, R);
      const dist = p1.distanceTo(p2);
      const mid = p1.clone().add(p2).multiplyScalar(0.5).normalize()
        .multiplyScalar(R * (1 + dist * 0.45));
      const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
      const color = SEV_COLOR[a.level] ?? 0x00e5ff;
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(curve.getPoints(48)),
        new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.75 })
      );
      arcGroup.add(line);
      const pulse = new THREE.Mesh(
        new THREE.SphereGeometry(0.02, 8, 8),
        new THREE.MeshBasicMaterial({ color })
      );
      arcGroup.add(pulse);
      pulses.push({ curve, t: Math.random(), speed: 0.004 + Math.random() * 0.006, mesh: pulse });
      const marker = new THREE.Mesh(
        new THREE.SphereGeometry(0.022, 8, 8),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9 })
      );
      marker.position.copy(p1);
      marker.userData.ph = Math.random() * 6;
      arcGroup.add(marker);
      markers.push(marker);
    }
  };
}

async function loadGlobe() {
  try {
    const d = await api("/api/arcs");
    if (window.__setArcs) window.__setArcs(d.arcs);
  } catch (e) { /* globe stays empty until backend is up */ }
}

async function loadAll() {
  const [feeds, stats, alerts, iocs] = await Promise.all([
    api("/api/feeds"), api("/api/stats"), api("/api/alerts?limit=100"), api("/api/iocs?limit=500"),
  ]);
  renderFeeds(feeds); renderStats(stats); renderTimeline(alerts); renderIocs(iocs);
  await loadGlobe();
}

/* ---------------- go ---------------- */
boot();
particles();
initGlobe();
loadAll().catch((e) => console.error("initial load failed:", e));
setInterval(() => loadAll().catch(() => {}), 12000);
