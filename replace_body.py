import sys

with open("templates/benchmarks.html", "r") as f:
    html = f.read()

head_part = html.split("<body>")[0]

new_body = """<body>
<!-- HEADER -->
<div class="header">
  <div>
    <h1>🛡️ Double-Blind Post-Quantum Communication</h1>
    <div class="header-sub">Kyber-768 · Dilithium-3 · AES-256-GCM · Fragmentation Wrapper</div>
  </div>
  <div style="display:flex; gap:20px; align-items:center;">
    <a href="/" style="color:var(--t2); text-decoration:none; font-size:11px; font-weight:700; padding:6px 12px; transition:0.2s;" onmouseover="this.style.color='var(--cyan)'" onmouseout="this.style.color='var(--t2)'">VPN Dashboard</a>
    <a href="/benchmarks" style="color:var(--cyan); text-decoration:none; font-size:11px; font-weight:700; background:rgba(6,182,212,0.1); padding:6px 12px; border-radius:6px; border:1px solid var(--cyan);">📊 Benchmarks</a>
    <div id="badge" class="badge off"><div class="dot"></div><span id="badgeTxt">Disconnected</span></div>
  </div>
</div>

<!-- TABS -->
<div class="tabs">
  <div class="tab active">📊 Post-Quantum vs Classical Benchmarks</div>
</div>

<div class="tc active" id="tab-simulation">
  <div style="text-align:center;margin-bottom:16px">
    <button class="btn btn-p" id="btnBench" onclick="startBenchmarks()">🚀 Run Comparative Benchmarks</button>
  </div>

  <div class="sim-grid">
    <div class="card">
      <div class="card-t">🔑 Key Exchange: Kyber-768 vs X25519</div>
      <table class="pt" id="tbl-kem">
        <thead><tr><th>Algorithm</th><th>Keygen (ms)</th><th>Exchange (ms)</th><th>Public Key (B)</th><th>Ciphertext (B)</th></tr></thead>
        <tbody>
          <tr><td colspan="5" style="text-align:center;color:var(--t3)">Awaiting test...</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-t">✍️ Digital Signatures: Dilithium-3 vs Ed25519</div>
      <table class="pt" id="tbl-sig">
        <thead><tr><th>Algorithm</th><th>Keygen (ms)</th><th>Sign (ms)</th><th>Verify (ms)</th><th>Signature (B)</th></tr></thead>
        <tbody>
          <tr><td colspan="5" style="text-align:center;color:var(--t3)">Awaiting test...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-t">🖥️ Benchmark Terminal Output</div>
    <div class="term" id="term" style="max-height: 400px;"></div>
  </div>
</div>

<script>
const S = io();

// connection
S.on('connect',()=>{$('badge').className='badge on';$('badgeTxt').textContent='Connected'});
S.on('disconnect',()=>{$('badge').className='badge off';$('badgeTxt').textContent='Disconnected'});

function $(id){return document.getElementById(id)}

S.on('backend_log',(d)=>{
  const t=$('term'), line=document.createElement('div');
  line.className='l';
  line.innerHTML=`<span class="ts">[${d.ts}]</span> <span class="${d.level}">${esc(d.text)}</span>`;
  t.appendChild(line);
  if(t.children.length>2000) t.removeChild(t.firstChild);
  t.scrollTop=t.scrollHeight;
});

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function startBenchmarks(){
  $('btnBench').disabled=true; $('btnBench').textContent='⏳ Running Benchmarks...';
  S.emit('start_benchmarks');
  $('term').innerHTML='';
  document.querySelector('#tbl-kem tbody').innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--t3)">Running...</td></tr>';
  document.querySelector('#tbl-sig tbody').innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--t3)">Running...</td></tr>';
}

S.on('bench_result', (data) => {
    if (data.type === 'kem') {
        const tbody = document.querySelector('#tbl-kem tbody');
        if (tbody.innerHTML.includes('Running')) tbody.innerHTML = '';
        const tr = document.createElement('tr');
        tr.innerHTML = `<td style="color:var(--cyan);font-weight:700;">${data.algo}</td>
                        <td>${data.keygen.toFixed(3)}</td>
                        <td>${data.exchange.toFixed(3)}</td>
                        <td>${data.pk_size}</td>
                        <td>${data.ct_size}</td>`;
        tbody.appendChild(tr);
    } else if (data.type === 'sig') {
        const tbody = document.querySelector('#tbl-sig tbody');
        if (tbody.innerHTML.includes('Running')) tbody.innerHTML = '';
        const tr = document.createElement('tr');
        tr.innerHTML = `<td style="color:var(--purple);font-weight:700;">${data.algo}</td>
                        <td>${data.keygen.toFixed(3)}</td>
                        <td>${data.sign.toFixed(3)}</td>
                        <td>${data.verify.toFixed(3)}</td>
                        <td>${data.sig_size}</td>`;
        tbody.appendChild(tr);
    }
});

S.on('bench_complete', () => {
  $('btnBench').disabled=false; $('btnBench').textContent='✅ Benchmarks Complete (Run Again)';
});

</script>
</body>
</html>
"""

with open("templates/benchmarks.html", "w") as f:
    f.write(head_part + new_body)

