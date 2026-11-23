const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

let currentReport = null;
let currentAudit = null;
let currentMem = null;
let sevFilter = 'all';

$('#minBtn').onclick = () => window.veritas.minimize();
$('#maxBtn').onclick = () => window.veritas.maximize();
$('#closeBtn').onclick = () => window.veritas.close();

window.veritas.getSysInfo().then(info => {
  $('#sysTag').textContent = `${info.platform} ${info.arch}`;
});

function switchView(viewId) {
  $$('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === viewId));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === viewId));
  if (viewId === 'v-proc' && $('#procBody').querySelector('.empty')) loadProcesses();
  if ((viewId === 'v-exec' || viewId === 'v-bypass') && !currentAudit) loadExecAudit();
  if (viewId === 'v-ram' && !currentMem) loadRamScan();
}

$$('.nav-btn').forEach(btn => {
  btn.onclick = () => switchView(btn.dataset.view);
});

$('#viewAllBtn').onclick = () => switchView('v-find');
$('#askAiQuickBtn').onclick = () => switchView('v-ai');

function appendAiMessage(role, html) {
  const box = $('#aiChat');
  const div = document.createElement('div');
  div.className = `ai-msg ${role}`;
  div.innerHTML = html;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

function handleAiQuestion(q) {
  const clean = (q || '').trim();
  if (!clean) return;
  appendAiMessage('user', esc(clean));
  const res = window.VeritasAI.answer(clean, currentReport, currentAudit, currentMem);
  appendAiMessage('bot', `<span class="ai-tag">${esc(res.tag)}</span><strong>${esc(res.title)}</strong><p>${esc(res.lines.join('\n'))}</p>`);
}

$$('.faq-chip').forEach(btn => {
  btn.onclick = () => handleAiQuestion(btn.dataset.q);
});

$('#aiForm').onsubmit = e => {
  e.preventDefault();
  const inp = $('#aiInput');
  handleAiQuestion(inp.value);
  inp.value = '';
};

window.veritas.onProgress(({ step, total, label }) => {
  const pct = Math.round((step / total) * 100);
  $('#progLabel').textContent = `[${step}/${total}] ${label}`;
  $('#progPct').textContent = `${pct}%`;
  $('#progBar').style.width = `${pct}%`;
});

function setBusy(busy) {
  $('#startFullBtn').disabled = busy;
  $('#startDeepBtn').disabled = busy;
  $('#customScanBtn').disabled = busy;
  $('#ramOnlyBtn').disabled = busy;
  $('#progWrap').classList.toggle('hidden', !busy);
  if (busy) {
    $('#progBar').style.width = '5%';
    $('#progPct').textContent = '0%';
    $('#progLabel').textContent = 'Running 12-stage + Live RAM engine...';
  }
}

function mergeMemoryFindings(report, mem) {
  if (!mem || !Array.isArray(mem.scanned)) return;
  for (const m of mem.scanned) {
    const hits = m.hits || [];
    if (!hits.length && !m.manualMappedPe) continue;
    const isJava = Boolean(m.isJava);
    report.findings.unshift({
      severity: 'CRITICAL',
      category: 'RAM_INJECTION',
      score: isJava ? 80 : 65,
      title: isJava
        ? `Live RAM injection / residual C++ trace in ${m.name}.exe (PID ${m.pid})`
        : `Residual cheat binary trace in ${m.name}.exe RAM (PID ${m.pid})`,
      location: `${m.name}.exe (PID ${m.pid})`,
      details: [
        `Memory Source: Win32 ReadProcessMemory (${m.regions} private regions)`,
        ...(m.manualMappedPe > 0 ? [`Manual-Mapped PE: ${m.manualMappedPe} unlinked DLL(s) in RWX/RX memory`] : []),
        `Matched RAM Strings: ${hits.join(', ')}`
      ]
    });
    report.score = Math.min(100, Math.max(report.score || 0, isJava ? 100 : 85));
    report.verdict = 'CRITICAL';
  }
}

async function launchScan(opts) {
  setBusy(true);
  try {
    const [data, audit, procs, mem] = await Promise.all([
      window.veritas.runScan(opts),
      window.veritas.runExecAudit().catch(() => null),
      window.veritas.listProcesses().catch(() => []),
      window.veritas.scanMemory().catch(() => ({ scanned: [] }))
    ]);
    currentMem = mem;
    mergeMemoryFindings(data, mem);
    currentReport = data;
    if (audit) {
      currentAudit = audit;
      renderExecAudit(audit);
    }
    renderMemory(mem);
    renderProcesses(procs || []);
    renderReport(data);
  } catch (err) {
    alert('Scan error: ' + err.message);
  } finally {
    setBusy(false);
  }
}

$('#startFullBtn').onclick = () => launchScan({ deep: false });
$('#startDeepBtn').onclick = () => launchScan({ deep: true });
$('#customScanBtn').onclick = async () => {
  const folder = await window.veritas.pickFolder();
  if (folder) launchScan({ deep: true, customPath: folder });
};
$('#ramOnlyBtn').onclick = async () => {
  switchView('v-ram');
  await loadRamScan();
};
$('#openModsBtn').onclick = async () => {
  const opened = await window.veritas.openModsFolder();
  if (!opened) {
    $('#openModsBtn').textContent = 'Mods Not Found';
    setTimeout(() => { $('#openModsBtn').textContent = 'Open Mods Folder'; }, 1600);
  }
};

$('#exportTxtBtn').onclick = async () => {
  const saved = await window.veritas.exportTxt();
  if (saved) {
    $('#exportTxtBtn').textContent = 'Saved .TXT';
    setTimeout(() => { $('#exportTxtBtn').textContent = 'Export .TXT Log'; }, 1800);
  }
};

$('#copySummaryBtn').onclick = async () => {
  if (!currentReport) return;
  const r = currentReport;
  const lines = [
    `VERITAS | ID: ${r.reportId} | Verdict: ${r.verdict} (${r.score}/100) | OS: ${r.os} | Boot: ${r.bootTime}`,
    ...r.findings.map(f => `[${f.severity}] [${f.category}] ${f.title} -> ${f.location}`)
  ];
  await navigator.clipboard.writeText(lines.join('\n'));
  $('#copySummaryBtn').textContent = 'Copied';
  setTimeout(() => { $('#copySummaryBtn').textContent = 'Copy Summary'; }, 1800);
};

function looksLikePath(loc) {
  return typeof loc === 'string' && (loc.includes(':\\') || loc.startsWith('/') || loc.includes('\\'));
}

function buildFindingRow(f) {
  const sev = f.severity.toLowerCase();
  const chips = (f.details || []).map(d => {
    const idx = d.indexOf(':');
    if (idx > 0 && idx < 34) {
      return `<span class="ev-chip"><b>${esc(d.slice(0, idx).trim())}</b> ${esc(d.slice(idx + 1).trim())}</span>`;
    }
    return `<span class="ev-chip">${esc(d)}</span>`;
  }).join('');

  const canReveal = looksLikePath(f.location);
  const actions = `<div class="row-acts">
    ${canReveal ? `<button class="btn sm rev-btn" data-path="${esc(f.location)}">Reveal</button>` : ''}
    <button class="btn sm cpy-btn" data-path="${esc(f.location)}">Copy</button>
  </div>`;

  return `<tr class="f-row" data-sev="${sev}">
    <td><span class="sev-pill ${sev}">${esc(f.severity)}</span></td>
    <td><span class="cat-tag">${esc(f.category)}</span></td>
    <td><strong>${esc(f.title)}</strong><div class="sub-loc">${esc(f.location)}</div></td>
    <td><div class="ev-grid">${chips}</div></td>
    <td>${actions}</td>
  </tr>`;
}

function bindRowActions() {
  $$('.rev-btn').forEach(btn => {
    btn.onclick = async () => {
      const ok = await window.veritas.revealPath(btn.dataset.path);
      if (!ok) {
        btn.textContent = 'Missing';
        setTimeout(() => { btn.textContent = 'Reveal'; }, 1500);
      }
    };
  });
  $$('.cpy-btn').forEach(btn => {
    btn.onclick = async () => {
      await navigator.clipboard.writeText(btn.dataset.path || '');
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1400);
    };
  });
}

function renderMemory(mem) {
  const list = (mem && Array.isArray(mem.scanned)) ? mem.scanned : [];
  const totalHits = list.reduce((acc, m) => acc + (m.hits ? m.hits.length : 0), 0);
  $('#c-ram').textContent = totalHits;
  $('#k-ram').textContent = totalHits ? `${totalHits} hits` : '0 (Clean)';
  $('#k-ram').style.color = totalHits ? '#f87171' : '#4ade80';
  $('#ramBody').innerHTML = list.length
    ? list.map(m => {
        const hasHit = (m.hits && m.hits.length > 0) || m.manualMappedPe > 0;
        return `<tr>
          <td><span class="st-pill ${hasHit ? 'bad' : 'ok'}">${hasHit ? 'DETECTED' : 'CLEAN'}</span></td>
          <td><strong>${esc(m.name)}.exe</strong></td>
          <td class="mono">${m.pid}</td>
          <td class="mono">${m.regions}</td>
          <td class="mono">${m.manualMappedPe > 0 ? `<span style="color:#f87171">${m.manualMappedPe} UNLINKED PE</span>` : '0'}</td>
          <td class="mono">${hasHit ? `<span style="color:#fca5a5">${esc((m.hits || []).join(', '))}</span>` : '<span class="muted">No cheat signatures in RAM</span>'}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="6" class="empty">No target processes scanned.</td></tr>';
}

async function loadRamScan() {
  $('#refreshRamBtn').disabled = true;
  try {
    currentMem = await window.veritas.scanMemory();
    renderMemory(currentMem);
  } finally {
    $('#refreshRamBtn').disabled = false;
  }
}
$('#refreshRamBtn').onclick = loadRamScan;

function renderExecAudit(a) {
  const pcaList = a.pca || [];
  $('#c-exec').textContent = pcaList.length;
  $('#c-byp').textContent = a.exclusions.length + a.tamperEvents.length;
  $('#k-excl').textContent = a.exclusions.length ? `${a.exclusions.length} found` : '0 (Clean)';
  $('#k-excl').style.color = a.exclusions.length ? '#fbbf24' : '#4ade80';

  $('#pcaBody').innerHTML = pcaList.length
    ? pcaList.slice(0, 80).map(p => {
        const cls = p.flagged ? 'bad' : (!p.exists ? 'warn' : 'ok');
        const txt = p.flagged ? 'IN-SESSION CHEAT' : (!p.exists ? 'DELETED' : 'IN-SESSION');
        return `<tr class="exec-row">
          <td><span class="st-pill ${cls}">${txt}</span></td>
          <td><strong>${esc(p.name)}</strong></td>
          <td class="mono">${esc(p.time || '—')}</td>
          <td class="mono">${p.runs}</td>
          <td class="mono">${p.exists ? '<span style="color:#4ade80">Present</span>' : '<span style="color:#fbbf24">Deleted</span>'}</td>
          <td class="mono muted">${esc(p.path)}</td>
          <td>${p.exists ? `<button class="btn sm rev-btn" data-path="${esc(p.path)}">Reveal</button>` : `<button class="btn sm cpy-btn" data-path="${esc(p.path)}">Copy</button>`}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="7" class="empty">No UserAssist executions recorded since PC boot.</td></tr>';

  $('#exclBody').innerHTML = a.exclusions.length
    ? a.exclusions.map(e => `<tr>
        <td><span class="st-pill warn">${esc(e.type)}</span></td>
        <td class="mono"><strong>${esc(e.value)}</strong></td>
        <td>${e.type === 'Path' ? `<button class="btn sm rev-btn" data-path="${esc(e.value)}">Reveal</button>` : '<span class="muted">—</span>'}</td>
      </tr>`).join('')
    : '<tr><td colspan="3" class="empty" style="color:#4ade80">CLEAN — No Windows Defender Exclusions configured.</td></tr>';

  $('#tamperBody').innerHTML = a.tamperEvents.length
    ? a.tamperEvents.map(t => `<tr>
        <td class="mono">#${t.id}</td>
        <td><span class="st-pill bad">${esc(t.type)}</span></td>
        <td class="mono">${esc(t.time)}</td>
        <td class="muted">${esc(t.detail)}</td>
      </tr>`).join('')
    : '<tr><td colspan="4" class="empty" style="color:#4ade80">CLEAN — No EventLog clear or Clock change since PC boot.</td></tr>';

  bindRowActions();
}

async function loadExecAudit() {
  $('#refreshExecBtn').disabled = true;
  $('#refreshBypassBtn').disabled = true;
  try {
    currentAudit = await window.veritas.runExecAudit();
    renderExecAudit(currentAudit);
  } finally {
    $('#refreshExecBtn').disabled = false;
    $('#refreshBypassBtn').disabled = false;
  }
}
$('#refreshExecBtn').onclick = loadExecAudit;
$('#refreshBypassBtn').onclick = loadExecAudit;

$('#execSearch').oninput = () => {
  const q = $('#execSearch').value.toLowerCase();
  $$('.exec-row').forEach(r => { r.style.display = !q || r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
};

function renderProcesses(list) {
  $('#c-proc').textContent = list.length;
  $('#procBody').innerHTML = list.length
    ? list.map(p => `<tr class="proc-row">
        <td><span class="st-pill ${p.flagged ? 'bad' : 'ok'}">${p.flagged ? 'CHECK' : 'OK'}</span></td>
        <td><strong>${esc(p.name)}</strong>${p.reason ? `<div class="sub-loc" style="color:#fbbf24">${esc(p.reason)}</div>` : ''}</td>
        <td class="mono">${p.pid}</td>
        <td class="mono">${p.memMb} MB</td>
        <td class="mono">${esc(p.start || '—')}</td>
        <td class="mono muted">${esc(p.path)}</td>
        <td><button class="btn sm rev-btn" data-path="${esc(p.path)}">Reveal</button></td>
      </tr>`).join('')
    : '<tr><td colspan="7" class="empty">No user processes listed.</td></tr>';
  bindRowActions();
}

async function loadProcesses() {
  $('#refreshProcBtn').disabled = true;
  try {
    renderProcesses(await window.veritas.listProcesses());
  } finally {
    $('#refreshProcBtn').disabled = false;
  }
}
$('#refreshProcBtn').onclick = loadProcesses;
$('#procSearch').oninput = () => {
  const q = $('#procSearch').value.toLowerCase();
  $$('.proc-row').forEach(r => { r.style.display = !q || r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
};

function buildTimeline(r) {
  const events = [];
  const boot = r.bootTime && r.bootTime !== 'Unknown' ? r.bootTime : '';
  if (boot) events.push({ ts: boot, type: 'SYSTEM', title: 'PC Booted (Session Start)', detail: r.os });
  for (const p of (r.processes || [])) {
    events.push({ ts: p.startTime || 'Active', type: 'MINECRAFT', title: `Launched ${p.launcher} (${p.version})`, detail: `PID ${p.pid} | ${p.modules} loaded modules` });
  }
  for (const t of (r.trash || [])) {
    if (boot && t.deletedAt && String(t.deletedAt) < boot) continue;
    events.push({ ts: t.deletedAt || 'Unknown', type: 'DELETED', title: `Deleted ${t.fileName}`, detail: `${t.size} | ${t.originalPath}` });
  }
  if (currentAudit) {
    for (const te of (currentAudit.tamperEvents || [])) {
      events.push({ ts: te.time || 'Unknown', type: 'TAMPER', title: te.type, detail: `Event ID ${te.id} | ${te.detail || ''}` });
    }
    for (const u of (currentAudit.pca || [])) {
      if (u.inSession) {
        events.push({
          ts: u.time,
          type: u.flagged ? 'CHEAT' : (!u.exists ? 'DELETED' : 'EXECUTED'),
          title: `Ran ${u.name} (${u.runs} runs)`,
          detail: `${u.exists ? 'On disk' : 'DELETED'} | ${u.path}`
        });
      }
    }
  }
  events.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
  return events;
}

function renderReport(r) {
  const color = r.verdict === 'CRITICAL' ? '#ef4444' : r.verdict === 'HIGH' ? '#f97316' : r.verdict === 'SUSPICIOUS' ? '#f59e0b' : '#22c55e';
  $('#verdictDot').style.background = color;
  $('#gaugeVerdict').textContent = r.verdict;
  $('#gaugeVerdict').style.color = color;
  $('#gaugeNum').textContent = `${r.score}/100`;

  const critCount = r.findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = r.findings.filter(f => f.severity === 'HIGH').length;
  const stoppedSvc = (r.services || []).filter(s => !s.status.toLowerCase().startsWith('running')).length;
  const exclCnt = currentAudit ? currentAudit.exclusions.length : 0;
  const boot = r.bootTime && r.bootTime !== 'Unknown' ? r.bootTime : '';
  const sessionTrash = (r.trash || []).filter(t => !boot || !t.deletedAt || String(t.deletedAt) >= boot);
  const sessionExecs = currentAudit && currentAudit.pca ? currentAudit.pca.length : 0;

  const banner = $('#summaryBanner');
  banner.classList.remove('hidden', 'sev-critical', 'sev-high', 'sev-suspicious', 'sev-clean');
  banner.classList.add(r.verdict === 'CRITICAL' ? 'sev-critical' : r.verdict === 'HIGH' ? 'sev-high' : r.verdict === 'SUSPICIOUS' ? 'sev-suspicious' : 'sev-clean');

  const badge = $('#sumBadge');
  badge.textContent = r.verdict;
  badge.className = `sev-pill ${r.verdict === 'CLEAN' ? 'info' : r.verdict.toLowerCase()}`;

  $('#summaryTitle').textContent = critCount > 0
    ? `${critCount} Critical, ${highCount} High priority finding(s) in current session`
    : (stoppedSvc > 0 || exclCnt > 0 ? `${stoppedSvc} stopped service(s), ${exclCnt} Defender exclusion(s)` : 'CLEAN — No cheats, injectors, or RAM traces detected');
  $('#summaryDesc').textContent = `Scanned ${r.jarsScanned} JARs, ${r.binariesScanned} binaries, live RAM, and ${r.services.length} services in ${r.elapsed}s.`;
  $('#sumMeta').innerHTML = `
    <span><b>Boot</b> ${esc(boot || '—')}</span>
    <span><b>Ran since boot</b> ${sessionExecs}</span>
    <span><b>Deleted since boot</b> ${sessionTrash.length}</span>
    <span><b>Report</b> ${esc(r.reportId)}</span>`;

  $('#k-inst').textContent = r.processes.length ? 'ACTIVE' : 'OFFLINE';
  $('#k-inst').style.color = r.processes.length ? '#4ade80' : '#fbbf24';
  $('#k-find').textContent = String(r.findings.length);
  $('#k-svc').textContent = `${r.services.length} (${stoppedSvc} stop)`;
  $('#k-trash').textContent = `${sessionTrash.length} bin / ${r.usb.length} usb`;

  $('#exportRow').classList.remove('hidden');
  $('#sideMeta').innerHTML = `${esc(r.reportId)}<br>${esc(r.os)}<br>boot ${esc(boot || '—')}`;

  const repFindings = r.findings.filter(f => ['REPLACE_METHOD', 'TIMELINE_TAMPER', 'CHEAT_CONFIG'].includes(f.category));
  const timeline = buildTimeline(r);

  $('#c-find').textContent = r.findings.length;
  $('#c-time').textContent = timeline.length;
  $('#c-rep').textContent = repFindings.length;
  $('#c-svc').textContent = r.services.length;
  $('#c-trash').textContent = sessionTrash.length;
  $('#c-usb').textContent = r.usb.length;
  $('#c-br').textContent = r.browser.length;
  $('#c-alts').textContent = r.mcAccounts.length;

  const cleanRow = '<tr><td colspan="5" class="empty" style="color:#4ade80">CLEAN — No suspicious artifacts detected.</td></tr>';
  $('#findBody').innerHTML = r.findings.length ? r.findings.map(buildFindingRow).join('') : cleanRow;
  $('#homeFindBody').innerHTML = r.findings.length ? r.findings.slice(0, 8).map(buildFindingRow).join('') : cleanRow;
  $('#repBody').innerHTML = repFindings.length ? repFindings.map(buildFindingRow).join('') : '<tr><td colspan="5" class="empty" style="color:#4ade80">CLEAN — No Replace Method or hidden configs detected.</td></tr>';

  bindRowActions();
  applyFindFilters();

  $('#timeBody').innerHTML = timeline.length
    ? timeline.map(ev => {
        const cls = (ev.type === 'TAMPER' || ev.type === 'CHEAT') ? 'bad' : ev.type === 'DELETED' ? 'warn' : (ev.type === 'MINECRAFT' || ev.type === 'EXECUTED') ? 'ok' : '';
        return `<tr>
          <td class="mono">${esc(ev.ts)}</td>
          <td><span class="${cls ? 'st-pill ' + cls : 'cat-tag'}">${esc(ev.type)}</span></td>
          <td><strong>${esc(ev.title)}</strong></td>
          <td class="mono muted">${esc(ev.detail)}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="4" class="empty">No timeline events recorded.</td></tr>';

  $('#instBody').innerHTML = r.processes.length
    ? r.processes.map(p => `<div style="margin-bottom:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <strong>${esc(p.launcher)} (${esc(p.version)})</strong>
          <span class="st-pill ok">ACTIVE</span>
        </div>
        <div class="ev-grid">
          <span class="ev-chip"><b>PID</b> ${p.pid}</span>
          <span class="ev-chip"><b>Started</b> ${esc(p.startTime)}</span>
          <span class="ev-chip"><b>Loaded Modules</b> ${p.modules}</span>
        </div>
        <div class="sub-loc" style="margin-top:8px">${esc(p.cmd)}</div>
      </div>`).join('')
    : '<span class="st-pill warn">OFFLINE</span><p class="muted" style="margin-top:8px">No active Minecraft Java process detected during scan.</p>';

  $('#svcBody').innerHTML = r.services.length
    ? r.services.map(s => {
        const ok = s.status.toLowerCase().startsWith('running');
        return `<tr><td><strong>${esc(s.name)}</strong></td><td><span class="st-pill ${ok ? 'ok' : 'bad'}">${esc(s.status)}</span></td><td>${s.critical ? '<span class="cat-tag">Critical SS</span>' : '<span class="muted">Telemetry</span>'}</td></tr>`;
      }).join('')
    : '<tr><td colspan="3" class="empty">Service audit applies to Windows systems.</td></tr>';

  $('#trashBody').innerHTML = sessionTrash.length
    ? sessionTrash.map(t => `<tr>
        <td class="mono">#${esc(t.id)}</td>
        <td><strong>${esc(t.fileName)}</strong></td>
        <td class="mono">${esc(t.deletedAt)}</td>
        <td>${esc(t.size)}</td>
        <td class="mono muted">${esc(t.originalPath)}</td>
        <td>${t.recoverable ? `<button class="btn sm rec-btn" data-id="${esc(t.id)}">Recover</button>` : '<span class="muted">Meta-only</span>'}</td>
      </tr>`).join('')
    : '<tr><td colspan="6" class="empty">No files deleted in Recycle Bin since PC boot.</td></tr>';

  $$('.rec-btn').forEach(btn => {
    btn.onclick = async () => {
      btn.disabled = true;
      btn.textContent = 'Recovering...';
      try {
        await window.veritas.recoverTrash(btn.dataset.id);
        btn.textContent = 'Recovered';
      } catch (e) {
        alert(e.message);
        btn.textContent = 'Failed';
      }
    };
  });

  $('#usbBody').innerHTML = r.usb.length
    ? r.usb.map(u => `<tr>
        <td><span class="st-pill ${u.connected ? 'ok' : 'warn'}">${u.connected ? 'CONNECTED' : 'DISCONNECTED'}</span></td>
        <td><strong>${esc(u.name)}</strong></td>
        <td class="mono">${esc(u.drive)}</td>
        <td class="mono muted">${esc(u.serial)}</td>
      </tr>`).join('')
    : '<tr><td colspan="4" class="empty">No USB storage devices found.</td></tr>';

  $('#brBody').innerHTML = r.browser.length
    ? r.browser.map(b => `<tr>
        <td><span class="cat-tag">${esc(b.source)}</span></td>
        <td class="mono"><strong>${esc(b.target)}</strong></td>
        <td class="muted">${esc(b.note)}</td>
      </tr>`).join('')
    : '<tr><td colspan="3" class="empty" style="color:#4ade80">CLEAN — No cheat domains found.</td></tr>';

  const altHtml = r.mcAccounts.length ? r.mcAccounts.map(a => `<span class="chip">${esc(a)}</span>`).join('') : '<span class="muted">None detected</span>';
  $('#envBody').innerHTML = `
    <div style="margin-bottom:14px">
      <div class="ev-grid">
        <span class="ev-chip"><b>Hardware</b> ${esc(r.hardware)}</span>
        <span class="ev-chip"><b>VM</b> ${r.isVm ? 'DETECTED' : 'Physical'}</span>
        <span class="ev-chip"><b>VPN</b> ${esc(r.vpns.length ? r.vpns.join(', ') : 'None')}</span>
        <span class="ev-chip"><b>TCP Listeners</b> ${r.tcpListeners}</span>
      </div>
    </div>
    <div><strong>Minecraft Accounts (${r.mcAccounts.length})</strong><div class="chips">${altHtml}</div></div>`;
}

async function runInspect(filePath) {
  const out = $('#inspResult');
  out.classList.remove('hidden');
  out.innerHTML = '<span class="muted mono">Analyzing file...</span>';
  try {
    const d = await window.veritas.inspectFile(filePath);
    const kb = (d.sizeBytes / 1024).toFixed(1) + ' KB';
    out.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:10px;flex-wrap:wrap">
        <strong>${esc(d.name)}</strong>
        <div class="row-acts">
          <button class="btn sm" id="inspReveal">Reveal</button>
          <button class="btn sm" id="inspCopyHash">Copy SHA-256</button>
          <button class="btn sm" id="inspVt">VirusTotal</button>
        </div>
      </div>
      <div class="kv-table">
        <div class="kv-k">Path</div><div class="kv-v">${esc(d.path)}</div>
        <div class="kv-k">SHA-256</div><div class="kv-v">${esc(d.sha256)}</div>
        <div class="kv-k">Size</div><div class="kv-v">${esc(kb)} (${d.sizeBytes} bytes)</div>
        <div class="kv-k">Created</div><div class="kv-v">${esc(d.created)}</div>
        <div class="kv-k">Modified</div><div class="kv-v">${esc(d.modified)}</div>
        <div class="kv-k">Replace Check</div><div class="kv-v"><span class="st-pill ${d.replaceSuspect ? 'warn' : 'ok'}">${esc(d.replaceNote)}</span></div>
        <div class="kv-k">Zone.Identifier</div><div class="kv-v">${esc(d.zoneInfo)}</div>
        <div class="kv-k">Signature</div><div class="kv-v"><span class="st-pill ${d.signature === 'Valid' ? 'ok' : 'warn'}">${esc(d.signature)}</span></div>
      </div>`;
    $('#inspReveal').onclick = () => window.veritas.revealPath(d.path);
    $('#inspCopyHash').onclick = async () => {
      await navigator.clipboard.writeText(d.sha256);
      $('#inspCopyHash').textContent = 'Copied';
      setTimeout(() => { $('#inspCopyHash').textContent = 'Copy SHA-256'; }, 1400);
    };
    $('#inspVt').onclick = () => window.veritas.openExternal(`https://www.virustotal.com/gui/file/${d.sha256}`);
  } catch (e) {
    out.innerHTML = `<span class="st-pill bad">ERROR</span> <span class="mono">${esc(e.message)}</span>`;
  }
}

$('#pickInspectBtn').onclick = async () => {
  const f = await window.veritas.pickFile();
  if (f) runInspect(f);
};

const dz = $('#dropZone');
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
dz.addEventListener('drop', e => {
  e.preventDefault();
  dz.classList.remove('drag');
  const f = e.dataTransfer?.files?.[0];
  if (f?.path) runInspect(f.path);
});

function applyFindFilters() {
  const q = $('#findSearch').value.toLowerCase();
  $$('#findBody .f-row').forEach(row => {
    const okS = sevFilter === 'all' || row.dataset.sev === sevFilter;
    const okQ = !q || row.textContent.toLowerCase().includes(q);
    row.style.display = okS && okQ ? '' : 'none';
  });
}

$$('.tab').forEach(t => {
  t.onclick = () => {
    $$('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    sevFilter = t.dataset.sev;
    applyFindFilters();
  };
});
$('#findSearch').oninput = applyFindFilters;
