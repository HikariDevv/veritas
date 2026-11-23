window.VeritasAI = (function () {
  function norm(s) {
    return String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  }

  function formatItem(f) {
    return `• [${f.severity}] ${f.title} (${f.location})`;
  }

  function answer(question, report, audit, mem) {
    if (!report) {
      return {
        tag: 'NO SCAN DATA',
        title: 'Run Full SS Scan first',
        lines: ['Click "RUN FULL SS SCAN" so Veritas AI can analyze javaw.exe RAM, UserAssist since boot, deleted files, and bypasses.']
      };
    }

    const q = norm(question);
    const boot = report.bootTime || 'Unknown';
    const findings = report.findings || [];
    const inSessionExecs = (audit && audit.pca) ? audit.pca : [];
    const deletedTrash = (report.trash || []).filter(t => !boot || boot === 'Unknown' || String(t.deletedAt || '') >= boot);
    const stoppedSvcs = (report.services || []).filter(s => !s.status.toLowerCase().startsWith('running'));
    const excl = (audit && audit.exclusions) ? audit.exclusions : [];
    const tamper = (audit && audit.tamperEvents) ? audit.tamperEvents : [];
    const memScanned = (mem && mem.scanned) ? mem.scanned : [];
    const memHits = memScanned.filter(m => (m.hits || []).length > 0 || m.manualMappedPe > 0);

    if (q.includes('ram') || q.includes('memor') || q.includes('javaw') || q.includes('inyect') || q.includes('inject') || q.includes('cheat') || q.includes('ejecut') || q.includes('uso') || q.includes('ran') || q.includes('sluded') || q.includes('slinky')) {
      const cheats = findings.filter(f => ['RAM_INJECTION', 'IN_SESSION_CHEAT', 'INJECTABLE_BINARY', 'INJECTED_MODULE', 'JVM_AGENT', 'SELF_DESTRUCT_TRACE', 'PREFETCH'].includes(f.category));
      const uaCheats = inSessionExecs.filter(x => x.flagged || !x.exists);
      const lines = [`Session started at PC boot: ${boot}`];
      if (memHits.length) {
        lines.push('LIVE RAM MEMORY DETECTIONS (javaw.exe / explorer.exe):');
        memHits.forEach(m => {
          lines.push(`• ${m.name}.exe (PID ${m.pid}, ${m.regions} regions, ${m.manualMappedPe} manual-mapped PE) -> ${m.hits.join(', ')}`);
        });
      }
      if (cheats.length) {
        lines.push(`High-confidence cheat/injectable findings (${cheats.length}):`);
        cheats.slice(0, 8).forEach(f => lines.push(formatItem(f)));
      }
      if (uaCheats.length) {
        lines.push('Executed/self-destructed in current session (UserAssist):');
        uaCheats.slice(0, 6).forEach(u => {
          lines.push(`• ${u.name} at ${u.time} (${u.runs} runs, ${u.exists ? 'Present' : 'DELETED AFTER RUN'}) -> ${u.path}`);
        });
      }
      if (!memHits.length && !cheats.length && !uaCheats.length) {
        lines.push('No cheats, manual-mapped DLLs, or RAM traces were detected in this session.');
      }
      return {
        tag: (memHits.length || cheats.length || uaCheats.length) ? 'RAM & INJECTABLE ANALYSIS' : 'CLEAN SESSION',
        title: (memHits.length || cheats.length) ? `Detected ${cheats.length} finding(s) + ${memHits.length} RAM process hit(s)` : 'No in-session cheats detected',
        lines
      };
    }

    if (q.includes('instancia') || q.includes('instance') || q.includes('minecraft') || q.includes('jvm') || q.includes('dll')) {
      const procs = report.processes || [];
      const modFindings = findings.filter(f => ['RAM_INJECTION', 'INJECTED_MODULE', 'JVM_AGENT', 'INJECTABLE_BINARY'].includes(f.category));
      const lines = [];
      if (!procs.length) {
        lines.push('Minecraft is currently OFFLINE (no active javaw process during scan).');
      } else {
        procs.forEach(p => {
          lines.push(`Active instance: ${p.launcher} (${p.version}) | PID ${p.pid} | Started ${p.startTime} | ${p.modules} loaded modules.`);
        });
      }
      if (modFindings.length) {
        lines.push(`Found ${modFindings.length} injectable DLL/RAM/JVM alert(s):`);
        modFindings.slice(0, 6).forEach(f => lines.push(formatItem(f)));
      } else {
        lines.push('No injected DLLs or unauthorized JVM agents were detected.');
      }
      return {
        tag: 'INSTANCE AUDIT',
        title: procs.length ? `Minecraft ACTIVE (${procs[0].launcher})` : 'Minecraft OFFLINE',
        lines
      };
    }

    if (q.includes('borr') || q.includes('delet') || q.includes('trash') || q.includes('papelera') || q.includes('destruct')) {
      const delExecs = inSessionExecs.filter(x => !x.exists);
      const lines = [`Filtering deletions since PC boot (${boot}):`];
      if (delExecs.length) {
        lines.push(`Executed & deleted in this session (${delExecs.length}):`);
        delExecs.slice(0, 6).forEach(u => lines.push(`• [DELETED EXE] ${u.name} (ran at ${u.time}) -> ${u.path}`));
      }
      if (deletedTrash.length) {
        lines.push(`Recycle Bin items deleted since boot (${deletedTrash.length}):`);
        deletedTrash.slice(0, 8).forEach(t => lines.push(`• [RECYCLE BIN #${t.id}] ${t.fileName} (${t.size}) at ${t.deletedAt} -> ${t.originalPath}`));
      }
      if (!delExecs.length && !deletedTrash.length) {
        lines.push('No files were deleted in Recycle Bin or after execution since PC boot.');
      }
      return {
        tag: 'DELETION & SELF-DESTRUCT',
        title: `${delExecs.length} deleted EXE(s), ${deletedTrash.length} Recycle Bin item(s) since boot`,
        lines
      };
    }

    if (q.includes('bypass') || q.includes('servicio') || q.includes('service') || q.includes('defender') || q.includes('log') || q.includes('reloj') || q.includes('clock')) {
      const lines = [
        `Stopped Windows forensic services: ${stoppedSvcs.length}`,
        ...stoppedSvcs.map(s => `• [STOPPED] ${s.name}`),
        `Windows Defender Exclusions: ${excl.length}`,
        ...excl.slice(0, 6).map(e => `• [${e.type}] ${e.value}`),
        `In-session EventLog/Clock tamper events: ${tamper.length}`,
        ...tamper.map(t => `• [ID ${t.id}] ${t.type} at ${t.time}`)
      ];
      return {
        tag: 'BYPASS & TAMPER AUDIT',
        title: (stoppedSvcs.length || excl.length || tamper.length) ? 'Tamper or bypass indicators present' : 'No bypass indicators detected',
        lines
      };
    }

    if (q.includes('replace') || q.includes('mod') || q.includes('jar') || q.includes('config')) {
      const rep = findings.filter(f => ['REPLACE_METHOD', 'TIMELINE_TAMPER', 'CHEAT_CONFIG', 'SUSPICIOUS_JAR'].includes(f.category));
      const lines = rep.length
        ? [`Found ${rep.length} Replace Method / JAR / hidden config alert(s):`, ...rep.slice(0, 8).map(formatItem)]
        : [`Scanned ${report.jarsScanned} JAR files — no Replace Method tampering or hidden configs detected.`];
      return { tag: 'REPLACE & MODS', title: rep.length ? `${rep.length} mod/config alert(s)` : 'Mods & JARs are clean', lines };
    }

    const crit = findings.filter(f => f.severity === 'CRITICAL');
    const high = findings.filter(f => f.severity === 'HIGH');
    let recommendation = 'CLEAN — Safe to pass screenshare.';
    if (crit.length > 0 || memHits.length > 0) recommendation = 'BAN RECOMMENDED — Critical in-session or live RAM cheat evidence found.';
    else if (high.length > 0 || stoppedSvcs.length > 0 || excl.length > 0) recommendation = 'MANUAL REVIEW — Suspicious traces or bypasses require verification.';

    const lines = [
      `Verdict: ${report.verdict} (${report.score}/100) | Boot: ${boot}`,
      `Recommendation: ${recommendation}`,
      `Summary: ${crit.length} Critical, ${high.length} High, ${memHits.length} RAM Hit(s), ${inSessionExecs.length} executed since boot, ${deletedTrash.length} Recycle Bin deletions since boot.`
    ];
    crit.slice(0, 5).forEach(f => lines.push(formatItem(f)));
    return { tag: 'SS VERDICT', title: recommendation, lines };
  }

  return { answer };
})();
