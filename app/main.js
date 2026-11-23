const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

let mainWindow = null;
let lastTxtPath = null;

if (process.platform === 'win32') {
  app.setAppUserModelId('com.dips.veritas');
}

function getEngineJar() {
  const localJar = path.join(__dirname, 'engine', 'veritas-1.0.0.jar');
  if (fs.existsSync(localJar)) return localJar;
  return path.join(__dirname, '..', 'veritas', 'dist', 'veritas-1.0.0.jar');
}

function createWindow() {
  const iconPath = path.join(__dirname, 'assets', process.platform === 'win32' ? 'veritas.ico' : 'veritas.png');
  mainWindow = new BrowserWindow({
    width: 1260,
    height: 820,
    minWidth: 980,
    minHeight: 650,
    frame: false,
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    backgroundColor: '#050506',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.on('win-minimize', () => mainWindow?.minimize());
ipcMain.on('win-maximize', () => {
  if (!mainWindow) return;
  mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
});
ipcMain.on('win-close', () => mainWindow?.close());

ipcMain.handle('get-sys-info', () => ({
  platform: process.platform,
  arch: process.arch,
  hostname: os.hostname()
}));

ipcMain.handle('pick-folder', async () => {
  const res = await dialog.showOpenDialog(mainWindow, { properties: ['openDirectory'] });
  return res.canceled ? null : res.filePaths[0];
});

ipcMain.handle('pick-file', async () => {
  const res = await dialog.showOpenDialog(mainWindow, { properties: ['openFile'] });
  return res.canceled ? null : res.filePaths[0];
});

ipcMain.handle('reveal-path', async (_event, targetPath) => {
  if (!targetPath || typeof targetPath !== 'string') return false;
  const cleaned = targetPath.trim();
  if (!fs.existsSync(cleaned)) return false;
  shell.showItemInFolder(cleaned);
  return true;
});

ipcMain.handle('open-mods-folder', async () => {
  let modsPath;
  if (process.platform === 'win32') {
    modsPath = path.join(process.env.APPDATA || os.homedir(), '.minecraft', 'mods');
  } else if (process.platform === 'darwin') {
    modsPath = path.join(os.homedir(), 'Library', 'Application Support', 'minecraft', 'mods');
  } else {
    modsPath = path.join(os.homedir(), '.minecraft', 'mods');
  }
  const target = fs.existsSync(modsPath) ? modsPath : path.dirname(modsPath);
  if (!fs.existsSync(target)) return null;
  await shell.openPath(target);
  return target;
});

ipcMain.handle('open-external', async (_event, url) => {
  if (typeof url === 'string' && url.startsWith('https://www.virustotal.com/')) {
    await shell.openExternal(url);
    return true;
  }
  return false;
});

function runPsJson(script, timeoutMs = 8000) {
  return new Promise(resolve => {
    if (process.platform !== 'win32') {
      resolve(null);
      return;
    }
    const utf8Script = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8;\n${script}`;
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', utf8Script],
      { windowsHide: true, timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' },
      (err, stdout) => {
        if (err || !stdout || !stdout.trim()) {
          resolve(null);
          return;
        }
        try {
          resolve(JSON.parse(stdout.trim()));
        } catch (_) {
          resolve(null);
        }
      }
    );
  });
}

function checkAuthenticode(filePath) {
  return new Promise(resolve => {
    if (process.platform !== 'win32') {
      resolve('N/A (non-Windows)');
      return;
    }
    const safePath = filePath.replace(/'/g, "''");
    execFile(
      'powershell.exe',
      ['-NoProfile', '-Command', `(Get-AuthenticodeSignature -LiteralPath '${safePath}').Status`],
      { windowsHide: true, timeout: 4000 },
      (err, stdout) => {
        if (err) resolve('Unknown');
        else resolve((stdout || '').trim() || 'Unknown');
      }
    );
  });
}

ipcMain.handle('inspect-file', async (_event, filePath) => {
  if (!filePath || !fs.existsSync(filePath)) throw new Error('File does not exist');
  const stat = fs.statSync(filePath);
  if (stat.isDirectory()) throw new Error('Select a file, not a folder');

  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');

  let zoneInfo = 'None (local or stripped)';
  if (process.platform === 'win32') {
    try {
      const ads = fs.readFileSync(filePath + ':Zone.Identifier', 'utf8');
      const host = (ads.match(/HostUrl=(.+)/i) || [])[1];
      const ref = (ads.match(/ReferrerUrl=(.+)/i) || [])[1];
      zoneInfo = host ? host.trim() : (ref ? ref.trim() : 'Internet Zone (ZoneId=3)');
    } catch (_) {}
  }

  const createdMs = stat.birthtimeMs || stat.ctimeMs;
  const modifiedMs = stat.mtimeMs;
  const diffSec = Math.round((createdMs - modifiedMs) / 1000);
  const replaceSuspect = diffSec > 300;
  const signature = await checkAuthenticode(filePath);

  return {
    name: path.basename(filePath),
    path: filePath,
    sizeBytes: stat.size,
    sha256,
    created: new Date(createdMs).toISOString().replace('T', ' ').slice(0, 19),
    modified: new Date(modifiedMs).toISOString().replace('T', ' ').slice(0, 19),
    replaceSuspect,
    replaceNote: replaceSuspect
      ? `Created ${Math.round(diffSec / 60)} min AFTER modified date (possible copied/replaced file)`
      : 'Normal timestamp order',
    zoneInfo,
    signature
  };
});

const SUS_EXEC_RE = /(vape|slinky|sluded|sludedloader|drip|dream|entropy|koid|whiteout|doomsday|karma|autoclick|opautoclick|gsautoclick|cheatengine|extremeinjector|xenos|ccleaner|bleachbit|wevtutil|fsutil|privazer|r-wipe|ghostclient|wurst|meteor|aristois|liquidbounce|impact|futureclient|rusherhack|boze|mio|prestige|grimclient|haru|raven|breeze|catlean|yukio|sapphire|exelon|icetea|akira|antic|cheatloader|eulen|redengine|hxcheats|susano|2take1|cherax|kiddions|modest-menu|yimmenu|tzproject|desudo|synapsex|krnl|fluxus|solara|jjsploit|dx9ware|aimmy)/i;

ipcMain.handle('run-exec-audit', async () => {
  const result = {
    bootTime: '',
    bootMs: 0,
    pca: [],
    prefetch: [],
    recent: [],
    exclusions: [],
    tamperEvents: [],
    bamCount: 0
  };

  if (process.platform === 'win32') {
    const psAudit = `
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$out = @{ bootTime = $boot.ToString('yyyy-MM-dd HH:mm:ss'); bootMs = [int64]([DateTimeOffset]$boot).ToUnixTimeMilliseconds(); pca = @(); exclusions = @(); tamper = @(); bam = 0 }
try {
  function R13([string]$s){ $a=$s.ToCharArray(); for($i=0;$i -lt $a.Length;$i++){ $c=[int]$a[$i]; if($c -ge 65 -and $c -le 90){$a[$i]=[char]((($c-65+13)%26)+65)} elseif($c -ge 97 -and $c -le 122){$a[$i]=[char]((($c-97+13)%26)+97)} }; -join $a }
  $ua = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count' -ErrorAction SilentlyContinue
  if ($ua) {
    foreach ($p in $ua.PSObject.Properties) {
      if ($p.Value -is [byte[]] -and $p.Value.Length -ge 68) {
        $n = R13 $p.Name
        $ft = [BitConverter]::ToInt64($p.Value, 60)
        if ($ft -gt 0 -and $n -match '^[A-Za-z]:\\\\.+\\.exe$') {
          $dt = [DateTime]::FromFileTime($ft)
          if ($dt -ge $boot) {
            $out.pca += @{
              path = $n
              name = [System.IO.Path]::GetFileName($n)
              exists = (Test-Path -LiteralPath $n)
              inSession = $true
              time = $dt.ToString('yyyy-MM-dd HH:mm:ss')
              runs = [BitConverter]::ToInt32($p.Value, 4)
            }
          }
        }
      }
    }
  }
} catch {}
try {
  $mp = Get-MpPreference -ErrorAction Stop
  foreach ($p in @($mp.ExclusionPath)) { if ($p) { $out.exclusions += @{ type = 'Path'; value = [string]$p } } }
  foreach ($p in @($mp.ExclusionProcess)) { if ($p) { $out.exclusions += @{ type = 'Process'; value = [string]$p } } }
  foreach ($p in @($mp.ExclusionExtension)) { if ($p) { $out.exclusions += @{ type = 'Extension'; value = [string]$p } } }
} catch {}
try {
  $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 5 -ErrorAction SilentlyContinue
  foreach ($e in @($ev)) {
    if ($e.TimeCreated -ge $boot) {
      $out.tamper += @{ id = 104; type = 'EventLog Cleared'; time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); detail = ($e.Message -split "\`n")[0] }
    }
  }
} catch {}
try {
  $ev2 = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 1 } -MaxEvents 5 -ErrorAction SilentlyContinue
  foreach ($e in @($ev2)) {
    if ($e.TimeCreated -ge $boot) {
      $out.tamper += @{ id = 1; type = 'System Clock Changed'; time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); detail = ($e.Message -split "\`n")[0] }
    }
  }
} catch {}
try {
  $bamKeys = Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings' -ErrorAction SilentlyContinue
  foreach ($k in @($bamKeys)) { $out.bam += ($k.Property | Measure-Object).Count }
} catch {}
$out | ConvertTo-Json -Depth 4 -Compress
`;
    const psData = await runPsJson(psAudit, 8000);
    const bootMs = psData ? Number(psData.bootMs || 0) : 0;
    if (psData) {
      result.bootTime = psData.bootTime || '';
      result.bootMs = bootMs;
      const rawPca = Array.isArray(psData.pca) ? psData.pca : [];
      result.pca = rawPca.map(item => ({
        name: item.name,
        path: item.path,
        exists: Boolean(item.exists),
        inSession: true,
        time: item.time || '',
        runs: Number(item.runs || 0),
        flagged: SUS_EXEC_RE.test(item.path || '')
      })).sort((a, b) => (Number(b.flagged) - Number(a.flagged))
        || (Number(!b.exists) - Number(!a.exists))
        || String(b.time).localeCompare(String(a.time)));
      result.exclusions = Array.isArray(psData.exclusions) ? psData.exclusions : [];
      result.tamperEvents = Array.isArray(psData.tamper) ? psData.tamper : [];
      result.bamCount = Number(psData.bam || 0);
    }

    const pfDir = 'C:\\Windows\\Prefetch';
    try {
      const files = fs.readdirSync(pfDir).filter(f => f.toLowerCase().endsWith('.pf'));
      const entries = [];
      for (const f of files) {
        try {
          const full = path.join(pfDir, f);
          const st = fs.statSync(full);
          if (bootMs && st.mtimeMs < bootMs) continue;
          const exeName = f.replace(/-[0-9A-F]{8}\.pf$/i, '');
          entries.push({
            name: exeName,
            file: f,
            time: new Date(st.mtimeMs).toISOString().replace('T', ' ').slice(0, 19),
            mtime: st.mtimeMs,
            flagged: SUS_EXEC_RE.test(exeName)
          });
        } catch (_) {}
      }
      entries.sort((a, b) => (b.flagged - a.flagged) || (b.mtime - a.mtime));
      result.prefetch = entries.slice(0, 60);
    } catch (_) {}

    const recDir = path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'Recent');
    try {
      const files = fs.readdirSync(recDir).filter(f => f.toLowerCase().endsWith('.lnk'));
      const entries = [];
      for (const f of files) {
        try {
          const full = path.join(recDir, f);
          const st = fs.statSync(full);
          if (bootMs && st.mtimeMs < bootMs) continue;
          const clean = f.replace(/\.lnk$/i, '');
          entries.push({
            name: clean,
            path: full,
            time: new Date(st.mtimeMs).toISOString().replace('T', ' ').slice(0, 19),
            mtime: st.mtimeMs,
            flagged: SUS_EXEC_RE.test(clean)
          });
        } catch (_) {}
      }
      entries.sort((a, b) => (b.flagged - a.flagged) || (b.mtime - a.mtime));
      result.recent = entries.slice(0, 45);
    } catch (_) {}
  } else {
    for (const hist of ['.zsh_history', '.bash_history']) {
      const p = path.join(os.homedir(), hist);
      if (fs.existsSync(p)) {
        try {
          const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/).slice(-60).reverse();
          for (const l of lines) {
            if (!l.trim()) continue;
            result.recent.push({ name: l.trim().slice(0, 120), path: p, time: hist, flagged: SUS_EXEC_RE.test(l) });
          }
        } catch (_) {}
      }
    }
  }

  return result;
});

ipcMain.handle('list-processes', async () => {
  if (process.platform === 'win32') {
    const ps = `
Get-Process | Where-Object { $_.Path } | ForEach-Object {
  $st = ''
  try { $st = $_.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch {}
  [PSCustomObject]@{
    pid = $_.Id
    name = $_.ProcessName
    path = $_.Path
    memMb = [Math]::Round($_.WorkingSet64 / 1MB, 1)
    start = $st
  }
} | Sort-Object memMb -Descending | Select-Object -First 80 | ConvertTo-Json -Compress
`;
    const list = await runPsJson(ps, 6000);
    const arr = Array.isArray(list) ? list : (list ? [list] : []);
    return arr.map(p => {
      const lp = String(p.path || '').toLowerCase();
      const susLoc = lp.includes('\\temp\\') || lp.includes('\\downloads\\') || lp.includes('\\appdata\\local\\temp');
      const susName = SUS_EXEC_RE.test(p.name || '') || SUS_EXEC_RE.test(lp);
      return { ...p, flagged: susLoc || susName, reason: susName ? 'Known cheat/macro/tool keyword' : (susLoc ? 'Running from Temp / Downloads' : '') };
    });
  }
  return [];
});

ipcMain.handle('scan-memory', async () => {
  if (process.platform === 'win32') {
    const memExe = path.join(__dirname, 'engine', 'veritas-mem.exe');
    if (!fs.existsSync(memExe)) return { scanned: [] };
    return new Promise(resolve => {
      execFile(memExe, [], { windowsHide: true, timeout: 12000, maxBuffer: 2 * 1024 * 1024, encoding: 'utf8' }, (err, stdout) => {
        if (err || !stdout || !stdout.trim()) {
          resolve({ scanned: [] });
          return;
        }
        try {
          resolve(JSON.parse(stdout.trim()));
        } catch (_) {
          resolve({ scanned: [] });
        }
      });
    });
  }

  if (process.platform === 'linux') {
    const scanned = [];
    try {
      for (const entry of fs.readdirSync('/proc')) {
        if (!/^\d+$/.test(entry)) continue;
        const pid = Number(entry);
        let comm = '';
        try { comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim(); } catch (_) { continue; }
        const low = comm.toLowerCase();
        if (!['java', 'javaw', 'gta5.exe', 'fivem', 'roblox'].some(t => low.includes(t))) continue;
        const hits = new Set();
        let regions = 0;
        let unlinked = 0;
        try {
          const maps = fs.readFileSync(`/proc/${pid}/maps`, 'utf8').split('\n');
          regions = maps.length;
          for (const line of maps) {
            const lm = line.toLowerCase();
            if ((lm.includes('/dev/shm/') || lm.includes('/tmp/')) && lm.includes('.so')) {
              hits.add(line.trim().split(/\s+/).pop());
            }
            if (lm.includes('.so') && lm.includes('(deleted)')) {
              unlinked++;
              hits.add('UNLINKED_SO:' + line.trim().split(/\s+/).slice(-2).join(' '));
            }
            if (SUS_EXEC_RE.test(lm)) {
              hits.add(line.trim().split(/\s+/).pop());
            }
          }
        } catch (_) {}
        scanned.push({ pid, name: comm, isJava: true, regions, manualMappedPe: unlinked, hits: [...hits] });
      }
    } catch (_) {}
    return { scanned };
  }

  if (process.platform === 'darwin') {
    return new Promise(resolve => {
      execFile('pgrep', ['-il', 'java|minecraft|roblox'], { timeout: 4000, encoding: 'utf8' }, (err, out) => {
        if (err || !out) { resolve({ scanned: [] }); return; }
        const lines = out.trim().split('\n').filter(Boolean);
        const scanned = [];
        let pending = lines.length;
        if (!pending) { resolve({ scanned }); return; }
        for (const l of lines) {
          const [pidStr, ...rest] = l.trim().split(/\s+/);
          const pid = Number(pidStr);
          const name = rest.join(' ') || 'java';
          execFile('lsof', ['-p', String(pid)], { timeout: 4000, maxBuffer: 2 * 1024 * 1024, encoding: 'utf8' }, (_e, lo) => {
            const hits = new Set();
            const rows = (lo || '').split('\n');
            for (const r of rows) {
              const lr = r.toLowerCase();
              if (lr.includes('.dylib') && (lr.includes('/tmp/') || SUS_EXEC_RE.test(lr))) {
                hits.add(r.trim().split(/\s+/).pop());
              }
            }
            scanned.push({ pid, name, isJava: true, regions: rows.length, manualMappedPe: 0, hits: [...hits] });
            if (--pending === 0) resolve({ scanned });
          });
        }
      });
    });
  }

  return { scanned: [] };
});

ipcMain.handle('run-scan', async (event, opts) => {
  const jar = getEngineJar();
  const stamp = Date.now();
  const jsonOut = path.join(os.tmpdir(), `veritas-gui-${stamp}.json`);
  const txtOut = path.join(os.tmpdir(), `veritas-log-${stamp}.txt`);
  lastTxtPath = txtOut;

  const args = ['-jar', jar, 'scan', '--no-color', '--gui-json', jsonOut, '--txt', txtOut];
  if (opts?.deep) args.push('--deep');
  if (opts?.customPath) args.push(opts.customPath);

  return new Promise((resolve, reject) => {
    const proc = spawn('java', args, { windowsHide: true });
    let errBuf = '';

    proc.stdout.on('data', chunk => {
      const lines = chunk.toString('utf8').split(/\r?\n/);
      for (const line of lines) {
        const m = line.match(/\[\s*(\d+)\/12\]\s*(.+)/);
        if (m) {
          event.sender.send('scan-progress', { step: Number(m[1]), total: 12, label: m[2].trim() });
        }
      }
    });

    proc.stderr.on('data', d => { errBuf += d.toString('utf8'); });

    proc.on('error', err => reject(new Error('Java 17+ is required: ' + err.message)));
    proc.on('close', code => {
      if (code !== 0 || !fs.existsSync(jsonOut)) {
        reject(new Error(errBuf.trim() || `Scan exited with code ${code}`));
        return;
      }
      try {
        const data = JSON.parse(fs.readFileSync(jsonOut, 'utf8'));
        fs.unlinkSync(jsonOut);
        resolve(data);
      } catch (e) {
        reject(e);
      }
    });
  });
});

ipcMain.handle('recover-trash', async (_event, id) => {
  const jar = getEngineJar();
  return new Promise((resolve, reject) => {
    const proc = spawn('java', ['-jar', jar, 'recover', String(id), '--no-color'], { windowsHide: true });
    let out = '';
    let err = '';
    proc.stdout.on('data', d => { out += d.toString('utf8'); });
    proc.stderr.on('data', d => { err += d.toString('utf8'); });
    proc.on('close', code => {
      if (code !== 0) {
        reject(new Error(err.trim() || 'Recovery failed'));
        return;
      }
      const line = out.split(/\r?\n/).find(l => l.startsWith('RECOVERED:'));
      const dest = line ? line.slice('RECOVERED:'.length).trim() : '';
      if (dest) shell.showItemInFolder(dest);
      resolve(dest);
    });
  });
});

ipcMain.handle('export-txt', async () => {
  if (!lastTxtPath || !fs.existsSync(lastTxtPath)) return null;
  const res = await dialog.showSaveDialog(mainWindow, {
    defaultPath: `veritas-forensic-log-${new Date().toISOString().slice(0, 10)}.txt`,
    filters: [{ name: 'Text Log', extensions: ['txt'] }]
  });
  if (res.canceled || !res.filePath) return null;
  fs.copyFileSync(lastTxtPath, res.filePath);
  return res.filePath;
});
