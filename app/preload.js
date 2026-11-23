const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('veritas', {
  minimize: () => ipcRenderer.send('win-minimize'),
  maximize: () => ipcRenderer.send('win-maximize'),
  close: () => ipcRenderer.send('win-close'),
  getSysInfo: () => ipcRenderer.invoke('get-sys-info'),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  pickFile: () => ipcRenderer.invoke('pick-file'),
  revealPath: p => ipcRenderer.invoke('reveal-path', p),
  openModsFolder: () => ipcRenderer.invoke('open-mods-folder'),
  openExternal: url => ipcRenderer.invoke('open-external', url),
  inspectFile: p => ipcRenderer.invoke('inspect-file', p),
  runExecAudit: () => ipcRenderer.invoke('run-exec-audit'),
  listProcesses: () => ipcRenderer.invoke('list-processes'),
  scanMemory: () => ipcRenderer.invoke('scan-memory'),
  runScan: opts => ipcRenderer.invoke('run-scan', opts),
  recoverTrash: id => ipcRenderer.invoke('recover-trash', id),
  exportTxt: () => ipcRenderer.invoke('export-txt'),
  onProgress: cb => ipcRenderer.on('scan-progress', (_e, data) => cb(data))
});
