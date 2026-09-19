export const API = '';

let token: string = localStorage.getItem('token') || '';

export function setToken(t: string) {
  token = t;
  localStorage.setItem('token', t);
}

export function getToken() {
  return token;
}

export async function request(path: string, opts: RequestInit = {}): Promise<any> {
  const res = await fetch(API + path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401) {
    localStorage.removeItem('token');
    if (!window.location.hash.startsWith('#/login')) {
      window.location.hash = '#/login';
      window.location.reload();
    }
    throw new Error('未登录或登录已过期');
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  login: (username: string, password: string) =>
    request('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  changePassword: (oldPassword: string, newPassword: string) =>
    request('/api/auth/password', { method: 'POST', body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }) }),
  projects: () => request('/api/projects'),
  deleteProject: (id: number) => request(`/api/projects/${id}`, { method: 'DELETE' }),
  createProject: (name: string, description: string) =>
    request('/api/projects', { method: 'POST', body: JSON.stringify({ name, description }) }),
  stats: (pid: number) => request(`/api/stats?project_id=${pid}`),
  listAssets: (pid: number, type: string, q = '', limit = 100, offset = 0) =>
    request(`/api/assets?project_id=${pid}&type=${type}&q=${encodeURIComponent(q)}&limit=${limit}&offset=${offset}`),
  ipDetail: (pid: number, ip: string) => request(`/api/assets/ip/${ip}?project_id=${pid}`),
  vulnDetail: (id: number) => request(`/api/vulnerabilities/${id}`),
  getAIConfig: () => request('/api/system/ai'),
  setAIConfig: (cfg: any) => request('/api/system/ai', { method: 'PUT', body: JSON.stringify(cfg) }),
  aiModels: (baseUrl?: string, apiKey?: string) =>
    request('/api/system/ai/models', { method: 'POST', body: JSON.stringify({ base_url: baseUrl || '', api_key: apiKey || '' }) }),
  aiAnalyzeAll: (pid: number) => request(`/api/vulnerabilities/ai-analyze-all?project_id=${pid}`, { method: 'POST' }),
  aiAnalyze: (id: number) => request(`/api/vulnerabilities/${id}/ai-analyze`, { method: 'POST' }),
  vulnsClear: (pid: number) => request(`/api/vulnerabilities?project_id=${pid}`, { method: 'DELETE' }),
  vulnDelete: (id: number) => request(`/api/vulnerabilities/${id}`, { method: 'DELETE' }),
  vulnMark: (id: number, mark: string) =>
    request(`/api/vulnerabilities/${id}/mark`, { method: 'PUT', body: JSON.stringify({ mark }) }),
  vulns: (pid: number, severity = '', q = '', mark = '', limit = 20, offset = 0) =>
    request(`/api/vulnerabilities?project_id=${pid}&limit=${limit}&offset=${offset}&severity=${severity}&q=${encodeURIComponent(q)}&mark=${mark}`),
  tasks: (pid: number) => request(`/api/tasks?project_id=${pid}&limit=100`),
  monitorTasks: (pid: number) => request(`/api/tasks?project_id=${pid}&recurring=true&limit=100`),
  createTask: (t: any) => request('/api/tasks', { method: 'POST', body: JSON.stringify(t) }),
  updateTask: (id: number, t: any) => request(`/api/tasks/${id}`, { method: 'PUT', body: JSON.stringify(t) }),
  taskLogs: (id: number) => request(`/api/tasks/${id}/logs`),
  taskAction: (id: number, action: string) =>
    request(`/api/tasks/${id}/${action}`, { method: 'POST' }),
  taskRun: (id: number) => request(`/api/tasks/${id}/run`, { method: 'POST' }),
  taskDelete: (id: number) => request(`/api/tasks/${id}`, { method: 'DELETE' }),
  assetsClear: (type: string, pid: number) => request(`/api/assets/${type}?project_id=${pid}`, { method: 'DELETE' }),
  assetDelete: (type: string, id: number, project_id: number) =>
    request(`/api/assets/${type}/${id}?project_id=${project_id}`, { method: 'DELETE' }),
  getWhitelist: () => request('/api/system/whitelist'),
  setWhitelist: (items: string[]) =>
    request('/api/system/whitelist', { method: 'PUT', body: JSON.stringify({ items }) }),
  importAssets: (project_id: number, content: string, type: string) =>
    request('/api/assets', { method: 'POST', body: JSON.stringify({ project_id, content, type }) }),
  changes: (pid: number, page = 1, size = 20) => request(`/api/changes?project_id=${pid}&limit=${size}&offset=${(page - 1) * size}`),
  search: (pid: number, q: string) => request(`/api/search?project_id=${pid}&q=${encodeURIComponent(q)}`),
  plugins: () => request('/api/system/plugins'),
  sysLogs: () => request('/api/system/logs'),
  getProxy: () => request('/api/system/proxy'),
  setProxy: (proxy: any) =>
    request('/api/system/proxy', { method: 'PUT', body: JSON.stringify(proxy) }),
  testProxy: (proxy: any, target: string) =>
    request('/api/system/proxy/test', { method: 'POST', body: JSON.stringify({ proxy, target }) }),
  getMapping: () => request('/api/system/mapping'),
  setMapping: (mapping: any) =>
    request('/api/system/mapping', { method: 'PUT', body: JSON.stringify(mapping) }),
  testMapping: (mapping: any, target: string) =>
    request('/api/system/mapping/test', { method: 'POST', body: JSON.stringify({ mapping, target }) }),
  mappingQuery: (project_id: number, target: string) =>
    request('/api/mapping/query', { method: 'POST', body: JSON.stringify({ project_id, target }) }),
  vulnRules: (params: string) => request(`/api/vuln-rules?${params}`),
  vulnRuleStats: () => request('/api/vuln-rules/stats'),
  getVulnRule: (id: number) => request(`/api/vuln-rules/${id}`),
  toggleVulnRule: (id: number, enabled: boolean) =>
    request(`/api/vuln-rules/${id}/toggle`, { method: 'POST', body: JSON.stringify({ enabled }) }),
  deleteVulnRule: (id: number) => request(`/api/vuln-rules/${id}`, { method: 'DELETE' }),
  clearVulnRules: () => request(`/api/vuln-rules`, { method: 'DELETE' }),
  testVulnRule: (id: number, target: string) =>
    request(`/api/vuln-rules/${id}/test`, { method: 'POST', body: JSON.stringify({ target }) }),
  pocFiles: (path: string) => request(`/api/poc-files?path=${encodeURIComponent(path)}`),
  pocMkdir: (path: string) =>
    request('/api/poc-files/mkdir', { method: 'POST', body: JSON.stringify({ path }) }),
  pocSave: (path: string, content: string) =>
    request('/api/poc-files/save', { method: 'POST', body: JSON.stringify({ path, content }) }),
  pocDelete: (path: string) =>
    request(`/api/poc-files?path=${encodeURIComponent(path)}`, { method: 'DELETE' }),
  pocImport: (path: string) =>
    request('/api/poc-files/import', { method: 'POST', body: JSON.stringify({ path }) }),
  getWatcher: () => request('/api/vuln-rules/watcher'),
  setWatcher: (cfg: any) =>
    request('/api/vuln-rules/watcher', { method: 'PUT', body: JSON.stringify(cfg) }),
  getRuleSources: () => request('/api/vuln-rules/sources'),
  setRuleSources: (cfg: any) =>
    request('/api/vuln-rules/sources', { method: 'PUT', body: JSON.stringify(cfg) }),
  updateRuleSources: () =>
    request('/api/vuln-rules/sources/update', { method: 'POST' }),
  getRuleSettings: () => request('/api/vuln-rules/settings'),
  setRuleSettings: (s: any) =>
    request('/api/vuln-rules/settings', { method: 'PUT', body: JSON.stringify(s) }),
  getWihSettings: () => request('/api/wih/settings'),
  setWihSettings: (cfg: any) =>
    request('/api/wih/settings', { method: 'PUT', body: JSON.stringify(cfg) }),
  testWih: (target: string) =>
    request('/api/wih/test', { method: 'POST', body: JSON.stringify({ target }) }),
};
