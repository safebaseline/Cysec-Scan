import { useEffect, useRef, useState, type ReactNode } from 'react';
import { api, setToken, getToken } from './api';
import './index.css';

type Project = { id: number; name: string; description: string };
type AskState = { title: string; placeholder?: string; confirmOnly?: boolean; resolve: (v: any) => void } | null;
let askHandler: ((opts: { title: string; placeholder?: string; confirmOnly?: boolean }, resolve: (v: any) => void) => void) | null = null;
function askText(title: string, placeholder = ''): Promise<string | null> { return new Promise((resolve) => { if (!askHandler) return resolve(null); askHandler({ title, placeholder }, resolve); }); }
function askConfirm(title: string): Promise<boolean> { return new Promise((resolve) => { if (!askHandler) return resolve(false); askHandler({ title, confirmOnly: true }, resolve); }); }
function AskDialog() { const [st, setSt] = useState<AskState>(null); const [val, setVal] = useState('');
  useEffect(() => { askHandler = (opts, resolve) => { setVal(''); setSt({ ...opts, resolve }); }; return () => { askHandler = null; }; }, []);
  if (!st) return null; const close = (v: any) => { const r = st.resolve; setSt(null); r(v); };
  return (<div className="modal" style={{ zIndex: 50 }}><div className="modal-body" style={{ maxWidth: 420 }} onClick={(e) => e.stopPropagation()}>
    <div className="card-title">{st.title}</div><div className="form">
      {!st.confirmOnly && <input autoFocus placeholder={st.placeholder || ''} value={val} onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') close(val.trim() || null); }} />}
      <div className="toolbar"><button onClick={() => close(st.confirmOnly ? true : (val.trim() || null))}>确定</button><button onClick={() => close(st.confirmOnly ? false : null)}>取消</button></div>
    </div></div></div>); }

function Card({ title, children }: { title?: string; children: ReactNode }) { return (<div className="card">{title && <div className="card-title">{title}</div>}{children}</div>); }
function Table({ cols, rows, onRow, actions }: { cols: string[]; rows: any[]; onRow?: (r: any) => void; actions?: (r: any) => ReactNode }) {
  const span = cols.length + (actions ? 1 : 0);
  return (<table className="tbl"><thead><tr>{cols.map((c) => <th key={c}>{label(c)}</th>)}{actions && <th style={{ textAlign: 'right' }}>操作</th>}</tr></thead>
    <tbody>{rows.length === 0 && <tr><td colSpan={span} className="empty">暂无数据</td></tr>}
    {rows.map((r, i) => (<tr key={i} onClick={() => onRow?.(r)} className={onRow ? 'clickable' : ''}>
      {cols.map((k) => { const v = (r as any)[k]; return <td key={k}>{cell(v)}</td>; })}
      {actions && <td className="row-act" onClick={(e) => e.stopPropagation()}>{actions(r)}</td>}</tr>))}</tbody></table>); }
function cell(v: any): ReactNode { if (v === null || v === undefined || v === '') return <span className="muted">-</span>;
  if (typeof v === 'string' && LABEL_MAP[v]) return label(v); if (typeof v === 'boolean') return v ? '✔' : '✘';
  if (typeof v === 'object') return JSON.stringify(v).slice(0, 80); const s = String(v); return s.length > 80 ? s.slice(0, 80) + '…' : s; }

// 分页：每页条数与后端 limit/offset 对应
const PAGE_SIZE = 20;
function Pager({ total, page, setPage }: { total: number; page: number; setPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (total <= PAGE_SIZE) return null;
  const cur = Math.min(Math.max(1, page), pages);
  const start = Math.max(1, Math.min(cur - 2, pages - 4));
  const nums: number[] = []; for (let i = start; i <= Math.min(pages, start + 4); i++) nums.push(i);
  return (<div className="pager">
    <button disabled={cur <= 1} onClick={() => setPage(cur - 1)}>‹ 上一页</button>
    {start > 1 && <><button className={cur === 1 ? 'active' : ''} onClick={() => setPage(1)}>1</button>{start > 2 && <span className="muted">…</span>}</>}
    {nums.map((p) => <button key={p} className={p === cur ? 'active' : ''} onClick={() => setPage(p)}>{p}</button>)}
    {start + 4 < pages && <><span className="muted">…</span><button className={cur === pages ? 'active' : ''} onClick={() => setPage(pages)}>{pages}</button></>}
    <button disabled={cur >= pages} onClick={() => setPage(cur + 1)}>下一页 ›</button>
    <span className="muted">第 {cur}/{pages} 页</span>
  </div>);
}
// 通用中英文标签映射
const LABEL_MAP: Record<string, string> = {
  severity: '风险等级', vuln_id: '漏洞编号', name: '漏洞名称', ip: 'IP', port: '端口', url: 'URL',
  component: '组件', mark: '标记', id: 'ID', source: '来源', rule_id: '规则编号', tags: '标签',
  supported: '可执行', enabled: '启用', status: '状态', progress: '进度', mode: '模式',
  scan_interval: '周期', created_by: '创建人', created_at: '创建时间', ended_at: '结束时间',
  next_run: '下次执行', targets: '目标', network: '网络类型', alive: '存活',
  probe_method: '探测方式', latency_ms: '延迟(ms)', risk_score: '风险评分', cname: 'CNAME',
  protocol: '协议', service: '服务', version: '版本', category: '分类', banner: 'Banner',
  status_code: '状态码', title: '标题', server: '服务器', tech: '技术栈',
  content_type: '内容类型', resp_size: '响应大小', domain: '域名', is_dir: '目录',
  size: '大小', mod_time: '修改时间', last_update: '上次更新', last_result: '上次结果',
  change: '变化', asset_type: '资产类型', asset: '资产', detail: '详情',
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
  confirmed: '实报', false_positive: '误报', ignored: '忽略',
  running: '运行中', pending: '排队中', paused: '已暂停', done: '已完成', failed: '失败', canceled: '已终止',
  quick: '快速', standard: '标准', deep: '深度', nuclei: 'Nuclei', xray: 'XRay', afrog: 'Afrog',
  true: '是', false: '否', add: '新增', remove: '移除', '-': '-',
};

function label(key: string): string { return LABEL_MAP[key] || key; }

const SEV_CLASS: Record<string, string> =  { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' };
export function SevTag({ sev }: { sev: string }) { return <span className={`sev ${SEV_CLASS[sev] || 'sev-info'}`}>{label(sev)}</span>; }

function Login({ onOk }: { onOk: () => void }) { const [u, setU] = useState('admin'); const [p, setP] = useState(''); const [err, setErr] = useState('');
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try { const r = await api.login(u, p); setToken(r.token); onOk(); } catch (ex: any) { setErr(ex.message); } };
  return (<div className="login-wrap"><form className="login" onSubmit={submit}><h2>Cysec-Scan</h2>
    <input placeholder="用户名" value={u} onChange={(e) => setU(e.target.value)} /><input placeholder="密码" type="password" value={p} onChange={(e) => setP(e.target.value)} />
    {err && <div className="err">{err}</div>}<button type="submit">登录</button></form></div>); }

function Dashboard({ pid }: { pid: number }) { const [stats, setStats] = useState<any>(null);
  useEffect(() => { api.stats(pid).then(setStats).catch(() => undefined); }, [pid]); if (!stats) return <div>加载中…</div>;
  const sev = stats.vuln_by_severity || {};
  const cards = [['IP 资产', stats.ips], ['域名', stats.domains], ['端口', stats.ports], ['Web 资产', stats.web], ['URL', stats.urls], ['漏洞', stats.vulns]] as [string, number][];
  return (<div className="grid">{cards.map(([label, v]) => (<Card key={label}><div className="stat-num">{v}</div><div className="stat-label">{label}</div></Card>))}
    <Card title="漏洞等级"><div className="sev-list">{['critical', 'high', 'medium', 'low', 'info'].map((s) => (<div key={s} className="sev-row"><SevTag sev={s} /><b>{sev[s] || 0}</b></div>))}</div></Card>
    <Card title="快速开始"><ol className="hint"><li>创建项目并导入授权资产</li><li>创建扫描任务</li><li>查看 IP → 端口 → Web → 漏洞</li><li>导出报告</li></ol></Card></div>); }

const ASSET_TABS = [['ip', 'IP'], ['domain', '域名'], ['port', '端口/服务'], ['web', 'Web 资产']] as [string, string][];

function Assets({ pid }: { pid: number }) {
  const [tab, setTab] = useState('ip');
  const [q, setQ] = useState('');
  const [pg, setPg] = useState(1);
  const [data, setData] = useState<any>({ items: [], total: 0 });
  const [detail, setDetail] = useState<any>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    api.listAssets(pid, tab, q, PAGE_SIZE, (pg - 1) * PAGE_SIZE).then((d) => {
      setData(d);
      if (!(d.items || []).length && pg > 1) setPg(pg - 1); // 删除后当前页为空则回退
    }).catch(() => undefined);
  }, [pid, tab, q, pg, refreshKey]);

  const columns: Record<string, string[]> = {
    ip: ['ip', 'network', 'alive', 'probe_method', 'latency_ms', 'risk_score', 'source'],
    domain: ['domain', 'cname', 'ip', 'source'],
    port: ['ip', 'port', 'protocol', 'service', 'version', 'category', 'banner'],
    web: ['url', 'ip', 'port', 'status_code', 'title', 'server', 'tech'],
  };

  const doClearAssets = async () => {
    if (!(await askConfirm('确认清空全部资产？不可恢复'))) return;
    try { await api.assetsClear(tab, pid); setRefreshKey(k => k + 1); } catch (e: any) { alert(e.message); }
  };
  const handleDelete = async (r: any) => {
    if (await askConfirm('确认删除该资产？')) {
      try { await api.assetDelete(tab, r.id, pid); setRefreshKey(k => k + 1); } catch (e) { /* ignore */ }
    }
  };

  return (
    <div>
      <div className="toolbar">
        {ASSET_TABS.map(([k, lbl]) => (
          <button key={k} className={tab === k ? 'active' : ''} onClick={() => { setTab(k); setPg(1); }}>{lbl}</button>
        ))}
        <input className="search" placeholder="搜索…" value={q} onChange={(e) => { setQ(e.target.value); setPg(1); }} />
        <span className="muted">共 {data.total} 条</span>
        <button style={{ marginLeft: 'auto' }} onClick={() => downloadExport(pid, tab, 'csv')}>导出 CSV</button>
        <button onClick={() => downloadExport(pid, tab, 'json')}>导出 JSON</button>
        <button onClick={doClearAssets}>全部删除</button>
      </div>
      <Card>
        <Table
          cols={columns[tab]}
          rows={data.items || []}
          onRow={tab === 'ip' ? (r) => setDetail(r.ip) : undefined}
          actions={(r: any) => <button onClick={() => handleDelete(r)}>删除</button>}
        />
        <Pager total={data.total || 0} page={pg} setPage={setPg} />
      </Card>
      {detail && <IPDetail pid={pid} ip={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

function IPDetail({ pid, ip, onClose }: { pid: number; ip: string; onClose: () => void }) { const [d, setD] = useState<any>(null);
  useEffect(() => { api.ipDetail(pid, ip).then(setD).catch(() => undefined); }, [pid, ip]); if (!d) return null;
  return (<div className="modal" onClick={onClose}><div className="modal-body" onClick={(e) => e.stopPropagation()}>
    <div className="modal-head"><h3>资产画像 · {ip}</h3><button onClick={onClose}>关闭</button></div><div className="profile">
      <div><b>网络：</b>{cell(d.info?.network)}　<b>存活：</b>{d.info?.alive ? '是' : '否'}　<b>评分：</b>{d.info?.risk_score || 0}/100</div>
      <h4>关联域名（{d.domains?.length || 0}）</h4><Table cols={['domain', 'cname', 'ip']} rows={d.domains || []} />
      <h4>开放端口（{d.ports?.length || 0}）</h4><Table cols={['port', 'protocol', 'service', 'version', 'category', 'banner']} rows={d.ports || []} />
      <h4>Web 资产（{d.web?.length || 0}）</h4><Table cols={['url', 'status_code', 'title', 'server', 'tech']} rows={d.web || []} />
      <h4>关联漏洞（{d.vulnerabilities?.length || 0}）</h4><Table cols={['severity', 'vuln_id', 'name', 'url', 'component', 'mark']} rows={d.vulnerabilities || []} /></div></div></div>); }

function downloadExport(pid: number, type: string, format: string) { return (e: any) => { e.preventDefault();
  fetch(`/api/export?project_id=${pid}&type=${type}&format=${format}`, { headers: { Authorization: `Bearer ${getToken()}` } }).then((r) => r.blob()).then((b) => { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = `${type}.${format}`; a.click(); }); }; }

const MARK_LABEL: Record<string, string> = { confirmed: '实报', false_positive: '误报', ignored: '忽略', '': '未标记' };
function Vulns({ pid }: { pid: number }) { const [sev, setSev] = useState(''); const [q, setQ] = useState(''); const [markFilter, setMarkFilter] = useState(''); const [data, setData] = useState<any>({ items: [] }); const [detail, setDetail] = useState<any>(null);
  const [pg, setPg] = useState(1);
  const [aiBusy, setAiBusy] = useState(0); const [aiMsg, setAiMsg] = useState('');
  const fetchPage = (page: number) => api.vulns(pid, sev, q, markFilter, PAGE_SIZE, (page - 1) * PAGE_SIZE).then((d) => {
    setData(d);
    if (!(d.items || []).length && page > 1) setPg(page - 1); // 删除后当前页为空则回退
  }).catch(() => undefined);
  useEffect(() => { fetchPage(pg); }, [pid, sev, q, markFilter, pg]);
  const refresh = () => fetchPage(pg);
  const doMark = async (id: number, mark: string) => { try { await api.vulnMark(id, mark); await refresh(); if (detail?.id === id) setDetail(await api.vulnDetail(id)); } catch (e: any) { alert(e.message); } };
  const [aiAllBusy, setAiAllBusy] = useState(false);
  const doAIAll = async () => {
    setAiAllBusy(true); setAiMsg('AI 批量研判中…（后台执行，完成后自动刷新）');
    try {
      const r = await api.aiAnalyzeAll(pid);
      setAiMsg(r.count > 0 ? `AI 批量研判已启动：${r.count} 个漏洞` : '无未标记漏洞需要研判');
      setTimeout(() => refresh(), 30000);
    } catch (e: any) { setAiMsg('AI 失败: ' + e.message); }
    finally { setAiAllBusy(false); }
  };
  const doClearAll = async () => {
    if (!(await askConfirm('确认清空全部漏洞？将删除不可恢复'))) return;
    try { const r = await api.vulnsClear(pid); setAiMsg('已清空 ' + (r.deleted || 0) + ' 条'); await refresh(); } catch (e: any) { alert(e.message); }
  };
  const doDelete = async (id: number) => {
    if (!(await askConfirm('确认删除该漏洞？删除后不可恢复'))) return;
    try { await api.vulnDelete(id); await refresh(); if (detail?.id === id) setDetail(null); } catch (e: any) { alert(e.message); }
  };
  const doAI = async (id: number) => { setAiBusy(id); setAiMsg(''); try { const v = await api.aiAnalyze(id); setAiMsg(`AI 研判: ${v.mark === 'confirmed' ? '实报' : '误报'}（${v.confidence}）${v.reasoning || ''}`); await refresh(); if (detail?.id === id) setDetail(await api.vulnDetail(id)); } catch (e: any) { setAiMsg('AI 失败: ' + e.message); } finally { setAiBusy(0); } };
  return (<div><div className="toolbar">
    {['', 'critical', 'high', 'medium', 'low', 'info'].map((s) => (<button key={s} className={sev === s ? 'active' : ''} onClick={() => { setSev(s); setPg(1); }}>{s ? label(s) : '全部'}</button>))}
    <input className="search" placeholder="搜索漏洞…" value={q} onChange={(e) => { setQ(e.target.value); setPg(1); }} />
    <select value={markFilter} onChange={(e) => { setMarkFilter(e.target.value); setPg(1); }}>
      <option value="">全部标记</option>
      <option value="unmarked">未标记</option>
      <option value="confirmed">实报</option>
      <option value="false_positive">误报</option>
    </select>
    <a className="btn" href="#" onClick={downloadExport(pid, 'vulnerabilities', 'csv')}>导出 CSV</a>
    <a className="btn" href="#" onClick={downloadExport(pid, 'vulnerabilities', 'json')}>导出 JSON</a>
    <button style={{ marginLeft: 'auto' }} onClick={doAIAll} disabled={aiAllBusy}>{aiAllBusy ? 'AI研判中…' : '🤖 AI全部研判'}</button>
    <button onClick={doClearAll}>全部删除</button></div>
    <Card><Table cols={['severity', 'vuln_id', 'name', 'ip', 'port', 'url', 'component', 'mark']} rows={data.items || []}
      onRow={(r) => api.vulnDetail(r.id).then(setDetail).catch(() => undefined)}
      actions={(v: any) => (<span>
        <button disabled={aiBusy === v.id} onClick={() => doAI(v.id)}>{aiBusy === v.id ? 'AI…' : 'AI研判'}</button>
        {v.mark !== 'confirmed' && <button onClick={() => doMark(v.id, 'confirmed')}>实报</button>}
        {v.mark !== 'false_positive' && <button onClick={() => doMark(v.id, 'false_positive')}>误报</button>}
        {v.mark && v.mark !== '' && <button onClick={() => doMark(v.id, '')}>取消</button>}
        <button onClick={() => doDelete(v.id)}>删除</button></span>)} />
      <Pager total={data.total || 0} page={pg} setPage={setPg} />
      {aiMsg && <div className="ok" style={{ marginTop: 6 }}>{aiMsg}</div>}
      <div className="muted" style={{ marginTop: 6 }}>点击行查看详情；右侧标记或 AI 研判</div></Card>
    {detail && (<div className="modal" onClick={() => setDetail(null)}><div className="modal-body" onClick={(e) => e.stopPropagation()}>
      <div className="modal-head"><h3>{detail.vuln_id} · {detail.name}</h3><button onClick={() => setDetail(null)}>关闭</button></div>
      <div className="profile"><div><b>等级：</b><SevTag sev={detail.severity} />　<b>资产：</b>{detail.ip}{detail.port ? ':' + detail.port : ''}　<b>URL：</b>{detail.url || '-'}
        {'　'}<b>标记：</b>{MARK_LABEL[detail.mark || ''] || '未标记'}</div>
        {detail.description && <div><b>描述：</b>{detail.description}</div>}
        {detail.evidence && <div><b>判定：</b>{detail.evidence}</div>}
        {detail.solution && <div><b>修复：</b>{detail.solution}</div>}
        <div style={{ marginTop: 8 }}>
          {detail.mark !== 'confirmed' && <button onClick={() => doMark(detail.id, 'confirmed')}>标记实报</button>}
          {detail.mark !== 'false_positive' && <button onClick={() => doMark(detail.id, 'false_positive')}>标记误报</button>}
          {detail.mark && <button onClick={() => doMark(detail.id, '')}>取消</button>}
          <button disabled={aiBusy === detail.id} onClick={() => doAI(detail.id)}>{aiBusy === detail.id ? 'AI 分析中…' : '🤖 AI 研判'}</button>
          <button onClick={() => doDelete(detail.id)}>删除漏洞</button></div>
        {aiMsg && <div className="ok" style={{ marginTop: 4 }}>{aiMsg}</div>}
        <h4>请求报文</h4><pre className="logs">{detail.request || '（无）'}</pre>
        <h4>响应报文</h4><pre className="logs">{detail.response || '（无）'}</pre></div></div></div>)}</div>); }

function Tasks({ pid }: { pid: number }) { const [data, setData] = useState<any>({ items: [] }); const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<any>({ name: '', targets: '', mode: 'standard', ports: '', concurrency: 8, timeout_sec: 5, priority: 5, scan_interval: '' });
  const [logs, setLogs] = useState<any[] | null>(null);
  const refresh = () => api.tasks(pid).then(setData).catch(() => undefined);
  useEffect(() => { refresh(); const t = setInterval(refresh, 4000); return () => clearInterval(t); }, [pid]);
  const create = async (e: React.FormEvent) => { e.preventDefault(); try { await api.createTask({ ...form, project_id: pid, target_type: 'ip' }); setShowCreate(false); refresh(); } catch (ex: any) { alert(ex.message); } };
  return (<div><div className="toolbar"><span className="muted">每 4 秒刷新</span><button onClick={() => setShowCreate(!showCreate)}>+ 创建任务</button></div>
    {showCreate && (<Card title="创建扫描任务"><form className="form" onSubmit={create}>
      <input placeholder="任务名称" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
      <textarea placeholder="目标（IP / CIDR / 域名 / URL）" value={form.targets} onChange={(e) => setForm({ ...form, targets: e.target.value })} required rows={3} />
      <div className="form-row">
        <label>模式<select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
          <option value="quick">快速（测绘+常见端口）</option><option value="standard">标准（测绘+Top1000+全部漏洞）</option><option value="deep">深度（测绘+全端口+全部漏洞）</option></select></label>
        <label>端口<input placeholder="空=默认" value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} /></label>
        <label>并发<input type="number" value={form.concurrency} onChange={(e) => setForm({ ...form, concurrency: +e.target.value })} /></label>
        <label>超时(秒)<input type="number" value={form.timeout_sec} onChange={(e) => setForm({ ...form, timeout_sec: +e.target.value })} /></label>
        <label>周期<select value={['','8h','24h','1w'].includes(form.scan_interval) ? form.scan_interval : 'custom'} onChange={(e) => setForm({ ...form, scan_interval: e.target.value === 'custom' ? '1h' : e.target.value })}>
          <option value="">一次性</option><option value="8h">8小时</option><option value="24h">24小时</option><option value="1w">每周</option><option value="custom">自定义</option></select></label>
        {!['','8h','24h','1w'].includes(form.scan_interval) && (<label>小时<input type="number" min={1} max={8760} style={{ width: 70 }} value={parseInt(form.scan_interval) || 1} onChange={(e) => setForm({ ...form, scan_interval: (Math.max(1, Math.min(8760, +e.target.value || 1))) + 'h' })} /></label>)}
      </div><button type="submit">提交</button></form></Card>)}
    <Card><Table cols={['id', 'name', 'mode', 'scan_interval', 'status', 'progress', 'created_at']}
      rows={(data.items || []).map((t: any) => ({ ...t, scan_interval: t.scan_interval || '-' }))}
      actions={(t: any) => (<span>
        {t.status === 'running' && <button onClick={() => api.taskAction(t.id, 'pause').then(refresh)}>暂停</button>}
        {t.status === 'paused' && <button onClick={() => api.taskAction(t.id, 'resume').then(refresh)}>恢复</button>}
        {(t.status === 'running' || t.status === 'pending' || t.status === 'paused') && <button onClick={() => api.taskAction(t.id, 'cancel').then(refresh)}>终止</button>}
        <button onClick={() => api.taskLogs(t.id).then(setLogs)}>日志</button>
        <button onClick={async () => { if (await askConfirm("删除任务 #" + t.id + "？")) api.taskDelete(t.id).then(refresh); }}>删除</button></span>)} /></Card>
    {logs && (<div className="modal" onClick={() => setLogs(null)}><div className="modal-body" onClick={(e) => e.stopPropagation()}>
      <div className="modal-head"><h3>日志</h3><button onClick={() => setLogs(null)}>关闭</button></div>
      <pre className="logs">{logs.map((l: any) => `[${l.created_at}] ${l.message}`).join('\n')}</pre></div></div>)}</div>); }

const INTERVAL_LABEL: Record<string, string> = { '8h': '每 8 小时', '24h': '每 24 小时', '1w': '每周' };
function intervalLabel(iv: string) { return INTERVAL_LABEL[iv] || ('每 ' + iv.replace('h', '') + ' 小时'); }
function Monitor({ pid }: { pid: number }) { const [data, setData] = useState<any>({ items: [], total: 0 });
  const refresh = () => api.monitorTasks(pid).then(setData).catch(() => undefined);
  useEffect(() => { refresh(); const t = setInterval(refresh, 5000); return () => clearInterval(t); }, [pid]);
  return (<div><div className="toolbar"><span className="muted">周期任务到期自动执行</span><span className="muted">共 {data.total} 个</span></div>
    <Card><Table cols={['id', 'name', 'targets', 'mode', 'scan_interval', 'status', 'progress', 'ended_at', 'next_run']}
      rows={(data.items || []).map((t: any) => ({ ...t, scan_interval: intervalLabel(t.scan_interval), ended_at: (t.ended_at || '-').toString().slice(0, 19).replace('T', ' '), next_run: t.next_run || (t.status === 'running' ? '执行中' : '-') }))}
      actions={(t: any) => (<span><button onClick={() => api.taskRun(t.id).then(refresh)}>立即执行</button>
        <button onClick={async () => { if (await askConfirm("删除 #" + t.id + "？")) api.taskDelete(t.id).then(refresh); }}>删除</button></span>)} /></Card></div>); }

function Changes({ pid }: { pid: number }) { const [rows, setRows] = useState<any[]>([]);
  useEffect(() => { api.changes(pid).then(setRows).catch(() => undefined); }, [pid]);
  return (<Card title="资产变化记录"><Table cols={['created_at', 'change', 'asset_type', 'asset', 'detail']} rows={rows} /></Card>); }

function ImportPanel({ pid }: { pid: number }) { const [content, setContent] = useState(''); const [msg, setMsg] = useState('');
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try { const r = await api.importAssets(pid, content, 'mixed'); setMsg(`IP ${r.ips}（新增 ${r.new_ips}），域名 ${r.domains}，URL ${r.urls}`); setContent(''); } catch (ex: any) { setMsg(ex.message); } };
  return (<div><Card title="资产导入"><form className="form" onSubmit={submit}>
    <textarea rows={5} placeholder={'192.168.1.1\nexample.com\nhttps://example.com'} value={content} onChange={(e) => setContent(e.target.value)} required />
    <button type="submit">导入</button>{msg && <div className="ok">{msg}</div>}</form></Card>
    <MappingQueryPanel pid={pid} /></div>); }

function MappingQueryPanel({ pid }: { pid: number }) { const [target, setTarget] = useState(''); const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<any>(null); const [sample, setSample] = useState<any[]>([]);
  const run = async (e: React.FormEvent) => { e.preventDefault(); setBusy(true); setMsg(null); setSample([]);
    try { const r = await api.mappingQuery(pid, target.trim()); setSample(r.sample || []); setMsg(r); } catch (ex: any) { setMsg({ error: ex.message }); } finally { setBusy(false); } };
  return (<Card title="空间测绘查询"><form className="form" onSubmit={run}><div className="toolbar">
    <input className="search" placeholder="IP 或域名" value={target} onChange={(e) => setTarget(e.target.value)} required />
    <button type="submit" disabled={busy}>{busy ? '测绘中…' : '立即测绘并入库'}</button></div>
    {msg && !msg.error && <div className="ok">共 {msg.total} 条，存活 {msg.verified_alive}</div>}
    {msg?.error && <div className="err">{msg.error}</div>}
    {sample.length > 0 && <Table cols={['Provider', 'IP', 'Port', 'URL', 'Title']} rows={sample} />}</form></Card>); }

function MappingSettings() {
  const [form, setForm] = useState<any>({});
  const [msg, setMsg] = useState('');
  const [target, setTarget] = useState('1.1.1.1');
  const [testing, setTesting] = useState(false);
  const [sample, setSample] = useState<any[]>([]);
  useEffect(() => {
    api.getMapping().then((r: any) => setForm(r.mapping || {})).catch(() => undefined);
  }, []);
  const save = async () => {
    setMsg('');
    try { const r = await api.setMapping(form); setMsg('已保存：' + (r.status || '')); } catch (e: any) { setMsg(e.message); }
  };
  const test = async () => {
    setTesting(true); setMsg(''); setSample([]);
    try {
      const r = await api.testMapping(form, target);
      setSample(r.results || []);
      const errs = Object.entries(r.errors || {}).map(([k, v]) => k + ': ' + v).join('；');
      setMsg('获取 ' + (r.total || 0) + ' 条' + (errs ? '；失败：' + errs : ''));
    } catch (e: any) { setMsg(e.message); }
    finally { setTesting(false); }
  };
  const set = (k: string, v: any) => setForm((f: any) => ({ ...f, [k]: v }));
  const prov = (key: string, label: string, fields: [string, string, string][]) => (
    <div className="provider-row">
      <label className="inline">
        <input type="checkbox" checked={!!form[key + '_enable']} onChange={(e) => set(key + '_enable', e.target.checked)} />
        <b>{label}</b>
      </label>
      {fields.map(([k, label2, ph]) => (
        <label key={k} className={k.includes('base_url') ? 'wide' : ''}>{label2}
          <input type={k.includes('key') && !k.includes('key_id') ? 'password' : 'text'} placeholder={ph} value={form[k] || ''} onChange={(e) => set(k, e.target.value)} />
        </label>
      ))}
    </div>
  );
  return (
    <Card title="空间测绘数据源（FOFA / Quake / Shodan / 0.zone / ZoomEye）">
      <div className="muted" style={{ marginBottom: 10 }}>
        标准/深度扫描任务自动调用已启用的测绘引擎扩展资产；测绘 API 始终直连不走代理
      </div>
      <div className="form">
        <div className="form-row">
          <label className="inline">
            <input type="checkbox" checked={!!form.enabled} onChange={(e) => set('enabled', e.target.checked)} />
            <b>启用空间测绘</b>
          </label>
          <label>单次查询条数<input type="number" value={form.size || 100} onChange={(e) => set('size', +e.target.value)} /></label>
          <label>请求间隔(毫秒)<input type="number" style={{ width: 80 }} value={form.interval_ms || 0} onChange={(e) => set('interval_ms', +e.target.value)} /></label>
        </div>
        {prov('fofa', 'FOFA', [['fofa_key', 'API Key', 'FOFA API 密钥'], ['fofa_base_url', 'Base URL（留空默认）', 'https://fofa.info/api/v1/search/all']])}
        {prov('quake', 'Quake（360）', [['quake_key', 'API Token', 'X-QuakeToken'], ['quake_base_url', 'Base URL', 'https://quake.360.cn/api/v3/search/quake_service']])}
        {prov('shodan', 'Shodan', [['shodan_key', 'API Key', 'Shodan API 密钥'], ['shodan_base_url', 'Base URL', 'https://api.shodan.io/shodan/host/search']])}
        {prov('zerozone', '0.zone', [['zerozone_key_id', 'Key ID', 'zone_key_id'], ['zerozone_base_url', 'Base URL', 'https://0.zone/api/data/']])}
        {prov('zoomeye', 'ZoomEye', [['zoomeye_key', 'API Key', 'ZoomEye API 密钥'], ['zoomeye_base_url', 'Base URL', 'https://api.zoomeye.org/v2/search']])}
        <div className="toolbar">
          <button onClick={save}>保存并生效</button>
          <input placeholder="测试目标（IP/域名）" value={target} onChange={(e) => setTarget(e.target.value)} />
          <button onClick={test} disabled={testing}>{testing ? '测试中…' : '测试测绘'}</button>
          {msg && <span className="muted">{msg}</span>}
        </div>
        {sample.length > 0 && <Table cols={['Provider', 'IP', 'Port', 'Service', 'URL', 'Title']} rows={sample} />}
      </div>
    </Card>
  );
}

function Settings() { const [form, setForm] = useState<any>({}); const [msg, setMsg] = useState<any>(null);
  const [testTarget, setTestTarget] = useState('www.baidu.com:80'); const [testRes, setTestRes] = useState<any>(null);
  useEffect(() => { api.getProxy().then((r) => setForm(r.proxy)).catch(() => undefined); }, []);
  const save = async () => { setMsg(null); try { const r = await api.setProxy(form); setMsg({ ok: true, text: `已生效：${r.status}` }); } catch (ex: any) { setMsg({ ok: false, text: ex.message }); } };
  const test = async () => { setTestRes({ loading: true }); setTestRes(await api.testProxy(form, testTarget)); };
  const set = (k: string, v: any) => setForm((f: any) => ({ ...f, [k]: v }));
  const [aiCfg, setAiCfg] = useState<any>({}); const [aiMsg, setAiMsg] = useState('');
  useEffect(() => { api.getAIConfig().then(setAiCfg).catch(() => undefined); }, []);
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [aiLoadingModels, setAiLoadingModels] = useState(false);
  const saveAI = async () => { try { await api.setAIConfig(aiCfg); setAiMsg('已保存'); setAiCfg(await api.getAIConfig()); } catch (e: any) { setAiMsg(e.message); } };
  const fetchModels = async () => {
    setAiLoadingModels(true); setAiMsg('');
    try {
      const r = await api.aiModels(aiCfg.base_url, aiCfg.api_key);
      setAiModels(r.models || []);
      if ((r.models || []).length === 0) { setAiMsg('API 返回 0 个模型'); }
    } catch (e: any) { setAiMsg('获取失败: ' + e.message); }
    finally { setAiLoadingModels(false); }
  };
  const [wlText, setWlText] = useState(''); const [wlMsg, setWlMsg] = useState('');
  useEffect(() => { api.getWhitelist().then((w: any) => setWlText((w.items || []).join('\n'))).catch(() => undefined); }, []);
  const saveWL = async () => { const items = wlText.split('\n').map((x: any) => x.trim()).filter((x: any) => x !== '');
    try { const r = await api.setWhitelist(items); setWlText((r.items || []).join('\n')); setWlMsg('已保存'); } catch (ex: any) { setWlMsg(ex.message); } };
  return (<div>
    <MappingSettings />
    <Card title="AI 研判配置（OpenAI 兼容）"><div className="form">
      <div className="toolbar"><label className="inline"><input type="checkbox" checked={!!aiCfg.enabled} onChange={(e) => setAiCfg({ ...aiCfg, enabled: e.target.checked })} />启用 AI</label>
        <label>Provider<select value={aiCfg.provider || 'openai'} onChange={(e) => { const prov = e.target.value;
          const def: any = { openai: { base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini' }, deepseek: { base_url: 'https://api.deepseek.com/v1', model: 'deepseek-chat' }, qwen: { base_url: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-plus' }, ollama: { base_url: 'http://localhost:11434/v1', model: 'llama3' } };
          setAiCfg({ ...aiCfg, provider: prov, ...(def[prov] || {}) }); }}>
          <option value="openai">OpenAI</option><option value="deepseek">DeepSeek</option><option value="qwen">通义千问</option><option value="ollama">Ollama</option><option value="custom">自定义</option></select></label></div>
      <div className="form-row">
        <label>API 地址<input style={{ width: 280 }} value={aiCfg.base_url || ''} onChange={(e) => setAiCfg({ ...aiCfg, base_url: e.target.value })} /></label>
        <label>模型
            <input style={{ width: 160 }} list="ai-model-list" placeholder="点击获取" value={aiCfg.model || ''} onChange={(e) => setAiCfg({ ...aiCfg, model: e.target.value })} />
            <datalist id="ai-model-list">{aiModels.map((m: string) => <option key={m} value={m} />)}</datalist>
            <button type="button" onClick={fetchModels} disabled={aiLoadingModels} style={{ marginTop: 4, fontSize: 12, padding: '2px 8px' }}>{aiLoadingModels ? '获取中…' : '获取模型列表'}</button>
          </label>
        <label>API Key<input type="password" style={{ width: 200 }} value={aiCfg.api_key || ''} onChange={(e) => setAiCfg({ ...aiCfg, api_key: e.target.value })} /></label>
        <label>超时(秒)<input type="number" style={{ width: 60 }} value={aiCfg.timeout_sec || 30} onChange={(e) => setAiCfg({ ...aiCfg, timeout_sec: +e.target.value })} /></label></div>
      <div className="toolbar" style={{ marginTop: 8 }}>
          <label className="inline">
            <input type="checkbox" checked={!!aiCfg.auto_analyze} onChange={(e) => setAiCfg({ ...aiCfg, auto_analyze: e.target.checked })} />
            <b>AI 自动研判</b>（扫描完成后自动对新检出漏洞做 AI 研判并标记）
          </label>
          <label>最低研判等级
            <select value={aiCfg.auto_min_severity || 'low'} onChange={(e) => setAiCfg({ ...aiCfg, auto_min_severity: e.target.value })}>
              <option value="critical">仅严重</option>
              <option value="high">高危及以上</option>
              <option value="medium">中危及以上</option>
              <option value="low">低危及以上</option>
              <option value="info">全部</option>
            </select>
          </label>
        </div>
        <div className="toolbar"><button onClick={saveAI}>保存</button>{aiMsg && <span className="muted">{aiMsg}</span>}</div></div></Card>
    <Card title="资产白名单（跳过漏洞扫描）"><div className="form">
      <textarea rows={5} placeholder={'每行一项：192.168.1.10 / 10.0.0.0/8 / example.com'} value={wlText} onChange={(e) => setWlText(e.target.value)} />
      <div className="toolbar"><button onClick={saveWL}>保存白名单</button>{wlMsg && <span className="muted">{wlMsg}</span>}</div></div></Card>
    <Card title="全局出站代理"><div className="form">
      <div className="form-row"><label className="inline"><input type="checkbox" checked={!!form.enable} onChange={(e) => set('enable', e.target.checked)} />启用代理</label>
        <label>协议<select value={form.type || 'http'} onChange={(e) => set('type', e.target.value)}><option value="http">HTTP</option><option value="socks5">SOCKS5</option></select></label>
        <label>地址<input value={form.host || ''} onChange={(e) => set('host', e.target.value)} /></label>
        <label>端口<input type="number" value={form.port || ''} onChange={(e) => set('port', +e.target.value)} /></label>
        <label>用户名<input value={form.username || ''} onChange={(e) => set('username', e.target.value)} /></label>
        <label>密码<input type="password" value={form.password || ''} onChange={(e) => set('password', e.target.value)} /></label></div>
      <div className="toolbar"><button onClick={save}>保存并生效</button>
        <input placeholder="测试目标" value={testTarget} onChange={(e) => setTestTarget(e.target.value)} /><button onClick={test}>测试</button>
        {testRes && (testRes.loading ? <span className="muted">测试中…</span> : <span className={testRes.ok ? 'ok' : 'err'}>{testRes.ok ? `连通 ${testRes.latency_ms}ms` : testRes.error}</span>)}</div>
      {msg && <div className={msg.ok ? 'ok' : 'err'}>{msg.text}</div>}</div></Card></div>); }

function VulnRules() { const [data, setData] = useState<any>({ items: [], total: 0 }); const [stats, setStats] = useState<any>(null);
  const [filters, setFilters] = useState({ source: '', severity: '', enabled: '', supported: '', q: '' });
  const [pg, setPg] = useState(1);
  const setF = (patch: any) => { setFilters({ ...filters, ...patch }); setPg(1); };
  const [settings, setSettings] = useState<any>({ enabled_in_scan: false, max_per_target: 20 });
  const [detail, setDetail] = useState<any>(null);
  const [testTarget, setTestTarget] = useState('http://127.0.0.1:8080'); const [testRes, setTestRes] = useState<any>(null);
  const [sources, setSources] = useState<any>({ config: { sources: [] }, updating: false, log: [] });
  const [newURL, setNewURL] = useState(''); const [srcMsg, setSrcMsg] = useState('');
  const [watcher, setWatcher] = useState<any>(null);
  const [poc, setPoc] = useState<any>({ path: '', entries: [] }); const [pocMsg, setPocMsg] = useState<any>(null);
  const dirInputRef = useRef<HTMLInputElement>(null);
  const refresh = () => { const p = new URLSearchParams(Object.entries(filters).filter(([, v]) => v !== '') as any); p.set('limit', String(PAGE_SIZE)); p.set('offset', String((pg - 1) * PAGE_SIZE)); api.vulnRules(p.toString()).then((d) => { setData(d); if (!(d.items || []).length && pg > 1) setPg(pg - 1); }).catch(() => undefined); api.vulnRuleStats().then(setStats).catch(() => undefined); };
  useEffect(refresh, [filters.source, filters.severity, filters.enabled, filters.supported, filters.q, pg]);
  useEffect(() => { api.getRuleSettings().then(setSettings).catch(() => undefined); }, []);
  useEffect(() => { if (dirInputRef.current) { dirInputRef.current.setAttribute('webkitdirectory', ''); dirInputRef.current.setAttribute('directory', ''); } }, []);
  const refreshWatcher = () => api.getWatcher().then(setWatcher).catch(() => undefined);
  useEffect(() => { refreshWatcher(); const t = setInterval(refreshWatcher, 5000); return () => clearInterval(t); }, []);
  const refreshSources = () => api.getRuleSources().then(setSources).catch(() => undefined);
  useEffect(() => { refreshSources(); }, []);
  const refreshPoc = (path: string) => api.pocFiles(path).then(setPoc).catch((e: any) => setPocMsg({ ok: false, text: e.message }));
  useEffect(() => { refreshPoc(''); }, []);
  const uploadPocFiles = async (files: File[]) => { const yamls = files.filter((f) => /\.(yml|yaml)$/i.test(f.name)); if (!yamls.length) return;
    let ok = 0, fail = 0; for (const f of yamls) { let rel = ((f as any).webkitRelativePath as string) || f.name;
      if (rel.includes('/')) rel = rel.split('/').slice(1).join('/'); if (!rel) rel = f.name;
      try { await api.pocSave((poc.path ? poc.path + '/' : '') + rel, await f.text()); ok++; } catch { fail++; } }
    setPocMsg({ ok: fail === 0, text: `成功 ${ok}，失败 ${fail}` }); refreshPoc(poc.path); };
  const saveSettings = async () => { try { await api.setRuleSettings(settings); } catch (e: any) { alert(e.message); } };
  const toggle = async (id: number, en: boolean) => { await api.toggleVulnRule(id, en); refresh(); };
  const del = async (id: number) => { if (await askConfirm('删除该规则？')) { await api.deleteVulnRule(id); refresh(); } };
  const showDetail = async (id: number) => setDetail(await api.getVulnRule(id));
  const runTest = async (id: number) => { setTestRes({ loading: true }); setTestRes(await api.testVulnRule(id, testTarget)); };
  const applySources = async (cfg: any, msg: string) => { try { const r = await api.setRuleSources(cfg); setSources({ ...sources, config: r.config }); setSrcMsg(msg); } catch (ex: any) { setSrcMsg(ex.message); refreshSources(); } };
  const clearAll = async () => { if (await askConfirm("清空全部 " + (stats?.total || 0) + " 条规则？")) { const r = await api.clearVulnRules(); setPocMsg({ ok: true, text: '已清空 ' + (r.deleted ?? 0) + ' 条' }); refresh(); } };
  return (<div>
    <Card title="规则执行设置"><div className="toolbar">
      <label className="inline"><input type="checkbox" checked={!!settings.enabled_in_scan} onChange={(e) => setSettings({ ...settings, enabled_in_scan: e.target.checked })} />深度扫描时执行规则</label>
      <label>每目标最大规则数（0=全部）<input type="number" style={{ width: 80 }} value={settings.max_per_target} onChange={(e) => setSettings({ ...settings, max_per_target: +e.target.value })} /></label>
      <button onClick={saveSettings}>保存</button>
      {stats && <span className="muted">共 {stats.total} · 可执行 {stats.supported} · 启用 {stats.enabled}</span>}
      <button style={{ marginLeft: 'auto' }} onClick={clearAll}>全部删除</button></div></Card>
    <Card title="模板源更新"><div className="toolbar">
      <input className="search" placeholder="GitHub 仓库 URL" value={newURL} onChange={(e) => setNewURL(e.target.value)} /><button onClick={() => { if (newURL.trim()) { applySources({ ...sources.config, sources: [...(sources.config?.sources || []), { url: newURL.trim(), enabled: true }] }, '已添加'); setNewURL(''); } }}>添加源</button>
      <label className="inline"><input type="checkbox" checked={!!sources.config?.auto_daily} onChange={(e) => applySources({ ...sources.config, auto_daily: e.target.checked }, '已更新')} />每日自动更新</label>
      <label>更新时间(HH:MM)<input type="text" placeholder="02:00" style={{ width: 90 }} value={sources.config?.auto_time || '02:00'}
        onChange={(e) => { const t = e.target.value.trim(); setSources({ ...sources, config: { ...sources.config, auto_time: e.target.value } }); if (/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(t)) applySources({ ...sources.config, auto_time: t }, '已设 ' + t); }} /></label>
      <label>镜像前缀<input type="text" placeholder="https://ghproxy.com" style={{ width: 200 }} value={sources.config?.mirror || ''} onChange={(e) => setSources({ ...sources, config: { ...sources.config, mirror: e.target.value } })} onBlur={() => applySources(sources.config, '已保存')} /></label>
      <button onClick={async () => { try { const r = await api.updateRuleSources(); if (r.started) { setSrcMsg('更新已开始'); refreshSources(); } } catch (ex: any) { setSrcMsg(ex.message); } }} disabled={sources.updating}>{sources.updating ? '更新中…' : '立即更新'}</button>
      {srcMsg && <span className="muted">{srcMsg}</span>}</div>
      <Table cols={['url', 'enabled', 'last_update', 'last_result']} rows={sources.config?.sources || []}
        actions={(x: any) => { const idx = (sources.config?.sources || []).findIndex((y: any) => y.url === x.url);
          return (<span><button onClick={() => applySources({ ...sources.config, sources: sources.config.sources.map((s2: any, j: number) => j === idx ? { ...s2, enabled: !s2.enabled } : s2) }, '已更新')}>{x.enabled ? '停用' : '启用'}</button>
            <button onClick={async () => { if (await askConfirm('删除 ' + x.url + '？')) applySources({ ...sources.config, sources: sources.config.sources.filter((_: any, j: number) => j !== idx) }, '已删除'); }}>删除</button></span>); }} />
      {sources.updating && <pre className="logs" style={{ maxHeight: 160 }}>{(sources.log || []).slice(-12).join('\n')}</pre>}</Card>
    <Card title="POC 文件仓库（默认 xray/nuclei/afrog）"><div className="toolbar">
      <span className="muted">poc://{poc.path || ''}</span>
      {poc.path && <><button onClick={() => refreshPoc(poc.path.split('/').slice(0, -1).join('/'))}>⬆</button><button onClick={() => refreshPoc('')}>根目录</button></>}
      <button onClick={async () => { const name = await askText('新建文件夹', '名'); if (name) api.pocMkdir((poc.path ? poc.path + '/' : '') + name).then(() => refreshPoc(poc.path)).catch(() => undefined); }}>＋ 文件夹</button>
      <label className="inline" style={{ cursor: 'pointer', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 12px' }}>⬆ 文件<input type="file" accept=".yml,.yaml" multiple style={{ display: 'none' }} onChange={async (e) => { await uploadPocFiles(Array.from(e.target.files || [])); e.target.value = ''; }} /></label>
      <label className="inline" style={{ cursor: 'pointer', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 12px' }}>📁 文件夹<input ref={dirInputRef} type="file" multiple style={{ display: 'none' }} onChange={async (e) => { await uploadPocFiles(Array.from(e.target.files || [])); e.target.value = ''; }} /></label>
      <button onClick={() => api.pocImport(poc.path || '').then((r: any) => { setPocMsg({ ok: true, text: `导入 ${r.imported} 条` }); refresh(); }).catch((ex: any) => setPocMsg({ ok: false, text: ex.message }))}>导入目录</button></div>
      {pocMsg && <div className={pocMsg.ok ? 'ok' : 'err'} style={{ marginTop: 6 }}>{pocMsg.text}</div>}
      <Table cols={['name', 'is_dir', 'size', 'mod_time']} rows={poc.entries || []}
        actions={(x: any) => (<span>{x.is_dir && <button onClick={() => refreshPoc((poc.path ? poc.path + '/' : '') + x.name)}>进入</button>}
          <button onClick={async () => { if (await askConfirm('删除 ' + x.name + '？')) api.pocDelete((poc.path ? poc.path + '/' : '') + x.name).then(() => refreshPoc(poc.path)).catch(() => undefined); }}>删除</button></span>)} /></Card>
    <Card title="POC 目录监控"><div className="toolbar">
      <label className="inline"><input type="checkbox" checked={!!watcher?.enabled} onChange={(e) => api.setWatcher({ enabled: e.target.checked, interval_sec: watcher?.interval_sec || 60 }).then(setWatcher)} />启用</label>
      <label>间隔(秒)<input type="number" style={{ width: 80 }} value={watcher?.interval_sec ?? 60} onBlur={(e: any) => api.setWatcher({ enabled: watcher?.enabled ?? true, interval_sec: +e.target.value }).then(setWatcher)} /></label>
      {watcher && <span className="muted">文件 {watcher.watching_files} · 上次 {((watcher.last_check || '') + '').slice(11, 19)}</span>}</div></Card>
    <div className="toolbar">
      <select value={filters.source} onChange={(e) => setF({ source: e.target.value })}><option value="">全部来源</option><option value="nuclei">nuclei</option><option value="xray">xray</option><option value="afrog">afrog</option></select>
      <select value={filters.severity} onChange={(e) => setF({ severity: e.target.value })}><option value="">全部等级</option>{['critical', 'high', 'medium', 'low', 'info'].map((x) => <option key={x} value={x}>{x}</option>)}</select>
      <select value={filters.enabled} onChange={(e) => setF({ enabled: e.target.value })}><option value="">启用状态</option><option value="true">已启用</option><option value="false">已停用</option></select>
      <select value={filters.supported} onChange={(e) => setF({ supported: e.target.value })}><option value="">可执行性</option><option value="true">可执行</option><option value="false">不可执行</option></select>
      <input className="search" placeholder="搜索" value={filters.q} onChange={(e) => setF({ q: e.target.value })} /><span className="muted">共 {data.total} 条</span>
      <input className="search" placeholder="测试目标" value={testTarget} onChange={(e) => setTestTarget(e.target.value)} style={{ marginLeft: 'auto' }} />
      {testRes && (testRes.loading ? <span className="muted">测试中…</span> : <span className={testRes.matched ? 'ok' : 'err'}>{testRes.matched ? '命中' : testRes.error ? testRes.error.slice(0, 50) : '未命中'}</span>)}</div>
    <Card><Table cols={['id', 'source', 'rule_id', 'name', 'severity', 'tags', 'supported', 'enabled']} rows={data.items || []}
      actions={(r: any) => (<span><button onClick={() => toggle(r.id, !r.enabled)}>{r.enabled ? '停用' : '启用'}</button>
        <button onClick={() => runTest(r.id)}>测试</button><button onClick={() => showDetail(r.id)}>YAML</button><button onClick={() => del(r.id)}>删除</button></span>)} />
      <Pager total={data.total || 0} page={pg} setPage={setPg} /></Card>
    {detail && (<div className="modal" onClick={() => setDetail(null)}><div className="modal-body" onClick={(e) => e.stopPropagation()}>
      <div className="modal-head"><h3>{detail.rule_id}</h3><button onClick={() => setDetail(null)}>关闭</button></div><pre className="logs">{detail.raw}</pre></div></div>)}</div>); }

const NAV = [['#', '仪表盘'], ['#assets', '资产管理'], ['#vulns', '漏洞风险'], ['#tasks', '扫描任务'], ['#monitor', '资产监控'], ['#import', '资产导入'], ['#changes', '变化监控'], ['#rules', '漏洞规则库'], ['#settings', '系统设置']];

export default function App() { const [logged, setLogged] = useState(!!getToken()); const [projects, setProjects] = useState<Project[]>([]);
  const [pid, setPid] = useState<number>(0); const [hash, setHash] = useState(window.location.hash || '#');
  useEffect(() => { const fn = () => setHash(window.location.hash || '#'); window.addEventListener('hashchange', fn); return () => window.removeEventListener('hashchange', fn); }, []);
  useEffect(() => { if (logged) api.projects().then((ps: Project[]) => { setProjects(ps); const saved = +(localStorage.getItem('pid') || 0); if (ps.length && (!saved || !ps.find((p) => p.id === saved))) setPid(ps[0].id); else if (saved) setPid(saved); }).catch(() => undefined); }, [logged]);
  useEffect(() => { if (pid) localStorage.setItem('pid', String(pid)); }, [pid]);
    const addProject = async () => {
    const name = await askText('新建项目', '项目名称');
    if (!name) return;
    await api.createProject(name, '');
    const ps = await api.projects();
    setProjects(ps);
    setPid(ps[ps.length - 1].id);
  };
  const delProject = async () => {
    const cur = (projects.find((x: any) => x.id === pid) || {}).name;
    if (!(await askConfirm('确认删除项目 ' + cur + ' ？'))) return;
    await api.deleteProject(pid);
    localStorage.removeItem('pid');
    const ps = await api.projects();
    setProjects(ps);
    setPid(ps.length ? ps[0].id : 0);
  };

if (!logged) return <Login onOk={() => setLogged(true)} />;
  const page = hash.split('?')[0];
  return (<div className="app">
      <header>
        <div className="brand">Cysec-Scan <span className="muted">攻击面资产发现与风险检测平台</span></div>
        <div className="proj-select">
          项目：
          <select value={pid} onChange={(e) => setPid(+e.target.value)}>
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button onClick={addProject}>+ 项目</button>
          {pid > 0 && <button onClick={delProject}>删除项目</button>}
        </div>
        <nav>
          {NAV.map(([h, label]) => (
            <a key={h} href={h} className={page === h ? 'active' : ''}>{label}</a>
          ))}
          <a href="#login" onClick={() => { localStorage.removeItem('token'); setLogged(false); }}>退出</a>
        </nav>
      </header>
    <main>{pid === 0 && <Card>请先创建项目</Card>}
      {pid > 0 && page === '#' && <Dashboard pid={pid} />}{pid > 0 && page === '#assets' && <Assets pid={pid} />}
      {pid > 0 && page === '#vulns' && <Vulns pid={pid} />}{pid > 0 && page === '#tasks' && <Tasks pid={pid} />}
      {pid > 0 && page === '#monitor' && <Monitor pid={pid} />}{pid > 0 && page === '#import' && <ImportPanel pid={pid} />}
      {pid > 0 && page === '#changes' && <Changes pid={pid} />}{pid > 0 && page === '#rules' && <VulnRules />}
      {page === '#settings' && <Settings />}</main>
    <footer className="muted">仅用于已授权资产的安全检测</footer><AskDialog /></div>); }
