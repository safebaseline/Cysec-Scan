import { Fragment, createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { api, API, setToken, getToken } from './api';
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
// 长文本列省略截断（配合 CSS .tbl td.ell）：nowrap 下不截断会把行高/表格撑爆
const ELLIPSIS_COLS = new Set(['url', 'web_url', 'page_url', 'target', 'targets', 'banner', 'file_path', 'asset', 'value']);
function Table({ cols, rows, onRow, actions }: { cols: string[]; rows: any[]; onRow?: (r: any) => void; actions?: (r: any) => ReactNode }) {
  const span = cols.length + (actions ? 1 : 0);
  return (<table className="tbl"><thead><tr>{cols.map((c) => <th key={c}>{label(c)}</th>)}{actions && <th style={{ textAlign: 'right' }}>操作</th>}</tr></thead>
    <tbody>{rows.length === 0 && <tr><td colSpan={span} className="empty">暂无数据</td></tr>}
    {rows.map((r, i) => (<tr key={i} onClick={() => onRow?.(r)} className={onRow ? 'clickable' : ''}>
      {cols.map((k) => { const v = (r as any)[k]; const body = TIME_COLS.has(k) ? cell(fmtTime(v)) : (k === 'status' && STATUS_SET.has(v) ? <span className={`status st-${v}`}>{label(v)}</span> : (k === 'severity' && SEV_CLASS[v] ? <SevTag sev={v} /> : cell(v))); return ELLIPSIS_COLS.has(k) && typeof v === 'string' && v ? <td key={k} className="ell" title={v}>{body}</td> : <td key={k}>{body}</td>; })}
      {actions && <td className="row-act" onClick={(e) => e.stopPropagation()}>{actions(r)}</td>}</tr>))}</tbody></table>); }
// fmtTime 时间列展示统一转换：后端存储为 UTC（SQLite CURRENT_TIMESTAMP），
// 展示为本地时区 24 小时制（浏览器时区，即中国时区环境显示北京时间）；解析失败原样返回
function fmtTime(s: any): string {
  if (typeof s !== 'string' || !s) return s;
  if (!s.includes('T')) return s; // 后端已存中国时区 24 小时制，直接展示
  const t = new Date(s); // 兼容历史 time.Time 带偏移格式：规范为本地 24 小时制
  if (isNaN(t.getTime())) return s;
  const p = (n: number) => String(n).padStart(2, '0');
  return `${t.getFullYear()}-${p(t.getMonth() + 1)}-${p(t.getDate())} ${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`;
}
const TIME_COLS = new Set(['created_at', 'first_seen', 'last_seen', 'started_at', 'ended_at', 'last_probe', 'updated_at']);
const STATUS_SET = new Set(['running', 'pending', 'paused', 'done', 'failed', 'canceled']); // 任务状态徽章
function cell(v: any): ReactNode { if (v === null || v === undefined || v === '') return <span className="muted">-</span>;
  if (typeof v === 'string' && LABEL_MAP[v]) return label(v); if (typeof v === 'boolean') return v ? '✔' : '✘';
  if (typeof v === 'object') return JSON.stringify(v).slice(0, 80); const s = String(v); return s.length > 80 ? s.slice(0, 80) + '…' : s; }

// NumInput 手动输入模式的正整数输入框：实时过滤非数字字符与前导零、超上限截断，
// 失焦时为空/0 则回落到 min。type=text + 数字键盘（type=number 会静默吞掉非法字符且允许 e/-）。
function NumInput({ value, onChange, min = 1, max, width, placeholder }: { value: number; onChange: (v: number) => void; min?: number; max?: number; width?: number; placeholder?: string }) {
  const sanitize = (s: string): number => {
    const digits = s.replace(/\D/g, '').replace(/^0+/, '');
    if (digits === '') return 0;
    let n = parseInt(digits, 10);
    if (max && n > max) n = max;
    return n;
  };
  return <input type="text" inputMode="numeric" placeholder={placeholder}
    value={value || ''} style={width ? { width } : undefined}
    onChange={(e) => onChange(sanitize(e.target.value))}
    onBlur={() => { if (!value) onChange(min); }} />;
}

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
  severity: '风险等级', vuln_id: '漏洞编号', name: '名称', ip: 'IP', port: '端口', url: 'URL',
  username: '用户名', action: '动作', object: '对象',
  component: '组件', mark: '标记', id: 'ID', source: '来源', rule_id: '规则编号', tags: '标签',
  supported: '可执行', enabled: '启用', status: '状态', progress: '进度', mode: '模式',
  scan_interval: '周期', created_by: '创建人', created_at: '创建时间', ended_at: '结束时间',
  first_seen: '发现时间', last_seen: '最近命中',
  next_run: '下次执行', targets: '目标', network: '网络类型', alive: '存活',
  probe_method: '探测方式', latency_ms: '延迟(ms)', risk_score: '风险评分', cname: 'CNAME',
  protocol: '协议', service: '服务', version: '版本', category: '分类', banner: 'Banner',
  status_code: '状态码', title: '标题', server: '服务器', tech: '技术栈',
  content_type: '内容类型', resp_size: '响应大小', domain: '域名', is_dir: '目录',
  size: '大小', mod_time: '修改时间', last_update: '上次更新', last_result: '上次结果',
  change: '变化', asset_type: '资产类型', asset: '资产', detail: '详情',
  web_url: '所属站点', anchor: '锚文本', evidence: '命中内容',
  page_url: '所属页面', page_title: '标题',
  client_ip: '来源 IP', result: '结果',
  type: '类型',
  darklink: '暗链', brokenlink: '坏链', sensword: '敏感字', wih: '敏感信息',
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
  confirmed: '实报', false_positive: '误报', ignored: '忽略',
  running: '运行中', pending: '排队中', paused: '已暂停', done: '已完成', failed: '失败', canceled: '已终止',
  quick: '快速', standard: '标准', deep: '深度', nuclei: 'Nuclei', xray: 'XRay', afrog: 'Afrog',
  true: '是', false: '否', add: '新增', remove: '移除', '-': '-',
};

function label(key: string): string { return LABEL_MAP[key] || key; }

const SEV_CLASS: Record<string, string> =  { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' };
export function SevTag({ sev }: { sev: string }) { return <span className={`sev ${SEV_CLASS[sev] || 'sev-info'}`}>{label(sev)}</span>; }

// SSE 实时事件流：后端数据变化（assets/vulns/weaknesses/tasks）推送触发面板刷新，
// 高频轮询降级为 30s 兜底；EventSource 断线自动重连，不可用时静默回退纯轮询
const SSEContext = createContext<Record<string, number>>({});
function useTopicTick(topic: string): number { return useContext(SSEContext)[topic] || 0; }
export function SSEProvider({ children }: { children: ReactNode }) {
  const [ticks, setTicks] = useState<Record<string, number>>({});
  useEffect(() => {
    const tok = getToken();
    if (!tok) return;
    let es: EventSource | null = null;
    try {
      es = new EventSource(`${API}/api/events?token=${encodeURIComponent(tok)}`);
      es.onmessage = (e) => { try { const d = JSON.parse(e.data); if (d && d.topic) setTicks((p) => ({ ...p, [d.topic]: (p[d.topic] || 0) + 1 })); } catch { /* 忽略坏帧 */ } };
    } catch { /* SSE 不可用：回退轮询兜底 */ }
    return () => { es?.close(); };
  }, []);
  return <SSEContext.Provider value={ticks}>{children}</SSEContext.Provider>;
}

function Login({ onOk }: { onOk: () => void }) { const [u, setU] = useState('admin'); const [p, setP] = useState(''); const [err, setErr] = useState('');
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try { const r = await api.login(u, p); setToken(r.token); onOk(); } catch (ex: any) { setErr(ex.message); } };
  return (<div className="login-wrap"><form className="login" onSubmit={submit}><h2>Cysec-Scan</h2>
    <input placeholder="用户名" value={u} onChange={(e) => setU(e.target.value)} /><input placeholder="密码" type="password" value={p} onChange={(e) => setP(e.target.value)} />
    {err && <div className="err">{err}</div>}<button type="submit">登录</button></form></div>); }

function Dashboard({ pid }: { pid: number }) { const [stats, setStats] = useState<any>(null);
  const [recentVulns, setRecentVulns] = useState<any[]>([]); const [recentWeak, setRecentWeak] = useState<any[]>([]);
  // 实时刷新：SSE 事件驱动（资产/漏洞/弱点变化亚秒推送）+ 30s 轮询兜底
  const tkAssets = useTopicTick('assets'); const tkVulns = useTopicTick('vulns'); const tkWeak = useTopicTick('weaknesses');
  useEffect(() => {
    const load = () => { api.stats(pid).then(setStats).catch(() => undefined); };
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [pid, tkAssets, tkVulns, tkWeak]);
  useEffect(() => {
    const load = () => {
      api.vulns(pid, '', '', '', 6, 0).then((d) => setRecentVulns(d.items || [])).catch(() => undefined);
      api.weaknesses(pid, 1, 6).then((d) => setRecentWeak(d.items || [])).catch(() => undefined);
    };
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [pid, tkVulns, tkWeak]);
  // 模块自定义排序：拖拽调整仪表盘模块位置（localStorage 持久化，恢复默认一键还原）
  const DASH_DEFAULT = ['stats', 'vuln', 'weak', 'recentVuln', 'recentWeak', 'quick'];
  const [order, setOrder] = useState<string[]>(() => { try { const o = JSON.parse(localStorage.getItem('dash_layout') || 'null'); return Array.isArray(o) && o.length ? o.filter((x: string) => DASH_DEFAULT.includes(x)) : DASH_DEFAULT; } catch { return DASH_DEFAULT; } });
  const [editing, setEditing] = useState(false);
  const [dragMod, setDragMod] = useState('');
  const [overMod, setOverMod] = useState('');
  const persist = (o: string[]) => { setOrder(o); localStorage.setItem('dash_layout', JSON.stringify(o)); };
  const onDropMod = (target: string) => {
    if (!dragMod || dragMod === target) { setDragMod(''); setOverMod(''); return; }
    const o = order.filter((x) => x !== dragMod);
    o.splice(o.indexOf(target), 0, dragMod);
    persist(o); setDragMod(''); setOverMod('');
  };
  if (!stats) return <div>加载中…</div>;
  const sev = stats.vuln_by_severity || {};
  const wk = stats.weakness_by_type || {};
  // 每行内联"（实报a/误报b/未标记c）"细分：mks = {等级/类型: {confirmed, false_positive, '': n}}
  const sevMarks = stats.vuln_by_severity_marks || {};
  const wkMarks = stats.weakness_by_type_marks || {};
  const markBits = (m: any) => {
    const c = (m && m.confirmed) || 0, f = (m && m.false_positive) || 0, u = (m && m['']) || 0;
    return <span className="mark-bits">（<span className="bit-ok">实报{c}</span>/<span className="bit-err">误报{f}</span>/未标记{u}）</span>;
  };
  const cards = [['IP 资产', stats.ips], ['域名', stats.domains], ['端口', stats.ports], ['Web 资产', stats.web], ['URL', stats.urls], ['漏洞', stats.vulns], ['弱点', stats.weaknesses]] as [string, number][];
  const modProps = (id: string) => ({
    className: 'card dash-module ' + (overMod === id && dragMod !== id ? 'drag-over ' : '') + (id === 'stats' ? 'dash-s12' : id.startsWith('recent') ? 'dash-s6' : 'dash-s4'),
    draggable: editing,
    onDragStart: () => setDragMod(id),
    onDragEnd: () => { setDragMod(''); setOverMod(''); },
    onDragOver: (e: any) => { e.preventDefault(); setOverMod(id); },
    onDragLeave: () => setOverMod(''),
    onDrop: (e: any) => { e.preventDefault(); onDropMod(id); },
  });
  const title = (t: string) => (<div className="card-title">{editing && <span className="drag-handle">⠿</span>}{t}</div>);
  const modules: Record<string, ReactNode> = {
    stats: (<div {...modProps('stats')}><div className="grid" style={{ margin: 0 }}>{cards.map(([l, v]) => (<div key={l} className="card" style={{ marginBottom: 0 }}><div className="stat-num">{v}</div><div className="stat-label">{l}</div></div>))}</div></div>),
    vuln: (<div {...modProps('vuln')}>{title('漏洞风险（实时）')}<div className="sev-list">{['critical', 'high', 'medium', 'low', 'info'].map((x) => (<div key={x} className="sev-row"><SevTag sev={x} /><b>{sev[x] || 0}{markBits(sevMarks[x])}</b></div>))}
      <div className="sev-row"><span className="muted">未研判</span><b>{stats.vuln_unmarked || 0}</b></div></div></div>),
    weak: (<div {...modProps('weak')}>{title('弱点分布（实时）')}<div className="sev-list">
      <div className="sev-row"><span className="pill"><span className="dot" />暗链</span><b>{wk.darklink || 0}{markBits(wkMarks.darklink)}</b></div>
      <div className="sev-row"><span className="pill"><span className="dot" />坏链</span><b>{wk.brokenlink || 0}{markBits(wkMarks.brokenlink)}</b></div>
      <div className="sev-row"><span className="pill"><span className="dot" />敏感字</span><b>{wk.sensword || 0}{markBits(wkMarks.sensword)}</b></div>
      <div className="sev-row"><span className="pill"><span className="dot" />敏感信息</span><b>{wk.wih || 0}{markBits(wkMarks.wih)}</b></div>
      <div className="sev-row"><span className="muted">未研判</span><b>{stats.weakness_unmarked || 0}</b></div></div></div>),
    recentVuln: (<div {...modProps('recentVuln')}>{title('最近漏洞（实时）')}{recentVulns.length === 0 ? <div className="muted">暂无数据</div> : (<table className="tbl"><tbody>
      {recentVulns.map((v: any) => (<tr key={v.id}><td style={{ width: 70 }}><SevTag sev={v.severity} /></td>
        <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis' }}>{v.name}</td>
        <td className="muted" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>{v.url || v.ip}</td>
        <td style={{ width: 60 }}>{v.mark ? MARK_LABEL[v.mark] || v.mark : <span className="muted">-</span>}</td></tr>))}</tbody></table>)}</div>),
    recentWeak: (<div {...modProps('recentWeak')}>{title('最近弱点（实时）')}{recentWeak.length === 0 ? <div className="muted">暂无数据</div> : (<table className="tbl"><tbody>
      {recentWeak.map((w: any) => (<tr key={w.id}><td style={{ width: 80 }}><span className="pill">{label(w.type)}</span></td>
        <td style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis' }}>{w.anchor || w.detail}</td>
        <td className="muted" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>{w.web_url}</td>
        <td style={{ width: 60 }}>{w.mark ? MARK_LABEL[w.mark] || w.mark : <span className="muted">-</span>}</td></tr>))}</tbody></table>)}</div>),
    quick: (<div {...modProps('quick')}>{title('快速开始')}<ol className="hint"><li>创建项目并导入授权资产</li><li>创建扫描任务（勾选执行内容：资产收集 / 漏洞扫描 / 弱点检测 / 存活检测）</li><li>查看 IP → 端口 → Web → 漏洞 / 弱点</li><li>导出报告</li></ol></div>),
  };
  const shown = order.length ? order : DASH_DEFAULT;
  return (<div>
    <div className="toolbar"><span className="muted">每 5 秒实时刷新</span>
      <button className={editing ? 'active' : ''} onClick={() => setEditing(!editing)}>{editing ? '完成布局' : '自定义布局'}</button>
      {editing && <button onClick={() => persist(DASH_DEFAULT)}>恢复默认</button>}
      {editing && <span className="muted">拖动模块标题区调整位置，松手即保存</span>}</div>
    <div className={editing ? 'dash-grid dash-editing' : 'dash-grid'}>{shown.map((id) => <Fragment key={id}>{modules[id]}</Fragment>)}</div></div>); }

const ASSET_TABS = [['ip', 'IP'], ['domain', '域名'], ['port', '端口/服务'], ['web', 'Web 资产']] as [string, string][];
// 资产页签值 -> 导出接口 type（ips/domains/ports/webs）
const ASSET_EXPORT_TYPE: Record<string, string> = { ip: 'ips', domain: 'domains', port: 'ports', web: 'webs' };

function Assets({ pid }: { pid: number }) {
  const [tab, setTab] = useState('ip');
  const [fpText, setFpText] = useState(''); const [fpMsg, setFpMsg] = useState('');
  useEffect(() => { api.getFPAssets(pid).then((r) => setFpText((r.items || []).join('\n'))).catch(() => undefined); setFpMsg(''); }, [pid]);
  const saveFP = async () => { const items = fpText.split('\n').map((x: string) => x.trim()).filter(Boolean); try { const r = await api.setFPAssets(pid, items); const c = r.cleaned || {}; const n = (c.ips || 0) + (c.domains || 0) + (c.webs || 0) + (c.urls || 0); setFpMsg('已保存（后续命中不再入库）' + (n > 0 ? '；已清理存量：IP ' + (c.ips || 0) + ' / 域名 ' + (c.domains || 0) + ' / Web ' + (c.webs || 0) + ' / URL ' + (c.urls || 0) : '')); } catch (e: any) { setFpMsg(e.message); } };
  const [q, setQ] = useState('');
  const [pg, setPg] = useState(1);
  const [data, setData] = useState<any>({ items: [], total: 0 });
  const [detail, setDetail] = useState<any>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const tkAssets = useTopicTick('assets');

  useEffect(() => {
    api.listAssets(pid, tab, q, PAGE_SIZE, (pg - 1) * PAGE_SIZE).then((d) => {
      setData(d);
      if (!(d.items || []).length && pg > 1) setPg(pg - 1); // 删除后当前页为空则回退
    }).catch(() => undefined);
  }, [pid, tab, q, pg, refreshKey, tkAssets]);

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
      <Card title="误报资产配置（本项目，命中不入库）"><div className="form">
      <div className="toolbar">
        <textarea rows={3} style={{ width: 480 }} placeholder={'每行一条：域名根（xxx.example.cn，含全部子域）/ IP / CIDR（192.0.2.0/24）/ URL 前缀'} value={fpText} onChange={(e) => setFpText(e.target.value)} />
        <button onClick={saveFP}>保存</button>{fpMsg && <span className="muted">{fpMsg}</span>}</div>
      <p className="hint">生效范围：端口扫描发现的 IP、子域名爆破/证书收集、空间测绘导入、Web 资产识别；保存时自动清理已入库的匹配资产（IP 含端口、Web 含其 URL 与指纹）。</p></div></Card>
      <div className="toolbar">
        {ASSET_TABS.map(([k, lbl]) => (
          <button key={k} className={tab === k ? 'active' : ''} onClick={() => { setTab(k); setPg(1); }}>{lbl}</button>
        ))}
        <input className="search" placeholder="搜索…" value={q} onChange={(e) => { setQ(e.target.value); setPg(1); }} />
        <span className="muted">共 {data.total} 条</span>
        <button style={{ marginLeft: 'auto' }} onClick={() => downloadExport(pid, ASSET_EXPORT_TYPE[tab] || tab, 'csv')}>导出 CSV</button>
        <button onClick={() => downloadExport(pid, ASSET_EXPORT_TYPE[tab] || tab, 'json')}>导出 JSON</button>
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
      <h4>关联漏洞（{d.vulnerabilities?.length || 0}）</h4><Table cols={['severity', 'vuln_id', 'name', 'url', 'component', 'first_seen', 'mark']} rows={d.vulnerabilities || []} /></div></div></div>); }

// 直接执行下载（此前为事件工厂函数：onClick={() => downloadExport(...)} 写法只调工厂不执行处理器，点击无反应）
function downloadExport(pid: number, type: string, format: string) {
  fetch(`/api/export?project_id=${pid}&type=${type}&format=${format}`, { headers: { Authorization: `Bearer ${getToken()}` } }).then((r) => r.blob()).then((b) => { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = `${type}.${format}`; a.click(); }); }

const MARK_LABEL: Record<string, string> = { confirmed: '实报', false_positive: '误报', ignored: '忽略', '': '未标记' };
function Vulns({ pid }: { pid: number }) { const [sev, setSev] = useState(''); const [q, setQ] = useState(''); const [markFilter, setMarkFilter] = useState(''); const [data, setData] = useState<any>({ items: [] }); const [detail, setDetail] = useState<any>(null);
  const [pg, setPg] = useState(1);
  const [aiBusy, setAiBusy] = useState(0); const [aiMsg, setAiMsg] = useState('');
  const fetchPage = (page: number) => api.vulns(pid, sev, q, markFilter, PAGE_SIZE, (page - 1) * PAGE_SIZE).then((d) => {
    setData(d);
    if (!(d.items || []).length && page > 1) setPg(page - 1); // 删除后当前页为空则回退
  }).catch(() => undefined);
  const tkVulns = useTopicTick('vulns');
  useEffect(() => { fetchPage(pg); }, [pid, sev, q, markFilter, pg, tkVulns]);
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
  return (<div><Card title="漏洞风险"><div className="toolbar">
    {['', 'critical', 'high', 'medium', 'low', 'info'].map((s) => (<button key={s} className={sev === s ? 'active' : ''} onClick={() => { setSev(s); setPg(1); }}>{s ? label(s) : '全部'}</button>))}
    <input className="search" placeholder="搜索漏洞…" value={q} onChange={(e) => { setQ(e.target.value); setPg(1); }} />
    <select value={markFilter} onChange={(e) => { setMarkFilter(e.target.value); setPg(1); }}>
      <option value="">全部标记</option>
      <option value="unmarked">未标记</option>
      <option value="confirmed">实报</option>
      <option value="false_positive">误报</option>
    </select>
    <button onClick={() => downloadExport(pid, 'vulnerabilities', 'csv')}>导出 CSV</button>
    <button onClick={() => downloadExport(pid, 'vulnerabilities', 'json')}>导出 JSON</button>
    <button style={{ marginLeft: 'auto' }} onClick={doAIAll} disabled={aiAllBusy}>{aiAllBusy ? 'AI研判中…' : '🤖 AI全部研判'}</button>
    <button onClick={doClearAll}>全部删除</button></div>
    <Table cols={['severity', 'vuln_id', 'name', 'ip', 'port', 'url', 'component', 'first_seen', 'mark']} rows={data.items || []}
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
        {'　'}<b>发现时间：</b>{fmtTime(detail.first_seen) || '-'}　<b>标记：</b>{MARK_LABEL[detail.mark || ''] || '未标记'}</div>
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
        {(detail.ai_mark || detail.ai_reasoning) ? (<>
          <h4>AI 研判结果</h4>
          <div><b>结论：</b>{MARK_LABEL[detail.ai_mark] || detail.ai_mark}　{detail.ai_confidence && <><b>置信度：</b>{detail.ai_confidence}</>}</div>
          {detail.ai_reasoning && <pre className="logs" style={{ marginTop: 6 }}>{detail.ai_reasoning}</pre>}
        </>) : (<div className="muted" style={{ marginTop: 8 }}>AI 研判结果：尚未研判，点上方「🤖 AI 研判」生成。</div>)}
        <h4>请求报文</h4><pre className="logs">{detail.request || '（无）'}</pre>
        <h4>响应报文</h4><pre className="logs">{detail.response || '（无）'}</pre></div></div></div>)}</div>); }

function Tasks({ pid }: { pid: number }) { const [data, setData] = useState<any>({ items: [] }); const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<any>({ name: '', targets: '', mode: 'custom', ports: '', concurrency: 8, timeout_sec: 5, priority: 5, scan_interval: '', phases: ['collect', 'portscan', 'vulnscan'], subdomain_brute: true });
  const [editId, setEditId] = useState<number | null>(null); // 非 null 时表单为编辑模式
  const [logs, setLogs] = useState<any[] | null>(null);
  const [logTaskId, setLogTaskId] = useState<number>(0); // 日志弹窗开关：>0 打开，关闭时清零（否则轮询会把弹窗填回来）
  const refresh = () => api.tasks(pid).then(setData).catch(() => undefined);
  const tkTasks = useTopicTick('tasks');
  useEffect(() => { refresh(); const t = setInterval(refresh, 30000); return () => clearInterval(t); }, [pid, tkTasks]);
  useEffect(() => {
    if (!logTaskId) return;
    let alive = true; // 关闭后丢弃在途响应，防止 setLogs 把弹窗重新顶出来
    const tick = () => api.taskLogs(logTaskId).then((l: any[]) => { if (alive) setLogs(l); }).catch(() => undefined);
    tick();
    const t = setInterval(tick, 2000);
    return () => { alive = false; clearInterval(t); };
  }, [logTaskId]);
  const closeLogs = () => { setLogTaskId(0); setLogs(null); };
  const resetForm = () => { setEditId(null); setForm({ name: '', targets: '', mode: 'custom', ports: '', concurrency: 8, timeout_sec: 5, priority: 5, scan_interval: '', phases: ['collect', 'portscan', 'vulnscan'], subdomain_brute: true }); };
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try {
      const payload = { ...form, phases: (form.phases || []).join(','), mode: (form.phases || []).length ? 'custom' : form.mode };
      if (editId) { await api.updateTask(editId, payload); } else { await api.createTask({ ...payload, project_id: pid, target_type: 'ip' }); }
      setShowCreate(false); resetForm(); refresh(); } catch (ex: any) { alert(ex.message); } };
  const PHASE_LABEL: Record<string, string> = { collect: '资产收集', portscan: '端口扫描', vulnscan: '漏洞扫描', weakness: '弱点检测', alive: 'Web资产存活检测' };
  const legacyPhases = (m: string) => (m === 'quick' ? ['collect', 'portscan', 'alive'] : ['collect', 'portscan', 'vulnscan', 'weakness']);
  const startEdit = (t: any) => { setEditId(t.id); setForm({ name: t.name || '', targets: t.targets || '', mode: t.mode || 'custom', ports: t.ports || '', concurrency: t.concurrency || 8, timeout_sec: t.timeout_sec || 5, priority: t.priority || 5, scan_interval: t.scan_interval || '', phases: t.phases ? t.phases.split(',').filter(Boolean) : legacyPhases(t.mode || 'standard'), subdomain_brute: t.phases ? !!t.subdomain_brute : true }); setShowCreate(true); };
  return (<div><div className="toolbar"><span className="muted">每 4 秒刷新</span><button onClick={() => { if (editId) resetForm(); setShowCreate(!showCreate); }}>+ 创建任务</button></div>
    {showCreate && (<Card title={editId ? '编辑任务 #' + editId : '创建扫描任务'}><form className="form" onSubmit={submit}>
      <input placeholder="任务名称" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
      <textarea placeholder="目标（IP / CIDR / 域名 / URL）" value={form.targets} onChange={(e) => setForm({ ...form, targets: e.target.value })} required rows={3} />
      <div className="form-row">
        <label>执行内容
          <span style={{ display: 'flex', gap: 14, flexWrap: 'wrap', paddingTop: 4 }}>
            {(['collect', 'vulnscan', 'weakness', 'alive'] as string[]).map((ph) => (
              <label key={ph} className="inline">
                <input type="checkbox" checked={(form.phases || []).includes(ph)}
                  onChange={(e) => {
                    let ps = e.target.checked ? [...(form.phases || []), ph] : (form.phases || []).filter((x: string) => x !== ph);
                    if (ph === 'collect' && !e.target.checked) { ps = ps.filter((x: string) => x !== 'portscan'); } // 联动：取消资产收集同时取消端口扫描
                    setForm({ ...form, phases: ps });
                  }} />
                {PHASE_LABEL[ph]}
              </label>
            ))}
          </span></label>
      </div>
      {(form.phases || []).includes('collect') && (<div className="form-row" style={{ paddingLeft: 12 }}>
        <label className="inline"><input type="checkbox" checked={!!form.subdomain_brute} onChange={(e) => setForm({ ...form, subdomain_brute: e.target.checked })} />子域名爆破</label>
        <label className="inline"><input type="checkbox" checked={(form.phases || []).includes('portscan')}
          onChange={(e) => setForm({ ...form, phases: e.target.checked ? [...(form.phases || []), 'portscan'] : (form.phases || []).filter((x: string) => x !== 'portscan') })} />端口扫描</label>
        {(form.phases || []).includes('portscan') && (<label>端口范围<input placeholder="空=默认（Top1000）" value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} /></label>)}
      </div>)}
      <div className="form-row">
        <label>并发<NumInput value={form.concurrency} min={1} onChange={(v) => setForm({ ...form, concurrency: v })} /></label>
        <label>超时(秒)<NumInput value={form.timeout_sec} min={1} onChange={(v) => setForm({ ...form, timeout_sec: v })} /></label>
        <label>扫描周期（对任务全部执行内容生效）<select value={['','8h','24h','1w'].includes(form.scan_interval) ? form.scan_interval : 'custom'} onChange={(e) => setForm({ ...form, scan_interval: e.target.value === 'custom' ? '1h' : e.target.value })}>
          <option value="">一次性</option><option value="8h">8小时</option><option value="24h">24小时</option><option value="1w">每周</option><option value="custom">自定义</option></select></label>
        {!['','8h','24h','1w'].includes(form.scan_interval) && (<label>小时<NumInput width={70} value={parseInt(form.scan_interval) || 1} min={1} max={8760} onChange={(v) => setForm({ ...form, scan_interval: v + 'h' })} /></label>)}
      </div><button type="submit">{editId ? '保存修改' : '提交'}</button>{editId && <button type="button" onClick={() => { setShowCreate(false); resetForm(); }}>取消编辑</button>}</form></Card>)}
    <Card><Table cols={['id', 'name', 'mode', 'scan_interval', 'status', 'progress', 'created_at']}
      rows={(data.items || []).map((t: any) => ({ ...t, mode: t.phases ? (t.phases.split(',').filter(Boolean).map((x: string) => PHASE_LABEL[x] || x).join('+')) : t.mode, scan_interval: t.scan_interval || '-' }))}
      actions={(t: any) => (<span>
        {t.status === 'running' && <button onClick={() => api.taskAction(t.id, 'pause').then(refresh)}>暂停</button>}
        {t.status === 'paused' && <button onClick={() => api.taskAction(t.id, 'resume').then(refresh)}>恢复</button>}
        {(t.status === 'running' || t.status === 'pending' || t.status === 'paused') && <button onClick={() => api.taskAction(t.id, 'cancel').then(refresh)}>终止</button>}
        {['done', 'failed', 'canceled'].includes(t.status) && <button onClick={() => api.taskRun(t.id).then(refresh).catch((e: any) => alert(e.message))}>重启</button>}
        {['done', 'failed', 'canceled'].includes(t.status) && <button onClick={() => startEdit(t)}>编辑</button>}
        <button onClick={() => setLogTaskId(t.id)}>日志</button>
        <button onClick={async () => { if (await askConfirm("删除任务 #" + t.id + "？")) api.taskDelete(t.id).then(refresh); }}>删除</button></span>)} /></Card>
    {logTaskId > 0 && logs && (<div className="modal" onClick={closeLogs}><div className="modal-body" onClick={(e) => e.stopPropagation()}>
      <div className="modal-head"><h3>日志</h3><button onClick={closeLogs}>关闭</button></div>
      <pre className="logs">{logs.map((l: any) => `[${fmtTime(l.created_at)}] ${l.message}`).join('\n')}</pre></div></div>)}</div>); }

const INTERVAL_LABEL: Record<string, string> = { '8h': '每 8 小时', '24h': '每 24 小时', '1w': '每周' };
function intervalLabel(iv: string) { return INTERVAL_LABEL[iv] || ('每 ' + iv.replace('h', '') + ' 小时'); }
function Monitor({ pid }: { pid: number }) { const [data, setData] = useState<any>({ items: [], total: 0 });
  const refresh = () => api.monitorTasks(pid).then(setData).catch(() => undefined);
  const tkTasks = useTopicTick('tasks');
  useEffect(() => { refresh(); const t = setInterval(refresh, 30000); return () => clearInterval(t); }, [pid, tkTasks]);
  return (<div><div className="toolbar"><span className="muted">周期任务到期自动执行</span><span className="muted">共 {data.total} 个</span></div>
    <Card><Table cols={['id', 'name', 'targets', 'mode', 'scan_interval', 'status', 'progress', 'ended_at', 'next_run']}
      rows={(data.items || []).map((t: any) => ({ ...t, scan_interval: intervalLabel(t.scan_interval), ended_at: (t.ended_at || '-').toString().slice(0, 19).replace('T', ' '), next_run: t.next_run || (t.status === 'running' ? '执行中' : '-') }))}
      actions={(t: any) => (<span><button onClick={() => api.taskRun(t.id).then(refresh)}>立即执行</button>
        <button onClick={async () => { if (await askConfirm("删除 #" + t.id + "？")) api.taskDelete(t.id).then(refresh); }}>删除</button></span>)} /></Card></div>); }

// 弱点管理：链接爬取（暗链/坏链/敏感字）+ WIH JS 敏感信息检测结果归并展示
function WeaknessPanel({ pid }: { pid: number }) { const [rows, setRows] = useState<any[]>([]); const [total, setTotal] = useState(0); const [pg, setPg] = useState(1);
  const [type, setType] = useState(''); const [q, setQ] = useState(''); const [msg, setMsg] = useState(''); const [markF, setMarkF] = useState('');
  const [aiBusy, setAiBusy] = useState(0); const [aiAllBusy, setAiAllBusy] = useState(false);
  const [detail, setDetail] = useState<any>(null);
  const [cfg, setCfg] = useState<any>(null);
  useEffect(() => { setPg(1); }, [pid, type, markF]);
  const tkWeak = useTopicTick('weaknesses');
  useEffect(() => { const t = setTimeout(() => { api.weaknesses(pid, pg, 20, q, type, markF).then((d) => { setRows(d.items || []); setTotal(d.total || 0); if (!(d.items || []).length && pg > 1) setPg(pg - 1); }).catch(() => undefined); }, q ? 300 : 0); return () => clearTimeout(t); }, [pid, pg, q, type, markF, tkWeak]);
  const doMark = async (id: number, mark: string) => { try { await api.weaknessMark(id, mark); setRows(rows.map((x) => x.id === id ? { ...x, mark } : x)); if (detail?.id === id) setDetail({ ...detail, mark }); } catch (e: any) { setMsg(e.message); } };
  const doAI = async (id: number) => { setAiBusy(id); setMsg(''); try { const v = await api.weaknessAI(id); setRows(rows.map((x) => x.id === id ? { ...x, mark: v.mark, ai_mark: v.mark, ai_confidence: v.confidence, ai_reasoning: v.reasoning } : x)); if (detail?.id === id) setDetail({ ...detail, mark: v.mark, ai_mark: v.mark, ai_confidence: v.confidence, ai_reasoning: v.reasoning }); setMsg('AI 研判：' + (v.mark || '-') + '（' + (v.confidence || '') + '）' + (v.reasoning || '')); } catch (e: any) { setMsg('AI 失败: ' + e.message); } finally { setAiBusy(0); } };
  const doAIAll = async () => { setAiAllBusy(true); setMsg(''); try { const r = await api.weaknessAIAll(pid); setMsg(r.count > 0 ? `AI 批量研判已启动：${r.count} 个弱点` : '无未标记弱点需要研判'); if (r.count > 0) setTimeout(() => setPg(1), 30000); } catch (e: any) { setMsg('AI 失败: ' + e.message); } finally { setAiAllBusy(false); } };
  useEffect(() => { api.getWeaknessSettings().then(setCfg).catch(() => undefined); }, []);
  const saveCfg = async () => { try { const r = await api.setWeaknessSettings(cfg); setCfg({ ...r, senssub: cfg.senssub }); setMsg('已保存并即时生效'); } catch (e: any) { setMsg(e.message); } };
  // 敏感字词库订阅（默认预设 konsheng/Sensitive-lexicon，可自定义任意 GitHub/自定义源）
  const [subBusy, setSubBusy] = useState(false); const [subMsg, setSubMsg] = useState<any>(null);
  const [discBusy, setDiscBusy] = useState(false);
  const [wmOpen, setWmOpen] = useState(false);
  const sub: any = cfg?.senssub || null;
  const setSubEffective = (n: number) => setCfg((c: any) => ({ ...c, senssub: { ...c.senssub, state: { ...c.senssub?.state, word_count: n } } }));
  const patchSub = (p: any) => setCfg({ ...cfg, senssub: { ...sub, ...p } });
  const toggleSubFile = (path: string, on: boolean) => patchSub({ files: (sub.files || []).map((f: any) => (f.path === path ? { ...f, enabled: on } : f)) });
  const addSubFile = async () => {
    const path = await askText('新增词库文件', '相对路径，如 Vocabulary/xxx.txt');
    if (!path) return;
    if ((sub.files || []).some((f: any) => f.path === path)) { setSubMsg({ ok: false, text: '该文件已在清单中' }); return; }
    const name = (await askText('显示名（可留空）', '')) || path;
    patchSub({ files: [...(sub.files || []), { path, name, enabled: true }] });
  };
  const delSubFile = (path: string) => patchSub({ files: (sub.files || []).filter((f: any) => f.path !== path) });
  const restorePreset = async () => {
    if (!(await askConfirm('恢复默认预设（konsheng/Sensitive-lexicon）？当前自定义配置将被覆盖'))) return;
    try { const r = await api.setSensSub({ preset: true }); setCfg({ ...cfg, senssub: r }); setSubMsg({ ok: true, text: '已恢复默认预设（未保存，点"保存订阅配置"生效）' }); } catch (e: any) { setSubMsg({ ok: false, text: e.message }); }
  };
  const doDiscover = async () => {
    setDiscBusy(true); setSubMsg(null);
    try {
      const r = await api.discoverSensSub(sub.base || '');
      const known = new Set((sub.files || []).map((f: any) => f.path));
      const add = ((r.files || []) as string[]).filter((p) => !known.has(p)).map((p) => ({ path: p, name: (p.split('/').pop() || p).replace(/\.txt$/i, ''), enabled: false }));
      if (add.length) patchSub({ files: [...(sub.files || []), ...add] });
      setSubMsg({ ok: true, text: `发现 ${r.files?.length || 0} 个 txt 文件${add.length ? `，新增 ${add.length} 个（默认未勾选）` : ''}` });
    } catch (e: any) { setSubMsg({ ok: false, text: e.message }); } finally { setDiscBusy(false); }
  };
  const saveSub = async () => { try { const r = await api.setSensSub(sub); setCfg({ ...cfg, senssub: r }); setSubMsg({ ok: true, text: '订阅配置已保存' }); } catch (e: any) { setSubMsg({ ok: false, text: e.message }); } };
  const doUpdateSub = async () => { setSubBusy(true); setSubMsg(null); try { const v = await api.updateSensSub(sub); setCfg({ ...cfg, senssub: v }); setSubMsg(v.state?.last_ok ? { ok: true, text: `更新成功：${v.state.word_count} 词` } : { ok: false, text: '部分文件拉取失败，见状态明细' }); } catch (e: any) { setSubMsg({ ok: false, text: e.message }); } finally { setSubBusy(false); } };
  const TYPES: [string, string][] = [['', '全部'], ['darklink', '暗链'], ['brokenlink', '坏链'], ['sensword', '敏感字'], ['wih', '敏感信息']];
  // 导出当前筛选（类型/搜索/标记）下的全部弱点，口径与列表一致
  const exportWeakness = (format: string) => {
    const qs = `project_id=${pid}&type=weaknesses&q=${encodeURIComponent(q)}&wk=${type}&mark=${markF}&format=${format}`;
    fetch(`/api/export?${qs}`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((r) => r.blob()).then((b) => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(b);
        a.download = `weaknesses.${format}`;
        a.click();
      });
  };
  return (<div>
    <Card title="弱点管理"><div className="toolbar">
      {TYPES.map(([v, l]) => (<button key={v} className={type === v ? 'active' : ''} onClick={() => setType(v)}>{l}</button>))}
      <input className="search" placeholder="搜索站点 / 链接 / 详情…" value={q} onChange={(e) => { setQ(e.target.value); setPg(1); }} />
      <select value={markF} onChange={(e) => { setMarkF(e.target.value); setPg(1); }}>
        <option value="">全部标记</option><option value="unmarked">未标记</option><option value="confirmed">实报</option><option value="false_positive">误报</option></select>
      <span className="muted">共 {total} 条</span>
      <button onClick={() => exportWeakness('csv')}>导出 CSV</button>
      <button onClick={() => exportWeakness('json')}>导出 JSON</button>
      <button style={{ marginLeft: 'auto' }} disabled={aiAllBusy} onClick={doAIAll}>{aiAllBusy ? '研判中…' : '🤖 AI全部研判'}</button>
      <button onClick={async () => { if (await askConfirm('清空当前筛选类型的全部弱点？')) { const r = await api.weaknessClear(pid, type); setMsg('已清空 ' + (r.deleted || 0) + ' 条'); setPg(1); } }}>清空</button></div>
      <Table cols={['created_at', 'type', 'severity', 'web_url', 'page_url', 'url', 'anchor', 'status_code', 'detail', 'mark']} rows={rows} onRow={(r: any) => setDetail(r)}
        actions={(r: any) => (<span>
          <button disabled={aiBusy === r.id} onClick={() => doAI(r.id)}>{aiBusy === r.id ? '研判中…' : 'AI研判'}</button>
          <button onClick={() => doMark(r.id, 'confirmed')}>实报</button>
          <button onClick={() => doMark(r.id, 'false_positive')}>误报</button>
          {r.mark && <button onClick={() => doMark(r.id, '')}>取消</button>}
          <button onClick={() => { api.weaknessDelete(r.id).then(() => { setTotal(total - 1); setRows(rows.filter((x) => x.id !== r.id)); }); }}>删除</button></span>)} />
      <Pager total={total} page={pg} setPage={setPg} />
      {msg && <div className="muted" style={{ marginTop: 6 }}>{msg}</div>}</Card>
    {detail && (<div className="modal" onClick={() => setDetail(null)}><div className="modal-body" onClick={(e) => e.stopPropagation()}>
      <div className="modal-head"><h3>弱点详情</h3><button onClick={() => setDetail(null)}>关闭</button></div>
      <div className="profile">
        <div><b>类型：</b>{label(detail.type)}　<b>等级：</b><SevTag sev={detail.severity} />　<b>标记：</b>{MARK_LABEL[detail.mark || ''] || '未标记'}</div>
        <div><b>所属站点：</b>{detail.web_url}</div>
        <div style={{ wordBreak: 'break-all' }}><b>所属页面：</b>{detail.page_url || '-'}</div>
        <div><b>页面标题：</b>{detail.page_title || '-'}</div>
        <div style={{ wordBreak: 'break-all' }}><b>URL：</b>{detail.url}</div>
        {detail.anchor && <div><b>锚文本：</b>{detail.anchor}</div>}
        {detail.status_code ? <div><b>状态码：</b>{detail.status_code}</div> : null}
        {detail.detail && <div><b>详情：</b>{detail.detail}</div>}
        {detail.evidence && (<><h4>命中内容</h4><pre className="logs">{detail.evidence}</pre></>)}
        {detail.context ? (<><h4>引用位置（该 URL 在页面中出现的地方）</h4><pre className="logs">{detail.context}</pre></>) : (<div className="muted" style={{ marginTop: 8 }}>引用位置：该弱点产生于旧版本扫描或非链接类检测，重新扫描对应站点可补充。</div>)}
        {(detail.ai_mark || detail.ai_reasoning) ? (<>
          <h4>AI 研判结果</h4>
          <div><b>结论：</b>{MARK_LABEL[detail.ai_mark] || detail.ai_mark}　{detail.ai_confidence && <><b>置信度：</b>{detail.ai_confidence}</>}</div>
          {detail.ai_reasoning && <pre className="logs" style={{ marginTop: 6 }}>{detail.ai_reasoning}</pre>}
        </>) : (<div className="muted" style={{ marginTop: 8 }}>AI 研判结果：尚未研判，点上方「🤖 AI研判」生成。</div>)}
        <div style={{ marginTop: 10 }}><button disabled={aiBusy === detail.id} onClick={() => doAI(detail.id)}>{aiBusy === detail.id ? 'AI 研判中…' : '🤖 AI研判'}</button>
          <button onClick={() => doMark(detail.id, 'confirmed')}>实报</button>
          <button onClick={() => doMark(detail.id, 'false_positive')}>误报</button>
          {detail.mark && <button onClick={() => doMark(detail.id, '')}>取消</button>}</div>
      </div></div></div>)}
    {cfg && (<Card title="弱点检测设置"><div className="form">
      <div className="toolbar"><label className="inline"><input type="checkbox" checked={!!cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })} />扫描时执行弱点检测（链接爬取/暗链/坏链/敏感字/敏感信息）</label>
        <label className="inline"><input type="checkbox" checked={!cfg.dark_verify_disabled} onChange={(e) => setCfg({ ...cfg, dark_verify_disabled: !e.target.checked })} />暗链目标内容核验（隐藏外链请求目标页并命中暗链关键词才报）</label></div>
      <div className="toolbar">
        <label>每站点最大爬取页面数<NumInput width={80} value={cfg.max_pages || 50} min={1} max={9999} onChange={(v) => setCfg({ ...cfg, max_pages: v })} /></label>
        <label>每站点最大检查链接数<NumInput width={80} value={cfg.max_links || 50} min={1} max={9999} onChange={(v) => setCfg({ ...cfg, max_links: v })} /></label></div>
      <div className="form-row">
        <label>词库·手动部分（每行一个；敏感字与暗链关键词共用，与下方订阅词库合并生效）<textarea rows={6} style={{ width: 320 }} value={(cfg.sensitive_words || []).join('\n')} onChange={(e) => setCfg({ ...cfg, sensitive_words: e.target.value.split('\n').map((x: string) => x.trim()).filter(Boolean) })} /></label>
        <label>坏链忽略域名（后缀匹配，不探测，每行一个）<textarea rows={6} style={{ width: 320 }} value={(cfg.broken_ignore_hosts || []).join('\n')} onChange={(e) => setCfg({ ...cfg, broken_ignore_hosts: e.target.value.split('\n').map((x: string) => x.trim()).filter(Boolean) })} /></label></div>
      {sub && (<div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
        <b style={{ fontSize: 13 }}>敏感字词库订阅</b> <span className="muted">订阅任意 GitHub 敏感词仓库或自定义 raw 源（默认预设 konsheng/Sensitive-lexicon，MIT），勾选文件定期拉取，与手动词库合并参与检测</span>
        <div className="toolbar" style={{ marginTop: 6 }}>
          <label>订阅源<input style={{ width: 380 }} placeholder="https://github.com/owner/repo 或 raw 基址" value={sub.base || ''} onChange={(e) => patchSub({ base: e.target.value })} /></label>
          <button disabled={discBusy} onClick={doDiscover} title="拉取 GitHub 仓库文件列表（.txt），勾选后纳入订阅">{discBusy ? '发现中…' : '发现文件'}</button>
          <button onClick={addSubFile}>＋ 文件</button>
          <button onClick={restorePreset}>恢复预设</button>
        </div>
        <div className="toolbar">
          <label className="inline"><input type="checkbox" checked={!!sub.auto_update} onChange={(e) => patchSub({ auto_update: e.target.checked })} />每日自动更新</label>
          <label>更新时刻<input style={{ width: 70 }} placeholder="02:00" value={sub.update_time || ''} onChange={(e) => patchSub({ update_time: e.target.value })} /></label>
          <label>镜像前缀（直连失败重试，空=禁用）<input style={{ width: 200 }} placeholder="https://ghproxy.com/" value={sub.mirror || ''} onChange={(e) => patchSub({ mirror: e.target.value })} /></label>
          <button disabled={subBusy} onClick={doUpdateSub} title="保存当前勾选并立即拉取">{subBusy ? '更新中…' : '立即更新'}</button>
          <button onClick={saveSub}>保存订阅配置</button>
          {subMsg && <span className={subMsg.ok ? 'ok' : 'err'}>{subMsg.text}</span>}
        </div>
        <div className="muted" style={{ marginTop: 4 }}>
          上次更新：{sub.state?.last_update || '从未'}{sub.state?.last_ok ? `（成功，共 ${sub.state.word_count} 词）` : sub.state?.last_update ? '（部分文件失败）' : ''}
          {(sub.state?.errors || []).length > 0 && <span className="err"> 失败明细：{(sub.state.errors || []).join('；')}</span>}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 14px', marginTop: 6, maxHeight: 130, overflowY: 'auto' }}>
          {(sub.files || []).map((f: any) => (
            <div key={f.path} className="inline" style={{ fontSize: 12, minWidth: 140 }} title={f.path}>
              {/* label 只包"启用"复选框与名称：✕/暗 若仍在 label 内，点击会触发 label 默认行为
                  勾选"启用"，其 onChange 的状态更新会覆盖删除/暗链勾选，表现为操作"不生效" */}
              <label className="inline" style={{ gap: 4 }}>
                <input type="checkbox" checked={!!f.enabled} onChange={(e) => toggleSubFile(f.path, e.target.checked)} />
                {f.name}{sub.state?.file_count?.[f.name] ? `（${sub.state.file_count[f.name]} 词）` : ''}
              </label>
              <input type="checkbox" checked={!!f.for_dark} title="该文件词表同时用作暗链关键词（外链锚文本/URL 匹配；内容审核类词库慎开，易误报）" style={{ marginLeft: 5 }} onChange={(e) => patchSub({ files: (sub.files || []).map((x: any) => (x.path === f.path ? { ...x, for_dark: e.target.checked } : x)) })} />
              <span style={{ opacity: .75 }}>暗</span>
              <span style={{ cursor: 'pointer', marginLeft: 4, opacity: .6 }} title={'移除 ' + f.path} onClick={(e) => { e.preventDefault(); e.stopPropagation(); delSubFile(f.path); }}>✕</span>
            </div>
          ))}
          {!(sub.files || []).length && <span className="muted" style={{ fontSize: 12 }}>暂无词库文件：可「发现文件」自动拉取仓库清单，或「＋ 文件」手工添加路径</span>}
        </div>
        {sub.state?.word_count > 0 && (<div className="toolbar" style={{ marginTop: 8 }}>
          <button onClick={() => setWmOpen(true)}>📦 管理词库</button>
          <span className="muted">词库共 {sub.state.word_count} 词（搜索 / 增补 / 删除）</span>
        </div>)}
        {wmOpen && (<SensWordsModal onClose={() => setWmOpen(false)} onEffective={setSubEffective} />)}
      </div>)}
      <div className="toolbar"><button onClick={saveCfg}>保存</button>{msg && <span className="muted">{msg}</span>}</div></div></Card>)}
    <WihPanel /></div>); }

// 日志管理：用户操作日志 / 登录日志 / 代理故障切换日志（system_logs 统一视图）
function LogsPanel() { const [rows, setRows] = useState<any[]>([]); const [total, setTotal] = useState(0); const [pg, setPg] = useState(1);
  const [type, setType] = useState(''); const [q, setQ] = useState(''); const [msg, setMsg] = useState('');
  useEffect(() => { setPg(1); }, [type]);
  useEffect(() => { const t = setTimeout(() => { api.systemLogs(pg, 20, q, type).then((d) => { setRows(d.items || []); setTotal(d.total || 0); if (!(d.items || []).length && pg > 1) setPg(pg - 1); }).catch(() => undefined); }, q ? 300 : 0); return () => clearTimeout(t); }, [pg, q, type]);
  const TYPES: [string, string][] = [['', '全部'], ['op', '操作日志'], ['login', '登录日志'], ['proxy_health', '代理切换日志'], ['console', 'Console 运行日志']];
  return (<Card title="日志管理"><div className="toolbar">
    {TYPES.map(([v, l]) => (<button key={v} className={type === v ? 'active' : ''} onClick={() => setType(v)}>{l}</button>))}
    <input className="search" placeholder="搜索用户 / 动作 / 对象 / 结果 / Console 内容…" value={q} onChange={(e) => { setQ(e.target.value); setPg(1); }} />
    <span className="muted">共 {total} 条</span>
    <button style={{ marginLeft: 'auto' }} onClick={async () => { if (await askConfirm('确认清空全部系统日志？')) { const r = await api.systemLogsClear(); setMsg('已清空 ' + (r.deleted || 0) + ' 条'); setPg(1); } }}>清空</button></div>
    <Table cols={['created_at', 'username', 'action', 'object', 'client_ip', 'result']} rows={rows} />
    <Pager total={total} page={pg} setPage={setPg} />
    {msg && <div className="muted" style={{ marginTop: 6 }}>{msg}</div>}</Card>); }

function Changes({ pid }: { pid: number }) { const [rows, setRows] = useState<any[]>([]); const [total, setTotal] = useState(0); const [pg, setPg] = useState(1);
  const [q, setQ] = useState(''); const [type, setType] = useState(''); const [change, setChange] = useState('');
  useEffect(() => { setPg(1); }, [pid]);
  useEffect(() => { const t = setTimeout(() => { api.changes(pid, pg, 20, q, type, change).then((d) => { setRows(d.items || []); setTotal(d.total || 0); if (!(d.items || []).length && pg > 1) setPg(pg - 1); }).catch(() => undefined); }, q ? 300 : 0); return () => clearTimeout(t); }, [pid, pg, q, type, change]);
  return (<Card title="资产变化记录"><div className="toolbar">
    <input className="search" placeholder="搜索资产 / 详情…" value={q} onChange={(e) => { setQ(e.target.value); setPg(1); }} />
    <select value={type} onChange={(e) => { setType(e.target.value); setPg(1); }}>
      <option value="">全部类型</option><option value="ip">IP</option><option value="domain">域名</option>
      <option value="port">端口</option><option value="web">Web</option><option value="url">URL</option><option value="vuln">漏洞</option></select>
    <select value={change} onChange={(e) => { setChange(e.target.value); setPg(1); }}>
      <option value="">全部变化</option><option value="add">新增</option><option value="remove">移除</option></select>
    <span className="muted">共 {total} 条</span></div>
    <Table cols={['created_at', 'change', 'asset_type', 'asset', 'detail']} rows={rows} />
    <Pager total={total} page={pg} setPage={setPg} /></Card>); }

function ImportPanel({ pid }: { pid: number }) { const [content, setContent] = useState(''); const [msg, setMsg] = useState('');
  const submit = async (e: React.FormEvent) => { e.preventDefault(); try { const r = await api.importAssets(pid, content, 'mixed'); setMsg(`IP ${r.ips}（新增 ${r.new_ips}），域名 ${r.domains}，URL ${r.urls}`); setContent(''); } catch (ex: any) { setMsg(ex.message); } };
  return (<div><Card title="资产导入"><form className="form" onSubmit={submit}>
    <textarea rows={5} placeholder={'192.168.1.1\nexample.com\nhttps://example.com'} value={content} onChange={(e) => setContent(e.target.value)} required />
    <button type="submit">导入</button>{msg && <div className="ok">{msg}</div>}</form></Card>
    <CertCollectPanel pid={pid} />
    <MappingQueryPanel pid={pid} /></div>); }

// 证书透明度即时收集：crt.name 主源 / crt.sh 备用，查询 CT 日志历史子域，勾选后导入为项目域名资产
function CertCollectPanel({ pid }: { pid: number }) { const [domain, setDomain] = useState(''); const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<any>(null); const [items, setItems] = useState<string[]>([]); const [sel, setSel] = useState<Set<string>>(new Set());
  const run = async (e: React.FormEvent) => { e.preventDefault(); setBusy(true); setMsg(null); setItems([]); setSel(new Set());
    try { const r = await api.ctCollect(domain.trim()); setItems(r.items || []); setSel(new Set(r.items || [])); setMsg(r); } catch (ex: any) { setMsg({ error: ex.message }); } finally { setBusy(false); } };
  const toggle = (d: string) => { const n = new Set(sel); if (n.has(d)) { n.delete(d); } else { n.add(d); } setSel(n); };
  const doImport = async () => { if (!sel.size) return; try { const r = await api.importAssets(pid, [...sel].join('\n'), 'domain'); setMsg({ imported: `已导入 ${r.domains} 个域名（新增 ${r.new_domains ?? '-'}），导入后由扫描任务/实时扫描纳入后续检测` }); } catch (ex: any) { setMsg({ error: ex.message }); } };
  return (<Card title="证书透明度收集"><form className="form" onSubmit={run}><div className="toolbar">
    <input className="search" placeholder="根域名（如 example.com）" value={domain} onChange={(e) => setDomain(e.target.value)} required />
    <button type="submit" disabled={busy}>{busy ? '收集中…' : '查询子域'}</button>
    {msg?.error && <span className="err">{msg.error}</span>}
    {msg?.total > 0 && <span className="muted">命中 {msg.total} 个子域（来源 {msg.source}）</span>}
    {msg && !msg.error && msg.total === 0 && <span className="muted">未收集到子域（两源均无记录或不可达）</span>}</div>
    {items.length > 0 && (<div>
      <div className="toolbar" style={{ marginTop: 6 }}>
        <label className="inline"><input type="checkbox" checked={sel.size === items.length} onChange={(e) => setSel(e.target.checked ? new Set(items) : new Set())} />全选（{sel.size}/{items.length}）</label>
        <button type="button" disabled={!sel.size} onClick={doImport}>导入所选为域名资产</button>
        {msg?.imported && <span className="ok">{msg.imported}</span>}</div>
      <div style={{ maxHeight: 220, overflowY: 'auto', marginTop: 4 }}><table className="tbl"><thead><tr>
        <th style={{ width: 30 }}></th><th>子域名</th></tr></thead>
        <tbody>{items.map((d: string) => (<tr key={d}>
          <td><input type="checkbox" checked={sel.has(d)} onChange={() => toggle(d)} /></td>
          <td style={{ wordBreak: 'break-all' }}>{d}</td>
        </tr>))}</tbody></table></div>
    </div>)}
  </form></Card>); }

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
      const counts = Object.entries(r.counts || {}).map(([k, v]) => k + ' ' + v + ' 条').join('，');
      const skipped = (r.skipped || []).length ? '；未参与（未启用或未填密钥）：' + r.skipped.join('、') : '';
      setMsg('获取 ' + (r.total || 0) + ' 条' + (counts ? '（' + counts + '）' : '') + skipped + (errs ? '；失败：' + errs : ''));
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
          <input type={k.includes('key') ? 'password' : 'text'} placeholder={ph} value={form[k] || ''} onChange={(e) => set(k, e.target.value)} style={k.endsWith('_interval_ms') ? { width: 110 } : undefined} />
        </label>
      ))}
    </div>
  );
  return (
    <Card title="空间测绘数据源（FOFA / Quake / Shodan / 0.zone / ZoomEye）">
      <div className="muted" style={{ marginBottom: 10 }}>
        勾选「资产收集」阶段的扫描任务自动调用已启用的测绘引擎扩展资产（结果先探活再入库，429 自动退避重试）；「资产导入」页支持即时测绘；测绘 API 直连，不走全局代理
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
        {prov('fofa', 'FOFA', [['fofa_key', 'API Key', 'FOFA API 密钥'], ['fofa_base_url', 'Base URL（留空默认）', 'https://fofa.info/api/v1/search/all'], ['fofa_interval_ms', '间隔(ms)', '0=默认 1200']])}
        {prov('quake', 'Quake（360）', [['quake_key', 'API Token', 'X-QuakeToken'], ['quake_base_url', 'Base URL', 'https://quake.360.cn/api/v3/search/quake_service'], ['quake_interval_ms', '间隔(ms)', '0=默认 800']])}
        {prov('shodan', 'Shodan', [['shodan_key', 'API Key', 'Shodan API 密钥'], ['shodan_base_url', 'Base URL', 'https://api.shodan.io/shodan/host/search'], ['shodan_interval_ms', '间隔(ms)', '0=默认 1100']])}
        {prov('zerozone', '0.zone', [['zerozone_key_id', 'Key ID', 'zone_key_id'], ['zerozone_base_url', 'Base URL', 'https://0.zone/api/data/'], ['zerozone_interval_ms', '间隔(ms)', '0=默认 1100']])}
        {prov('zoomeye', 'ZoomEye', [['zoomeye_key', 'API Key', 'ZoomEye API 密钥'], ['zoomeye_base_url', 'Base URL', 'https://api.zoomeye.org/v2/search'], ['zoomeye_interval_ms', '间隔(ms)', '0=默认 1100']])}
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

// 域名一致性校验：任务输入域名为基准，测绘/反查带回的杂域名不入库；纯 IP 任务放行
function DomainConsistencyPanel() { const [enabled, setEnabled] = useState(true); const [roots, setRoots] = useState(''); const [msg, setMsg] = useState('');
  useEffect(() => { api.getDomainConsistency().then((r) => setEnabled(!!r.enabled)).catch(() => undefined); }, []);
  const toggle = async (v: boolean) => { setEnabled(v); try { await api.setDomainConsistency(v); setMsg(v ? '已启用（即时生效）' : '已停用（回到旧行为）'); } catch (e: any) { setMsg(e.message); } };
  const cleanup = async () => {
    const rs = roots.split('\n').map((x: string) => x.trim()).filter(Boolean);
    if (!rs.length) { setMsg('请先填写根域名（每行一个）'); return; }
    if (!(await askConfirm('将删除与这些根域名不一致的全部域名资产及杂域名 Web 资产，确认执行？'))) return;
    try { const r = await api.domainCleanup(rs); setMsg('清理完成：删除域名 ' + (r.deleted_domains || 0) + ' 条、Web 资产 ' + (r.deleted_webs || 0) + ' 条'); } catch (e: any) { setMsg(e.message); }
  };
  return (<Card title="域名一致性校验"><div className="form">
    <div className="toolbar"><label className="inline"><input type="checkbox" checked={enabled} onChange={(e) => toggle(e.target.checked)} />启用（收集到的域名必须与任务输入域名同根，从后往前逐标签比对；纯 IP 任务不受限）</label></div>
    <div className="toolbar"><textarea rows={3} style={{ width: 360 }} placeholder={'存量清理：每行一个根域名'} value={roots} onChange={(e) => setRoots(e.target.value)} />
      <button onClick={cleanup}>按根域名清理存量</button>{msg && <span className="muted">{msg}</span>}</div>
    <p className="hint">生效范围：空间测绘带回的域名与杂域名 vhost 站点、证书透明度收集兜底；拦截明细见任务日志。</p></div></Card>); }

// 敏感路径检测（界面自定义规则，引擎不内置路径与默认集；未配置则该检测跳过）
function LeakPathsPanel() { const [items, setItems] = useState<any[]>([]); const [msg, setMsg] = useState('');
  const [nu, setNu] = useState<any>({ path: '', name: '', severity: 'medium', keyword: '' });
  useEffect(() => { api.getLeakPaths().then((r) => { setItems(r.items || []); }).catch(() => undefined); }, []);
  const save = async (list: any[]) => { try { const r = await api.setLeakPaths(list); setItems(r.items || []); setMsg('已保存并即时生效'); } catch (e: any) { setMsg(e.message); } };
  const add = () => { const p = nu.path.trim(); if (!p) { setMsg('路径不能为空'); return; } save([...items, { ...nu, path: p }]); setNu({ path: '', name: '', severity: 'medium', keyword: '' }); };
  return (<Card title="敏感路径检测（自定义规则）"><div className="toolbar">
    <input className="search" placeholder="路径 如 /.git/config" value={nu.path} onChange={(e) => setNu({ ...nu, path: e.target.value })} />
    <input placeholder="名称（可空）" style={{ width: 160 }} value={nu.name} onChange={(e) => setNu({ ...nu, name: e.target.value })} />
    <label>等级<select value={nu.severity} onChange={(e) => setNu({ ...nu, severity: e.target.value })}>
      <option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="info">信息</option></select></label>
    <input placeholder="命中关键词（可空）" style={{ width: 160 }} value={nu.keyword} onChange={(e) => setNu({ ...nu, keyword: e.target.value })} />
    <button onClick={add}>添加</button>
    <button onClick={() => save([])}>清空</button>
    {msg && <span className="muted">{msg}</span>}</div>
    <Table cols={['path', 'name', 'severity', 'keyword']} rows={items}
      actions={(r: any) => (<button onClick={() => save(items.filter((x) => x.path !== r.path))}>删除</button>)} />
    <p className="hint">命中判定：HTTP 200 且正文包含关键词（未填关键词时要求正文非空）；未配置规则时扫描将跳过敏感路径检测。</p></Card>); }

function Settings() { const [form, setForm] = useState<any>({}); const [msg, setMsg] = useState<any>(null);
  const [testTarget, setTestTarget] = useState('www.baidu.com:80'); const [testRes, setTestRes] = useState<any>(null);
  const proxyDirty = useRef(false); // 用户正在编辑时暂停轮询回填，避免输入被 5 秒刷新覆盖
  useEffect(() => { api.getProxy().then((r) => setForm(r.proxy)).catch(() => undefined); }, []);
  useEffect(() => { const t = setInterval(() => { if (proxyDirty.current) return; api.getProxy().then((r) => setForm(r.proxy)).catch(() => undefined); }, 5000); return () => clearInterval(t); }, []); // 守护自动切换时勾选态实时跟随
  const save = async () => { setMsg(null); try { const r = await api.setProxy(form); proxyDirty.current = false; setMsg({ ok: true, text: `已生效：${r.status}` }); } catch (ex: any) { setMsg({ ok: false, text: ex.message }); } };
  const test = async () => { setTestRes({ loading: true }); setTestRes(await api.testProxy(form, testTarget)); };
  const set = (k: string, v: any) => { proxyDirty.current = true; setForm((f: any) => ({ ...f, [k]: v })); };
  const [healthCfg, setHealthCfg] = useState<any>({ interval_sec: 60 }); const [healthState, setHealthState] = useState<any>(null);
  useEffect(() => { api.getProxyHealth().then((r) => { setHealthCfg({ interval_sec: r.interval_sec || 60, target: r.target || '' }); setHealthState(r.state); }).catch(() => undefined); }, []);
  const saveHealth = async (v: number) => { try { const r = await api.setProxyHealth({ interval_sec: v }); setHealthState(r.state); } catch (e: any) { setMsg({ ok: false, text: '检测间隔保存失败: ' + e.message }); } };
  const saveHealthTarget = async (t: string) => { try { await api.setProxyHealth({ target: t }); } catch (e: any) { setMsg({ ok: false, text: '探测目标保存失败: ' + e.message }); } };
  const toggleHealth = async (v: boolean) => { try { const r = await api.setProxyHealth({ enabled: v }); setHealthState(r.state); } catch (e: any) { setMsg({ ok: false, text: '守护开关设置失败: ' + e.message }); } };
  const [aiCfg, setAiCfg] = useState<any>({}); const [aiMsg, setAiMsg] = useState('');
  useEffect(() => { api.getAIConfig().then(setAiCfg).catch(() => undefined); }, []);
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [aiLoadingModels, setAiLoadingModels] = useState(false);
  const [aiModelOpen, setAiModelOpen] = useState(false); // 模型下拉展开
  const saveAI = async () => { try { await api.setAIConfig(aiCfg); setAiMsg('已保存'); setAiCfg(await api.getAIConfig()); } catch (e: any) { setAiMsg(e.message); } };
  const fetchModels = async () => {
    setAiLoadingModels(true); setAiMsg(''); setAiModelOpen(false);
    try {
      const r = await api.aiModels(aiCfg.base_url, aiCfg.api_key);
      setAiModels(r.models || []);
      if ((r.models || []).length === 0) { setAiMsg('API 返回 0 个模型'); } else { setAiModelOpen(true); }
    } catch (e: any) { setAiMsg('获取失败: ' + e.message); }
    finally { setAiLoadingModels(false); }
  };
  const [wlText, setWlText] = useState(''); const [wlMsg, setWlMsg] = useState('');
  useEffect(() => { api.getWhitelist().then((w: any) => setWlText((w.items || []).join('\n'))).catch(() => undefined); }, []);
  const saveWL = async () => { const items = wlText.split('\n').map((x: any) => x.trim()).filter((x: any) => x !== '');
    try { const r = await api.setWhitelist(items); setWlText((r.items || []).join('\n')); setWlMsg('已保存'); } catch (ex: any) { setWlMsg(ex.message); } };
  const [pw, setPw] = useState({ old: '', neu: '', confirm: '' }); const [pwMsg, setPwMsg] = useState<any>(null);
  const submitPw = async () => {
    setPwMsg(null);
    if (pw.neu.length < 6) { setPwMsg({ ok: false, text: '新密码至少 6 位' }); return; }
    if (pw.neu !== pw.confirm) { setPwMsg({ ok: false, text: '两次输入的新密码不一致' }); return; }
    try {
      await api.changePassword(pw.old, pw.neu);
      setPw({ old: '', neu: '', confirm: '' });
      setPwMsg({ ok: true, text: '密码已修改；其他登录会话已注销，当前会话保持有效' });
    } catch (ex: any) { setPwMsg({ ok: false, text: ex.message }); }
  };
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
            <span style={{ position: 'relative', display: 'inline-block' }}>
              <input style={{ width: 160 }} placeholder="点击获取" value={aiCfg.model || ''} onChange={(e) => setAiCfg({ ...aiCfg, model: e.target.value })} />
              {aiModels.length > 0 && <button type="button" onClick={() => setAiModelOpen(!aiModelOpen)} style={{ fontSize: 10, padding: '6px 4px', marginLeft: 2, verticalAlign: 'top' }}>▼</button>}
              {aiModelOpen && aiModels.length > 0 && (<div style={{ position: 'absolute', top: '100%', left: 0, zIndex: 30, background: 'var(--panel)', border: '1px solid var(--border-hover)', borderRadius: 'var(--radius-xs)', maxHeight: 220, overflowY: 'auto', minWidth: 200, boxShadow: 'var(--shadow-md)' }}>
                {aiModels.map((m: string) => (<div key={m} onMouseDown={() => { setAiCfg({ ...aiCfg, model: m }); setAiModelOpen(false); }} style={{ padding: '5px 10px', cursor: 'pointer', color: m === aiCfg.model ? 'var(--accent)' : 'var(--text)', whiteSpace: 'nowrap' }}>{m}</div>))}
              </div>)}
            </span>
            <button type="button" onClick={fetchModels} disabled={aiLoadingModels} style={{ marginTop: 4, fontSize: 12, padding: '2px 8px' }}>{aiLoadingModels ? '获取中…' : '获取模型列表'}</button>
          </label>
        <label>API Key<input type="password" style={{ width: 280 }} value={aiCfg.api_key || ''} onChange={(e) => setAiCfg({ ...aiCfg, api_key: e.target.value })} /></label>
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
    <DomainConsistencyPanel />
    <Card title="资产白名单（跳过漏洞扫描）"><div className="form">
      <textarea rows={5} placeholder={'每行一项：192.168.1.10 / 10.0.0.0/8 / example.com'} value={wlText} onChange={(e) => setWlText(e.target.value)} />
      <div className="toolbar"><button onClick={saveWL}>保存白名单</button>{wlMsg && <span className="muted">{wlMsg}</span>}</div></div></Card>
    <Card title="全局出站代理"><div className="form">
      <div className="form-row"><label className="inline"><input type="checkbox" checked={!!form.enable} onChange={(e) => set('enable', e.target.checked)} />启用代理</label>
        <label>协议<select value={form.type || 'http'} onChange={(e) => set('type', e.target.value)}><option value="http">HTTP</option><option value="socks5">SOCKS5</option></select></label>
        <label>地址<input value={form.host || ''} onChange={(e) => set('host', e.target.value)} /></label>
        <label>端口<input type="number" value={form.port || ''} onChange={(e) => set('port', +e.target.value)} /></label>
        <label>用户名<input value={form.username || ''} onChange={(e) => set('username', e.target.value)} /></label>
        <label>密码<input type="password" value={form.password || ''} onChange={(e) => set('password', e.target.value)} /></label>
        <label className="inline"><input type="checkbox" checked={!!healthState?.active} onChange={(e) => toggleHealth(e.target.checked)} />连通性守护</label>
        <label>探测目标<input defaultValue="" placeholder={healthCfg.target || 'www.baidu.com:80'} style={{ width: 160 }} onBlur={(e) => saveHealthTarget(e.target.value.trim())} /></label>
        <label>检测间隔(秒)<NumInput width={70} value={healthCfg.interval_sec || 60} min={10} max={86400} onChange={(v) => { setHealthCfg({ ...healthCfg, interval_sec: v }); if (v >= 10) saveHealth(v); }} /></label>
        {healthState && (<span className={healthState.last === 'ok' ? 'ok' : healthState.last === 'fail' ? 'err' : 'muted'}>
          守护{healthState.active ? '运行中' : '未激活'} · 上次检测{healthState.last === 'ok' ? '正常' : healthState.last === 'fail' ? '异常（已切直连，检测继续）' : '-'} {healthState.last_at || ''}</span>)}</div>
      <div className="toolbar"><button onClick={save}>保存并生效</button>
        <input placeholder="测试目标" value={testTarget} onChange={(e) => setTestTarget(e.target.value)} /><button onClick={test}>测试</button>
        {testRes && (testRes.loading ? <span className="muted">测试中…</span> : <span className={testRes.ok ? 'ok' : 'err'}>{testRes.ok ? `连通 ${testRes.latency_ms}ms` : testRes.error}</span>)}</div>
      {msg && <div className={msg.ok ? 'ok' : 'err'}>{msg.text}</div>}</div></Card>
    <Card title="账号安全（修改密码）"><div className="form">
      <div className="form-row">
        <label>当前密码<input type="password" style={{ width: 200 }} value={pw.old} onChange={(e) => setPw({ ...pw, old: e.target.value })} /></label>
        <label>新密码（至少 6 位）<input type="password" style={{ width: 200 }} value={pw.neu} onChange={(e) => setPw({ ...pw, neu: e.target.value })} /></label>
        <label>确认新密码<input type="password" style={{ width: 200 }} value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} /></label>
      </div>
      <div className="toolbar"><button onClick={submitPw}>修改密码</button>{pwMsg && <span className={pwMsg.ok ? 'ok' : 'err'} style={{ marginTop: 0 }}>{pwMsg.text}</span>}</div>
      <p className="hint">修改成功后其他设备的登录会话将被注销，当前会话不受影响。</p></div></Card>
    </div>); }

// 订阅词库管理弹窗：词条（分页/搜索/来源/新增/删除）+ 排除清单（查看/恢复）
function SensWordsModal({ onClose, onEffective }: { onClose: () => void; onEffective: (n: number) => void }) {
  const PS = 100;
  const [tab, setTab] = useState<'words' | 'excluded'>('words');
  const [q, setQ] = useState(''); const [pg, setPg] = useState(0);
  const [d, setD] = useState<any>({ items: [], total: 0, pull: 0, custom: 0, excluded: 0, effective: 0 });
  const [ex, setEx] = useState<any>({ items: [], excluded: 0 });
  const [sel, setSel] = useState<Set<string>>(new Set()); const [addTxt, setAddTxt] = useState(''); const [msg, setMsg] = useState('');
  const load = () => { api.sensSubWords(q, pg * PS).then((r) => { setD(r); setSel(new Set()); }).catch(() => undefined); };
  const loadEx = () => { api.sensSubExcludes(q).then(setEx).catch(() => undefined); };
  useEffect(() => { const t = setTimeout(() => { if (tab === 'words') { load(); } else { loadEx(); } }, q ? 300 : 0); return () => clearTimeout(t); }, [q, pg, tab]);
  useEffect(() => { onEffective(d.effective); }, [d.effective]); // 清空后 0 也要同步外层计数
  const pages = Math.max(1, Math.ceil(d.total / PS));
  const toggle = (w: string) => { const n = new Set(sel); if (n.has(w)) { n.delete(w); } else { n.add(w); } setSel(n); };
  const doAdd = async () => {
    const ws = addTxt.split(/[,，;；\n\s]+/).map((x: string) => x.trim()).filter(Boolean);
    if (!ws.length) return;
    try { const r = await api.sensSubWordsAdd(ws); setMsg(`已新增 ${r.added} 个词条`); setAddTxt(''); load(); } catch (e: any) { setMsg(e.message); }
  };
  const doDel = async (ws: string[]) => {
    if (!ws.length) return;
    try { const r = await api.sensSubWordsDel(ws); setMsg(`已删除 ${r.removed} 个词条（记入排除清单）`); load(); } catch (e: any) { setMsg(e.message); }
  };
  const doRestore = async (ws: string[]) => {
    if (!ws.length) return;
    try { const r = await api.sensSubExcludesRestore(ws); setMsg(`已恢复 ${r.restored} 个词条`); loadEx(); load(); } catch (e: any) { setMsg(e.message); }
  };
  const doClear = async () => {
    if (!(await askConfirm(`清空词库将移除全部 ${d.effective} 个词条（拉取 + 手工），排除清单保留。清空后词库为空，可调整订阅文件后「立即更新」重新拉取。确定清空？`))) return;
    try { const r = await api.sensSubWordsClear(); setMsg(`已清空 ${r.cleared} 个词条`); load(); loadEx(); } catch (e: any) { setMsg(e.message); }
  };
  const allSel = (d.items || []).length > 0 && sel.size === (d.items || []).length;
  return (<div className="modal"><div className="modal-body" style={{ maxWidth: 720 }}>
    <div className="modal-head"><h3>管理订阅词库</h3><button onClick={onClose}>关闭</button></div>
    <div className="toolbar">
      <button className={tab === 'words' ? 'active' : ''} onClick={() => { setTab('words'); setQ(''); setPg(0); }}>词条（{d.effective}）</button>
      <button className={tab === 'excluded' ? 'active' : ''} onClick={() => { setTab('excluded'); setQ(''); }}>排除清单（{d.excluded}）</button>
      <input className="search" placeholder={tab === 'words' ? '搜索词条…' : '搜索排除词条…'} value={q} onChange={(e) => { setQ(e.target.value); setPg(0); }} />
      <span className="muted">生效 {d.effective} · 拉取 {d.pull} · 手工 {d.custom} · 排除 {d.excluded}</span>
      <button disabled={!d.effective} onClick={doClear} title="清空拉取与手工词表（排除清单保留）">清空词库</button>
    </div>
    {tab === 'words' && (<>
      <div className="toolbar">
        <input className="search" style={{ maxWidth: 320 }} placeholder="新增词条（空格/逗号/换行分隔，支持批量）" value={addTxt} onChange={(e) => setAddTxt(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { doAdd(); } }} />
        <button onClick={doAdd}>新增</button>
        <button disabled={!sel.size} onClick={() => doDel([...sel])}>删除所选（{sel.size}）</button>
        {msg && <span className="muted">{msg}</span>}
      </div>
      <div style={{ maxHeight: '38vh', overflowY: 'auto' }}><table className="tbl"><thead><tr>
        <th style={{ width: 30 }}><input type="checkbox" checked={allSel} onChange={(e) => setSel(e.target.checked ? new Set((d.items || []).map((x: any) => x.word)) : new Set())} /></th>
        <th>词条</th><th style={{ width: 64 }}>来源</th><th style={{ width: 64, textAlign: 'right' }}>操作</th></tr></thead>
        <tbody>{(d.items || []).map((x: any) => (<tr key={x.word}>
          <td><input type="checkbox" checked={sel.has(x.word)} onChange={() => toggle(x.word)} /></td>
          <td style={{ wordBreak: 'break-all' }}>{x.word}</td>
          <td className="muted">{x.origin === 'custom' ? '手工' : '拉取'}</td>
          <td className="row-act"><button onClick={() => doDel([x.word])}>删除</button></td>
        </tr>))}</tbody></table></div>
      <div className="toolbar" style={{ marginTop: 6 }}>
        <button disabled={pg === 0} onClick={() => setPg(pg - 1)}>上一页</button>
        <span className="muted">第 {pg + 1} / {pages} 页 · 匹配 {d.total} 词</span>
        <button disabled={pg + 1 >= pages} onClick={() => setPg(pg + 1)}>下一页</button>
      </div>
      <div className="muted" style={{ marginTop: 6 }}>删除的词条记入排除清单，订阅更新不会拉回；手工新增的词条在订阅更新后保留；生效词表 = 拉取 + 手工 − 排除。</div>
    </>)}
    {tab === 'excluded' && (<>
      <div className="toolbar">
        <button disabled={!(ex.items || []).length} onClick={() => doRestore((ex.items || []).slice())}>全部恢复</button>
        {msg && <span className="muted">{msg}</span>}
        <span className="muted">被删除的词条在此列出；恢复后立即回到生效词表（来源为拉取的词若上游仍存在，后续更新会继续保留）</span>
      </div>
      <div style={{ maxHeight: '42vh', overflowY: 'auto' }}><table className="tbl"><thead><tr>
        <th>排除词条</th><th style={{ width: 64, textAlign: 'right' }}>操作</th></tr></thead>
        <tbody>{(ex.items || []).map((w: string) => (<tr key={w}>
          <td style={{ wordBreak: 'break-all' }}>{w}</td>
          <td className="row-act"><button onClick={() => doRestore([w])}>恢复</button></td>
        </tr>))}
        {!(ex.items || []).length && (<tr><td colSpan={2} className="muted" style={{ textAlign: 'center', padding: 16 }}>排除清单为空</td></tr>)}</tbody></table></div>
    </>)}
  </div></div>);
}

// WIH JS 敏感信息检测（Web Info Hunter）：规则管理与单目标即时检测，规则集默认移植自 WIHscan（MIT）
function WihPanel() { const [cfg, setCfg] = useState<any>(null); const [msg, setMsg] = useState<any>(null);
  const [target, setTarget] = useState(''); const [res, setRes] = useState<any>(null);
  useEffect(() => { api.getWihSettings().then(setCfg).catch(() => undefined); }, []);
  const save = async (c: any) => { try { const r = await api.setWihSettings(c); setCfg(r); setMsg({ ok: true, text: '已保存并即时生效' }); } catch (e: any) { setMsg({ ok: false, text: e.message }); } };
  const toggleRule = (id: string, en: boolean) => save({ ...cfg, rules: cfg.rules.map((r: any) => (r.id === id ? { ...r, enabled: en } : r)) });
  const editPattern = async (r: any) => { const p = await askText('编辑规则正则（' + r.id + '）', r.pattern); if (p) save({ ...cfg, rules: cfg.rules.map((x: any) => (x.id === r.id ? { ...x, pattern: p } : x)) }); };
  const delRule = async (r: any) => { if (await askConfirm('删除规则 ' + r.id + ' ？')) save({ ...cfg, rules: cfg.rules.filter((x: any) => x.id !== r.id) }); };
  const addRule = async () => { const id = await askText('新增 WIH 规则', '规则 ID（如 my_ak）'); if (!id) return; const pattern = await askText('新增规则 ' + id, '正则表达式'); if (!pattern) return; save({ ...cfg, rules: [...cfg.rules, { id, name: id, enabled: true, severity: 'info', pattern }] }); };
  const runTest = async () => { if (!target.trim()) return; setRes({ loading: true }); try { setRes(await api.testWih(target.trim())); } catch (e: any) { setRes({ error: e.message }); } };
  if (!cfg) return null;
  return (<Card title="敏感信息检测"><div className="toolbar">
    <label className="inline"><input type="checkbox" checked={!!cfg.enabled_in_scan} onChange={(e) => setCfg({ ...cfg, enabled_in_scan: e.target.checked })} />扫描时执行（随勾选"弱点检测"的任务）</label>
    <label>每站点 JS 上限<input type="number" style={{ width: 70 }} value={cfg.max_js_per_site} onChange={(e) => setCfg({ ...cfg, max_js_per_site: +e.target.value })} /></label>
    <button onClick={() => save(cfg)}>保存</button>
    <button onClick={addRule}>＋ 规则</button>
    <span className="muted">共 {cfg.rules.length} 条 · 启用 {cfg.rules.filter((r: any) => r.enabled).length} 条</span>
    {msg && <span className={msg.ok ? 'ok' : 'err'}>{msg.text}</span>}</div>
    <div className="toolbar">
      <input className="search" placeholder="即时检测：页面或 JS 的 URL" value={target} onChange={(e) => setTarget(e.target.value)} />
      <button onClick={runTest}>检测</button>
      {res?.loading && <span className="muted">检测中…</span>}
      {res?.error && <span className="err">{res.error}</span>}
      {res?.hits && <span className={res.hits.length ? 'ok' : 'muted'}>{res.hits.length ? '命中 ' + res.hits.length + ' 条' : '未发现敏感信息'}</span>}</div>
    {res?.hits && res.hits.length > 0 && (<table className="tbl"><thead><tr><th>等级</th><th>名称</th><th>命中内容</th></tr></thead>
      <tbody>{res.hits.map((h: any, i: number) => (<tr key={i}><td><SevTag sev={h.severity} /></td><td>{h.name}</td><td style={{ maxWidth: 480, wordBreak: 'break-all' }}>{h.match}</td></tr>))}</tbody></table>)}
    <table className="tbl"><thead><tr><th>id</th><th>名称</th><th>等级</th><th>正则</th><th>启用</th><th style={{ textAlign: 'right' }}>操作</th></tr></thead>
      <tbody>{cfg.rules.map((r: any) => (<tr key={r.id}>
        <td>{r.id}</td><td>{r.name}</td><td><SevTag sev={r.severity || 'info'} /></td>
        <td style={{ maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.pattern}>{r.pattern}</td>
        <td><input type="checkbox" checked={r.enabled} onChange={(e) => toggleRule(r.id, e.target.checked)} /></td>
        <td className="row-act"><button onClick={() => editPattern(r)}>编辑</button> <button onClick={() => delRule(r)}>删除</button></td>
      </tr>))}</tbody></table>
    <div className="muted" style={{ marginTop: 6 }}>扫描时随"弱点检测"阶段执行：对站点首页与引用 JS（限额内）做规则匹配，命中归入弱点管理（类型：敏感信息）；未勾选弱点检测的任务不执行。</div>
  </Card>); }

function VulnRules() { const [data, setData] = useState<any>({ items: [], total: 0 }); const [stats, setStats] = useState<any>(null);
  const [mirrorCustomUI, setMirrorCustomUI] = useState(false); // 下拉切到"自定义"时展示自定义输入框（未保存前不影响生效值）
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
    <LeakPathsPanel />
    <Card title="模板源更新"><div className="toolbar">
      <input className="search" placeholder="GitHub 仓库 URL" value={newURL} onChange={(e) => setNewURL(e.target.value)} /><button onClick={() => { if (newURL.trim()) { applySources({ ...sources.config, sources: [...(sources.config?.sources || []), { url: newURL.trim(), enabled: true }] }, '已添加'); setNewURL(''); } }}>添加源</button>
      <label className="inline"><input type="checkbox" checked={!!sources.config?.auto_daily} onChange={(e) => applySources({ ...sources.config, auto_daily: e.target.checked }, '已更新')} />每日自动更新</label>
      <label>更新时间(HH:MM)<input type="text" placeholder="02:00" style={{ width: 90 }} value={sources.config?.auto_time || '02:00'}
        onChange={(e) => { const t = e.target.value.trim(); setSources({ ...sources, config: { ...sources.config, auto_time: e.target.value } }); if (/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(t)) applySources({ ...sources.config, auto_time: t }, '已设 ' + t); }} /></label>
      <label className="inline"><input type="checkbox" checked={!!sources.config?.mirror}
        onChange={(e) => applySources({ ...sources.config, mirror: e.target.checked ? (sources.config?.mirror || 'https://ghproxy.com') : '' }, e.target.checked ? '已启用镜像加速' : '已停用镜像（直连）')} />镜像加速</label>
      <label>镜像前缀
        <select value={['https://ghproxy.com', 'https://ghfast.top', 'https://gh-proxy.com', 'https://mirror.ghproxy.com'].includes(sources.config?.mirror) && !mirrorCustomUI ? sources.config.mirror : 'custom'}
          onChange={(e) => { if (e.target.value === 'custom') { setMirrorCustomUI(true); } else { setMirrorCustomUI(false); applySources({ ...sources.config, mirror: e.target.value }, '已切换 ' + e.target.value.replace('https://', '')); } }}>
          <option value="https://ghproxy.com">ghproxy.com</option>
          <option value="https://ghfast.top">ghfast.top</option>
          <option value="https://gh-proxy.com">gh-proxy.com</option>
          <option value="https://mirror.ghproxy.com">mirror.ghproxy.com</option>
          <option value="custom">自定义</option>
        </select></label>
      {(mirrorCustomUI || (!['https://ghproxy.com', 'https://ghfast.top', 'https://gh-proxy.com', 'https://mirror.ghproxy.com'].includes(sources.config?.mirror) && sources.config?.mirror)) && (<label>自定义地址<input type="text" placeholder="https://your-mirror.example.com" style={{ width: 220 }}
        value={sources.config?.mirror && !['https://ghproxy.com', 'https://ghfast.top', 'https://gh-proxy.com', 'https://mirror.ghproxy.com'].includes(sources.config.mirror) ? sources.config.mirror : ''}
        onChange={(e) => { setMirrorCustomUI(true); setSources({ ...sources, config: { ...sources.config, mirror: e.target.value } }); }}
        onBlur={(e) => { const v = e.target.value.trim(); if (v) { applySources({ ...sources, config: { ...sources.config, mirror: v } }, '已保存自定义镜像'); } else { setMirrorCustomUI(false); } }} /></label>)}
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

const NAV = [['#', '仪表盘'], ['#assets', '资产管理'], ['#vulns', '漏洞风险'], ['#weakness', '弱点管理'], ['#tasks', '扫描任务'], ['#monitor', '资产监控'], ['#import', '资产导入'], ['#changes', '变化监控'], ['#logs', '日志管理'], ['#rules', '漏洞规则库'], ['#settings', '系统设置']];
// 不依赖项目的全局页面：无项目时也可正常使用
const GLOBAL_PAGES = ['#rules', '#settings'];

export default function App() { const [logged, setLogged] = useState(!!getToken()); const [projects, setProjects] = useState<Project[]>([]);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  const applyTheme = (t: string) => { setTheme(t); localStorage.setItem('theme', t); document.documentElement.dataset.theme = t; };
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
        <div className="theme-switch">
          {([['dark', '深色'], ['gray', '灰色'], ['light', '浅色']] as [string, string][]).map(([v, l]) => (
            <button key={v} className={theme === v ? 'active' : ''} onClick={() => applyTheme(v)}>{l}</button>
          ))}
        </div>
        <nav>
          {NAV.map(([h, label]) => (
            <a key={h} href={h} className={page === h ? 'active' : ''}>{label}</a>
          ))}
          <a href="#login" onClick={() => { localStorage.removeItem('token'); setLogged(false); }}>退出</a>
        </nav>
      </header>
    <main>{pid === 0 && !GLOBAL_PAGES.includes(page) && <Card>请先创建项目</Card>}
      {pid > 0 && page === '#' && <Dashboard pid={pid} />}{pid > 0 && page === '#assets' && <Assets pid={pid} />}
      {pid > 0 && page === '#vulns' && <Vulns pid={pid} />}{pid > 0 && page === '#weakness' && <WeaknessPanel pid={pid} />}{pid > 0 && page === '#tasks' && <Tasks pid={pid} />}
      {pid > 0 && page === '#monitor' && <Monitor pid={pid} />}{pid > 0 && page === '#import' && <ImportPanel pid={pid} />}
      {pid > 0 && page === '#changes' && <Changes pid={pid} />}{page === '#logs' && <LogsPanel />}{page === '#rules' && <VulnRules />}
      {page === '#settings' && <Settings />}</main>
    <footer className="muted">仅用于已授权资产的安全检测</footer><AskDialog /></div>); }
