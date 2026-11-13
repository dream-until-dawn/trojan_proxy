import { request } from "./auth.js";

// 网站HTTP元数据与VPN目的IP统计独立；只在本页手动读取，不增加持续轮询。
const el = id => document.getElementById(`access-${id}`);
let active = false, revision = 0, before = 0, next = 0, pages = [], generation = 0;
const bytes = value => new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 1 }).format(value / 1024) + " KiB";
function filter() {
  return { hours: Number(el("hours").value), ip: el("ip").value.trim(), host: el("host").value.trim(),
    path: el("path").value.trim(), status_class: Number(el("class").value), trust: el("trust").value, before_id: before };
}
function chart(buckets) {
  const svg = el("chart"); svg.replaceChildren();
  if (!buckets.length) return;
  const max = Math.max(1, ...buckets.map(b => b.requests));
  const width = 800 / buckets.length;
  for (const [i, bucket] of buckets.entries()) {
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    const height = bucket.requests / max * 100;
    for (const [key, value] of Object.entries({ x: i * width, y: 110 - height, width: Math.max(1, width - 2), height, fill: "#19776b" })) rect.setAttribute(key, value);
    const title = document.createElementNS(svg.namespaceURI, "title");
    title.textContent = `${new Date(bucket.at_ms).toLocaleString()}：${bucket.requests} 请求，${bucket.errors} 错误`;
    rect.append(title); svg.append(rect);
  }
}
async function refresh(includePolicy = false) {
  if (!active) return;
  const current = ++generation;
  el("message").textContent = "正在读取网站访问记录…";
  el("refresh").disabled = true;
  try {
    const [state, data, policy] = await Promise.all([request("/api/access/status"), request("/api/access/dashboard", filter()), includePolicy ? request("/api/access/policy") : null]);
    if (!active || current !== generation) return;
    el("state").textContent = `${state.message}；积压 ${bytes(state.backlog_bytes)}；无效 ${state.invalid_records}；可能间断 ${state.possible_gaps}；最近采集 ${state.last_collected_ms ? new Date(state.last_collected_ms).toLocaleString() : "尚未完成"}`;
    el("total").textContent = `${data.totals.requests} 请求 · 白名单 ${data.totals.trusted} · 4xx/5xx ${data.totals.errors} · 请求体 ${bytes(data.totals.upload)} · 响应体 ${bytes(data.totals.download)}`;
    const rows = document.createDocumentFragment();
    for (const record of data.rows) {
      const tr = document.createElement("tr");
      for (const value of [new Date(record.at_ms).toLocaleString(), record.ip, record.trusted ? "白名单 / 7天" : "其他 / 30天", `${record.host}:${record.port}`, record.method, record.path, record.status || "中断", `${record.duration_ms.toFixed(1)} ms`, `${bytes(record.upload)} / ${bytes(record.download)}`]) {
        const td = document.createElement("td"); td.textContent = value; tr.append(td);
      }
      rows.append(tr);
    }
    el("rows").replaceChildren(rows); chart(data.hourly);
    next = data.next_before_id; el("next").disabled = !next; el("prev").disabled = !pages.length;
    el("page").textContent = `第 ${pages.length + 1} 页，每页最多50条`;
    if (policy) { revision = policy.revision; el("whitelist").value = policy.cidrs.join("\n"); el("revision").textContent = `白名单修订 ${revision}`; }
    el("message").textContent = state.available ? (data.rows.length ? "已刷新。统计包含管理页面自身和健康探测请求。" : "当前筛选范围没有可见记录。") : "采集当前不可用，以下历史可能不完整。";
  } catch (error) { if (active && current === generation) {el("rows").replaceChildren();el("total").textContent="";chart([]);el("message").textContent = error.message;} }
  finally { if (current === generation) el("refresh").disabled = false; }
}
export function startAccess() { active = true; if (location.hash === "#access") refresh(true); }
export function clearAccess() {
  active = false; generation++; revision = 0; before = 0; next = 0; pages = [];
  el("rows").replaceChildren();chart([]);el("filters").reset();el("whitelist").value = "";el("ack").checked = false;
  for (const id of ["total", "state", "message", "policy-message", "revision", "page"]) el(id).textContent = "";
  el("refresh").disabled = false;el("next").disabled = true;el("prev").disabled = true;
}
window.addEventListener("hashchange", () => { if (active && location.hash === "#access") refresh(!revision); });
el("filters").addEventListener("submit", e => { e.preventDefault();before=0;pages=[];refresh(); });
el("next").addEventListener("click", () => { if(next){pages.push(before);before=next;refresh();} });
el("prev").addEventListener("click", () => { if(pages.length){before=pages.pop();refresh();} });
el("policy-refresh").addEventListener("click", () => refresh(true));
el("apply").addEventListener("click", async () => {
  if (!el("ack").checked) {el("policy-message").textContent="请先确认历史重分类及清理。";return;}
  const current = generation;el("apply").disabled = true;
  try {
    const result = await request("/api/access/policy/apply", { revision, cidrs: el("whitelist").value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean), confirm:true });
    if (!active || current !== generation) return;
    el("policy-message").textContent=result.message;el("ack").checked=false;before=0;pages=[];await refresh(true);
  } catch(error) {if(active) el("policy-message").textContent=error.message;}
  finally {el("apply").disabled=false;}
});
