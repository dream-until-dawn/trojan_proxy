import { request } from './auth.js';

// 实时窗口单独轮询；历史查询仅在登录、选择范围或手动刷新时执行。
const $ = (id) => document.getElementById(id);
let active = false;
let timer;
let offset = 0;
let generation = 0;
let dashboardRequest = 0;

function bytes(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let number = amount; let unit = 0;
  while (number >= 1024 && unit < units.length - 1) { number /= 1024; unit++; }
  return `${number.toFixed(unit ? 2 : 0)} ${units[unit]}`;
}

function renderLive(live) {
  $('traffic-speed').textContent = live.available
    ? `上传 ${bytes(live.upload_bps)}/s · 下载 ${bytes(live.download_bps)}/s`
    : '当前网速：暂无有效采样';
  $('traffic-live-message').textContent = live.message || '';
}

function renderTimeline(timeline) {
  const svg = $('traffic-chart'); svg.replaceChildren();
  const points = timeline.points || [];
  const usable = points.filter((point) => point.observed_ms > 0 && !point.gap);
  if (!usable.length) return;
  const first = points[0].bucket; const span = Math.max(timeline.step_seconds, points.at(-1).bucket - first);
  const maximum = Math.max(1, ...usable.map((point) => Math.max(point.upload, point.download) * 1000 / point.observed_ms));
  for (const [field, color] of [['upload', '#146b70'], ['download', '#416bb8']]) {
    let segment = []; let previous;
    const flush = () => {
      if (segment.length > 1) {
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
        line.setAttribute('points', segment.join(' ')); line.setAttribute('fill', 'none');
        line.setAttribute('stroke', color); line.setAttribute('stroke-width', '2'); svg.append(line);
      }
      segment = [];
    };
    for (const point of points) {
      if (point.gap || point.observed_ms <= 0 || (previous !== undefined && point.bucket - previous > timeline.step_seconds)) flush();
      if (!point.gap && point.observed_ms > 0) {
        const x = 10 + (point.bucket - first) * 780 / span;
        const y = 130 - (Number(point[field]) * 1000 / point.observed_ms) * 120 / maximum;
        if (Number.isFinite(x) && Number.isFinite(y)) segment.push(`${x.toFixed(2)},${y.toFixed(2)}`);
      }
      previous = point.bucket;
    }
    flush();
  }
}

async function refreshDashboard() {
  const expected = generation;
  const requestNumber = ++dashboardRequest;
  try {
    const result = await request('/api/traffic/dashboard', { hours: Number($('traffic-hours').value), offset });
    if (!active || generation !== expected || dashboardRequest !== requestNumber) return;
    renderLive(result.live);
    $('traffic-total').textContent = `上传 ${bytes(result.totals.upload)} · 下载 ${bytes(result.totals.download)}`;
    $('traffic-gap').textContent = result.totals.gap ? '选定范围存在采集缺口，已知流量不能代表完整流量。' : '历史最多保留最近30天；空白时段不作为零流量补齐。';
    const rows = $('traffic-targets'); rows.replaceChildren();
    for (const item of result.targets) {
      const row = document.createElement('tr');
      for (const value of [item.ip, bytes(item.upload), bytes(item.download), item.connections, item.gap ? '不完整' : '正常']) {
        const cell = document.createElement('td'); cell.textContent = String(value); row.append(cell);
      }
      rows.append(row);
    }
    if (!result.targets.length) { const row = document.createElement('tr'); const cell = document.createElement('td'); cell.colSpan = 5; cell.textContent = '所选时间范围暂无目的地址记录'; row.append(cell); rows.append(row); }
    $('traffic-prev').disabled = offset === 0;
    $('traffic-next').disabled = result.targets.length < 100 || offset >= 10000;
    $('traffic-page').textContent = `第 ${offset / 100 + 1} 页`;
    renderTimeline(result.timeline); $('traffic-message').textContent = '';
  } catch (error) {
    if (active && generation === expected && dashboardRequest === requestNumber) $('traffic-message').textContent = error.message;
  }
}

async function pollLive() {
  const expected = generation;
  try {
    const live = await request('/api/traffic/live');
    if (active && generation === expected) renderLive(live);
  } catch (error) {
    if (active && generation === expected) $('traffic-live-message').textContent = error.message;
  }
  if (active && generation === expected) timer = setTimeout(pollLive, 2000);
}

// 登录后启用，退出后清空目的地址，避免另一个会话看到先前记录。
export async function startTraffic() {
  stopTraffic(); active = true; const expected = generation; await refreshDashboard();
  if (active && generation === expected) timer = setTimeout(pollLive, 2000);
}
export function stopTraffic() {
  active = false; generation++; clearTimeout(timer); offset = 0;
  $('traffic-targets').replaceChildren(); $('traffic-chart').replaceChildren();
  for (const id of ['traffic-total', 'traffic-speed', 'traffic-live-message', 'traffic-gap', 'traffic-message', 'traffic-page']) $(id).textContent = '';
}
$('traffic-refresh').addEventListener('click', refreshDashboard);
$('traffic-hours').addEventListener('change', () => { offset = 0; refreshDashboard(); });
$('traffic-prev').addEventListener('click', () => { offset = Math.max(0, offset - 100); refreshDashboard(); });
$('traffic-next').addEventListener('click', () => { offset = Math.min(10000, offset + 100); refreshDashboard(); });
$('traffic-clear').addEventListener('click', async () => {
  if (!$('traffic-ack-clear').checked) { $('traffic-message').textContent = '请先确认永久清空统计历史'; return; }
  const button = $('traffic-clear'); button.disabled = true;
  try {
    const result = await request('/api/traffic/clear', { confirm: true });
    offset = 0; $('traffic-ack-clear').checked = false; await refreshDashboard();
    $('traffic-message').textContent = result.message;
  } catch (error) { $('traffic-message').textContent = error.message; }
  finally { button.disabled = false; }
});
