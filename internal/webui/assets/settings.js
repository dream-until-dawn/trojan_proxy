import { request } from "./auth.js";

let snapshot = null;
let generation = 0;
let imported = null;
const panel = document.querySelector("#settings-panel");
const form = document.querySelector("#settings-form");
const message = document.querySelector("#settings-message");
const field = name => document.querySelector(`#site-${name}`);

function toggleAdminMode() {
  const byPath = field("admin-mode").value === "path";
  document.querySelector("#site-admin-port-field").hidden = byPath;
  document.querySelector("#site-admin-path-field").hidden = !byPath;
  field("admin-path").disabled = !byPath;
}

function directoryRow(binding = { id: "", root: "", relative: "." }) {
  const row = document.createElement("div"); row.className = "directory-binding";
  const values = [["目录名称", "id", binding.id], ["授权挂载", "root", binding.root], ["挂载内相对路径", "relative", binding.relative]];
  for (const [labelText, key, value] of values) {
    const label = document.createElement("label"); label.textContent = labelText;
    const input = document.createElement(key === "root" ? "select" : "input");
    input.dataset.key = key; input.required = true;
    if (key === "root") {
      for (const id of snapshot?.mounts || []) { const option = document.createElement("option"); option.value = id; option.textContent = id; input.append(option); }
    } else { input.maxLength = key === "id" ? 64 : 512; }
    input.value = value || (key === "root" ? snapshot?.mounts?.[0] || "" : "");
    label.append(input); row.append(label);
  }
  const remove = document.createElement("button"); remove.type = "button"; remove.className = "secondary"; remove.textContent = "移除目录绑定";
  remove.addEventListener("click", () => row.remove()); row.append(remove);
  document.querySelector("#site-directories").append(row);
}

function render() {
  const site = snapshot.candidate || snapshot.site;
  document.querySelector("#settings-legend").textContent = snapshot.candidate ? "候选设置（待确认）" : "网站与管理入口";
  field("domain").value = site.domain;
  field("admin-port").value = site.admin_port;
  field("admin-mode").value = site.admin_path ? "path" : "port";
  field("admin-path").value = site.admin_path || "/proxy";
  toggleAdminMode();
  field("vpn-port").value = site.vpn_port;
  field("resolver").value = site.vpn_resolver;
  field("addresses").value = (site.vpn_own_addresses || []).join("\n");
  field("certificate-source").value = site.certificate_source;
  field("acme-email").value = site.acme_email;
  imported = site.imported_version ? { domain: site.domain, version: site.imported_version } : null;
  document.querySelector("#site-directories").replaceChildren();
  for (const binding of site.directories || []) directoryRow(binding);
  document.querySelector("#settings-fields").disabled = Boolean(snapshot.candidate);
  document.querySelector("#site-ack-change").checked = false;
  document.querySelector("#site-add-directory").disabled = !snapshot.mounts.length || Boolean(snapshot.candidate);
  const pending = document.querySelector("#site-pending"); pending.hidden = !snapshot.candidate;
  const link = document.querySelector("#site-candidate-link"); link.removeAttribute("href"); link.textContent = "";
  if (snapshot.candidate) {
    document.querySelector("#site-pending-summary").textContent = `候选入口有效至 ${new Date(snapshot.deadline * 1000).toLocaleString()}。请打开新入口，用口令和下一组验证码重新登录，再确认。到期会恢复原入口。`;
    const target = new URL(snapshot.candidate_entry || snapshot.candidate_origin);
    if (target.protocol === "https:" || (target.protocol === "http:" && target.hostname === "127.0.0.1")) {
      link.href = target.href; link.textContent = `打开候选入口 ${target.href}`;
    }
    const currentBase = new URL("./", import.meta.url);
    const targetPath = target.pathname.endsWith("/") ? target.pathname : `${target.pathname}/`;
    document.querySelector("#site-confirm").disabled = currentBase.origin !== target.origin || currentBase.pathname !== targetPath || Date.now() >= snapshot.deadline * 1000;
  }
  document.querySelector("#site-current").textContent = `当前入口：${snapshot.current_entry || snapshot.current_origin} · 修订 ${snapshot.revision}`;
}

export function clearSettings() {
  generation++; snapshot = null; imported = null;
  form.reset(); document.querySelector("#certificate-form").reset();
  toggleAdminMode();
  document.querySelector("#site-directories").replaceChildren();
  document.querySelector("#site-candidate-link").removeAttribute("href");
  document.querySelector("#site-candidate-link").textContent = "";
  for (const id of ["site-current", "settings-message", "certificate-status", "certificate-message"]) document.querySelector(`#${id}`).textContent = "";
  panel.hidden = true;
  document.querySelector("#settings-fields").disabled = false;
  for (const id of ["site-propose", "certificate-import"]) document.querySelector(`#${id}`).disabled = false;
}

export async function refreshSettings() {
  const current = generation;
  try {
    const result = await request("/api/settings/status");
    if (current !== generation) return;
    panel.hidden = result.available === false;
    if (!result.available) return;
    snapshot = result.settings; render(); await refreshCertificate();
  } catch (error) {
    if (current === generation) { panel.hidden = false; message.textContent = error.message; }
  }
}

async function refreshCertificate() {
  const current = generation;
  try {
    const state = await request("/api/certificates/status");
    if (current !== generation) return;
    document.querySelector("#certificate-status").textContent = state.available
      ? `${state.message}${state.info ? ` · 有效至 ${new Date(state.info.not_after).toLocaleString()}` : ""}` : "证书管理尚未连接。";
  } catch (error) { if (current === generation) document.querySelector("#certificate-status").textContent = error.message; }
}

function draftSite() {
  const source = field("certificate-source").value;
  const domain = field("domain").value.trim();
  return {
    domain, admin_port: Number(field("admin-port").value), vpn_port: Number(field("vpn-port").value),
    admin_path: field("admin-mode").value === "path" ? field("admin-path").value.trim() : "",
    vpn_resolver: field("resolver").value.trim(), vpn_own_addresses: field("addresses").value.split(/[\s,，]+/).filter(Boolean),
    certificate_source: source, acme_email: field("acme-email").value.trim(),
    imported_version: source === "imported" && imported?.domain === domain ? imported.version : "",
    directories: Array.from(document.querySelectorAll(".directory-binding"), row => Object.fromEntries(
      Array.from(row.querySelectorAll("[data-key]"), input => [input.dataset.key, input.value.trim()]))),
  };
}

form.addEventListener("submit", async event => {
  event.preventDefault();
  if (!snapshot || !document.querySelector("#site-ack-change").checked) { message.textContent = "请先确认入口变更会影响连接，并保存路由草稿。"; return; }
  const current = generation; const before = snapshot.revision;
  document.querySelector("#site-propose").disabled = true;
  try {
    await request("/api/settings/propose", { revision: before, site: draftSite() });
    if (current !== generation) return;
    document.dispatchEvent(new CustomEvent("configuration-changed", { detail: { kind: "settings", before, after: before + 1 } }));
    await refreshSettings(); message.textContent = "候选入口已创建。请从新入口重新登录确认；也可撤回。";
  } catch (error) { if (current === generation) message.textContent = error.message; }
  finally { if (current === generation) document.querySelector("#site-propose").disabled = false; }
});

async function finishTransition(action) {
  if (!snapshot) return;
  const current = generation; const before = snapshot.revision;
  try {
    await request(`/api/settings/${action}`, { revision: before });
    if (current !== generation) return;
    document.dispatchEvent(new CustomEvent("configuration-changed", { detail: { kind: "settings", before, after: before + 1 } }));
    await refreshSettings(); message.textContent = action === "confirm" ? "新入口及设置已确认生效。" : "候选变更已撤回。";
  } catch (error) { if (current === generation) message.textContent = error.message; }
}

document.querySelector("#certificate-form").addEventListener("submit", async event => {
  event.preventDefault(); const current = generation;
  const output = document.querySelector("#certificate-message");
  const chain = document.querySelector("#certificate-chain").files[0];
  const key = document.querySelector("#certificate-key").files[0];
  const domain = field("domain").value.trim();
  if (!domain || !chain || !key || chain.size > 1024 * 1024 || key.size > 65536) { output.textContent = "先填写域名，并选择证书链（最多1MiB）和私钥（最多64KiB）。"; return; }
  const button = document.querySelector("#certificate-import"); button.disabled = true;
  try {
    const body = { domain, certificate: await chain.text(), private_key: await key.text() };
    if (current !== generation) return;
    const result = await request("/api/certificates/import", body);
    if (current !== generation) return;
    imported = { domain, version: result.version }; field("certificate-source").value = "imported";
    output.textContent = `证书已核验并暂存，有效至 ${new Date(result.info.not_after).toLocaleString()}。返回系统设置，提交候选并确认后才会启用。`;
  } catch (error) { if (current === generation) output.textContent = error.message; }
  finally { if (current === generation) { document.querySelector("#certificate-form").reset(); button.disabled = false; } }
});

field("domain").addEventListener("change", () => {
  if (!field("domain").value.trim()) field("certificate-source").value = "none";
  else if (field("certificate-source").value === "none") field("certificate-source").value = "automatic";
});
document.querySelector("#site-add-directory").addEventListener("click", () => directoryRow());
document.querySelector("#site-refresh").addEventListener("click", refreshSettings);
field("admin-mode").addEventListener("change", toggleAdminMode);
document.querySelector("#site-confirm").addEventListener("click", () => finishTransition("confirm"));
document.querySelector("#site-cancel").addEventListener("click", () => finishTransition("cancel"));
document.querySelector("#certificate-refresh").addEventListener("click", refreshCertificate);
document.addEventListener("configuration-changed", event => {
  const change = event.detail;
  if (snapshot && change.kind !== "settings" && snapshot.revision === change.before) snapshot.revision = change.after;
});
