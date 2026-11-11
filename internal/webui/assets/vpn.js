import { request } from "./auth.js";

let revision = 0;
let enabled = false;
const message = document.querySelector("#vpn-message");
const controls = ["vpn-enable", "vpn-disable", "vpn-rotate", "vpn-export"];

// 普通刷新只读取非秘密状态；口令仅在明确下载时进入临时内存。
export async function refreshVPN() {
  try {
    const state = await request("/api/vpn/status");
    revision = state.revision || 0;
    enabled = Boolean(state.enabled);
    const available = state.available !== false;
    document.querySelector("#vpn-status").textContent = state.message;
    document.querySelector("#vpn-endpoint").textContent = available ? `${state.domain || "尚无域名"}:${state.port} · 修订 ${revision}` : "";
    const certificate = state.certificate;
    document.querySelector("#vpn-certificate").textContent = certificate
      ? `证书有效至 ${new Date(certificate.not_after).toLocaleString()} · 指纹 ${certificate.fingerprint}`
      : "尚无匹配且可信的有效证书，不能启用VPN。";
    document.querySelector("#vpn-enable").disabled = !available || !state.certificate_ready || enabled || state.pending;
    document.querySelector("#vpn-disable").disabled = !available || !enabled || state.pending;
    document.querySelector("#vpn-rotate").disabled = !available || !enabled || !state.running || state.pending;
    document.querySelector("#vpn-export").disabled = !available || !enabled || !state.running || !state.certificate_ready || state.pending;
  } catch (error) {
    message.textContent = error.message;
    for (const id of controls) document.querySelector(`#${id}`).disabled = true;
  }
}

async function applyVPN(nextEnabled, rotate) {
  if (!document.querySelector("#vpn-ack-change").checked) {
    message.textContent = "请先确认启停或口令轮换会影响VPN连接。"; return;
  }
  for (const id of controls) document.querySelector(`#${id}`).disabled = true;
  message.textContent = "正在校验与应用…";
  try {
    const before = revision;
    await request("/api/vpn/apply", { revision, enabled: nextEnabled, rotate });
    message.textContent = rotate ? "新口令已生效，请重新下载客户端配置。" : "VPN目标已生效。";
    document.querySelector("#vpn-ack-change").checked = false;
    document.dispatchEvent(new CustomEvent("configuration-changed", { detail: { kind: "vpn", before, after: before + 1 } }));
  } catch (error) { message.textContent = error.message; }
  finally { await refreshVPN(); }
}

document.querySelector("#vpn-enable").addEventListener("click", () => applyVPN(true, false));
document.querySelector("#vpn-disable").addEventListener("click", () => applyVPN(false, false));
document.querySelector("#vpn-rotate").addEventListener("click", () => applyVPN(enabled, true));
document.querySelector("#vpn-refresh").addEventListener("click", refreshVPN);
document.querySelector("#vpn-export").addEventListener("click", async () => {
  if (!document.querySelector("#vpn-ack-secret").checked) {
    message.textContent = "下载文件含VPN口令，请先确认会妥善保管。"; return;
  }
  try {
    const profile = await request("/api/vpn/export");
    const url = URL.createObjectURL(new Blob([JSON.stringify(profile, null, 2) + "\n"], { type: "application/yaml" }));
    const link = document.createElement("a"); link.href = url; link.download = "trojan-clash.yaml"; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    document.querySelector("#vpn-ack-secret").checked = false;
    message.textContent = "配置已下载，可导入Clash Verge或Clash Mi；不要发送给他人。";
  } catch (error) { message.textContent = error.message; }
});

document.addEventListener("configuration-changed", (event) => {
  if (event.detail.kind === "routes") refreshVPN();
});
