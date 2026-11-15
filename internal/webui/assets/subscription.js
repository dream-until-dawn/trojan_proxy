import { request } from "./auth.js";

const message = document.querySelector("#subscription-message");
const secretPanel = document.querySelector("#subscription-secret");
const secretField = document.querySelector("#subscription-url");
let currentURL = "";
let generation = 0;

// 令牌只存在当前页面内存，不进入地址栏、持久化存储或普通列表。
function clearSecret() {
  currentURL = ""; secretField.value = ""; secretField.type = "password";
  secretPanel.hidden = true;
  document.querySelector("#subscription-reveal").textContent = "显示链接";
}

export function clearSubscriptions() {
  generation++; clearSecret();
  document.querySelector("#subscription-rows").replaceChildren();
  document.querySelector("#subscription-name").value = "";
  document.querySelector("#subscription-ack").checked = false;
  message.textContent = "";
}

export async function refreshSubscriptions() {
  const before = generation;
  try {
    const result = await request("/api/subscriptions/list");
    if (before !== generation) return;
    const rows = document.querySelector("#subscription-rows"); rows.replaceChildren();
    for (const item of result.items) {
      const row = document.createElement("tr");
      for (const value of [item.name, new Date(item.expires_at).toLocaleString()]) {
        const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
      }
      const cell = document.createElement("td"); const revoke = document.createElement("button");
      revoke.type = "button"; revoke.className = "secondary"; revoke.textContent = "撤销";
      revoke.addEventListener("click", async () => {
        const actionGeneration = generation; revoke.disabled = true;
        try {
          await request("/api/subscriptions/revoke", { id: item.id });
          if (actionGeneration !== generation) return;
          clearSecret(); await refreshSubscriptions();
          message.textContent = "订阅已撤销；已下载的节点配置仍需通过轮换VPN口令失效。";
        } catch (error) { if (actionGeneration === generation) message.textContent = error.message; }
        finally { revoke.disabled = false; }
      });
      cell.append(revoke); row.append(cell); rows.append(row);
    }
    message.textContent = result.items.length ? `有效订阅 ${result.items.length} / 16` : "尚无订阅，可先为电脑或手机创建链接。";
  } catch (error) { if (before === generation) message.textContent = error.message; }
}

document.querySelector("#subscription-create").addEventListener("click", async () => {
  if (!document.querySelector("#subscription-ack").checked) { message.textContent = "请先确认会妥善保管订阅链接。"; return; }
  const before = generation; const button = document.querySelector("#subscription-create"); button.disabled = true; clearSecret();
  try {
    const result = await request("/api/subscriptions/create", { name: document.querySelector("#subscription-name").value.trim() });
    if (before !== generation) return;
    currentURL = result.url; secretField.value = currentURL; secretPanel.hidden = false;
    document.querySelector("#subscription-ack").checked = false;
    await refreshSubscriptions();
    if (before === generation) message.textContent = "链接已创建，请复制到客户端；普通刷新不会再次返回此链接。";
  } catch (error) { if (before === generation) message.textContent = error.message; }
  finally { button.disabled = false; }
});

document.querySelector("#subscription-copy").addEventListener("click", async () => {
  if (!currentURL) return;
  try { await navigator.clipboard.writeText(currentURL); message.textContent = "已复制，请粘贴到客户端的远程订阅。"; }
  catch { message.textContent = "浏览器未允许复制，请显示链接后手动复制。"; }
});
document.querySelector("#subscription-reveal").addEventListener("click", () => {
  secretField.type = secretField.type === "password" ? "text" : "password";
  document.querySelector("#subscription-reveal").textContent = secretField.type === "password" ? "显示链接" : "隐藏链接";
});
document.querySelector("#subscription-clear").addEventListener("click", clearSecret);
document.querySelector("#subscription-refresh").addEventListener("click", refreshSubscriptions);
window.addEventListener("hashchange", () => { if (location.hash !== "#vpn") { generation++; clearSecret(); } });
