import { login, logout, request } from "./auth.js";
import { refreshRoutes } from "./routes.js";
import { refreshVPN } from "./vpn.js";
import { startTraffic, stopTraffic } from "./traffic.js";
import { refreshSettings, clearSettings } from "./settings.js";
import { showWorkspace, hideWorkspace } from "./navigation.js";

const form = document.querySelector("#login-form");
const message = document.querySelector("#message");
const submit = document.querySelector("#submit");

function showLogin() {
  stopTraffic(); clearSettings();
  hideWorkspace();
  document.querySelector("#login-panel").hidden = false;
  document.querySelector("#dashboard").hidden = true;
  document.querySelector("#password").focus();
  for (const id of ["ack-public", "vpn-ack-change", "vpn-ack-secret", "traffic-ack-clear"]) document.querySelector(`#${id}`).checked = false;
}

document.addEventListener("authentication-expired", () => { showLogin(); message.textContent = "会话已过期，请重新登录。"; });

form.addEventListener("submit", async (event) => {
  event.preventDefault(); submit.disabled = true; message.textContent = "正在验证…";
  try {
    await login(document.querySelector("#password").value,
      document.querySelector("#method").value,
      document.querySelector("#verification").value.trim());
    form.reset();
    for (const id of ["ack-public", "vpn-ack-change", "vpn-ack-secret", "traffic-ack-clear"]) document.querySelector(`#${id}`).checked = false;
    const status = await request("/api/status");
    document.querySelector("#status").textContent = status.scope;
    document.querySelector("#login-panel").hidden = true;
    document.querySelector("#dashboard").hidden = false;
    showWorkspace();
    await refreshSettings();
	await refreshRoutes();
	await refreshVPN();
    await startTraffic();
    message.textContent = "";
  } catch (error) { message.textContent = error.message; }
  finally { submit.disabled = false; }
});

document.querySelector("#logout").addEventListener("click", async () => {
  stopTraffic();
  try { await logout(); }
  catch { message.textContent = "本地会话已清除，服务器会话将按期限失效。"; }
  finally { showLogin(); }
});
