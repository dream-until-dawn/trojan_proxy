import { login, logout, request } from "./auth.js";

const form = document.querySelector("#login-form");
const message = document.querySelector("#message");
const submit = document.querySelector("#submit");

function showLogin() {
  document.querySelector("#login-panel").hidden = false;
  document.querySelector("#dashboard").hidden = true;
  document.querySelector("#password").focus();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault(); submit.disabled = true; message.textContent = "正在验证…";
  try {
    await login(document.querySelector("#password").value,
      document.querySelector("#method").value,
      document.querySelector("#verification").value.trim());
    form.reset();
    const status = await request("/api/status");
    document.querySelector("#status").textContent = status.scope;
    document.querySelector("#login-panel").hidden = true;
    document.querySelector("#dashboard").hidden = false;
    message.textContent = "";
  } catch (error) { message.textContent = error.message; }
  finally { submit.disabled = false; }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try { await logout(); }
  catch { message.textContent = "本地会话已清除，服务器会话将按期限失效。"; }
  finally { showLogin(); }
});
