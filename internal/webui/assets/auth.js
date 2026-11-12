// 会话只存在模块内存；不写Cookie、URL或任何浏览器持久化存储。
let token = "";

export async function request(path, body = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(new URL(`.${path}`, import.meta.url), {
    method: "POST", headers, body: JSON.stringify(body),
    credentials: "omit", cache: "no-store", redirect: "error",
  });
  const result = await response.json();
  if (response.status === 401 && token) { token = ""; document.dispatchEvent(new Event("authentication-expired")); }
  if (!response.ok) throw new Error(result.error || "请求失败，请稍后重试");
  return result;
}

export async function login(password, method, verification) {
  const result = await request("/api/login", {
    password, otp: method === "otp" ? verification : "",
    recovery: method === "recovery" ? verification : "",
  });
  token = result.token;
}

export async function logout() {
  try { if (token) await request("/api/logout"); }
  finally { token = ""; }
}
