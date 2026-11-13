// 会话只存在模块内存；不写Cookie、URL或任何浏览器持久化存储。
let token = "";

const timeoutMessage = "请求超过15秒，请先刷新核对结果，不要直接重复提交。迁移候选可能已过期，请返回旧入口检查。";
const invalidResponseMessage = "入口返回的不是管理接口内容；迁移候选可能已过期，请返回旧入口刷新。";

export async function request(path, body = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  // 时限覆盖响应体读取；只中止等待，不能断言服务端写入未发生，也不自动重试。
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 15000);
  let response, result;
  try {
    try {
      response = await fetch(new URL(`.${path}`, import.meta.url), {
        method: "POST", headers, body: JSON.stringify(body),
        credentials: "omit", cache: "no-store", redirect: "error",
        signal: controller.signal,
      });
    } catch (error) {
      throw new Error(error.name === "AbortError" ? timeoutMessage : "未能连接管理入口，请检查网络；迁移候选可能已过期，请返回旧入口刷新。");
    }
    try { result = await response.json(); }
    catch (error) { throw new Error(error.name === "AbortError" ? timeoutMessage : invalidResponseMessage); }
  } finally {
    clearTimeout(deadline);
  }
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error(invalidResponseMessage);
  if (response.status === 401 && token) { token = ""; document.dispatchEvent(new Event("authentication-expired")); }
  if (!response.ok) throw new Error(typeof result.error === "string" ? result.error : "请求失败，请刷新状态核对结果");
  return result;
}

export async function login(password, method, verification) {
  const result = await request("/api/login", {
    password, otp: method === "otp" ? verification : "",
    recovery: method === "recovery" ? verification : "",
  });
  if (typeof result.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(result.token)) throw new Error(invalidResponseMessage);
  token = result.token;
}

export async function logout() {
  try { if (token) await request("/api/logout"); }
  finally { token = ""; }
}
