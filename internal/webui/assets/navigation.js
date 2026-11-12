// hash仅包含菜单名，不存储凭据。独立功能页共用内存会话与未提交草稿。
const pages = {
  overview: ["总览", "服务与入口，一目了然"], routes: ["反向代理", "管理公开服务与只读目录"],
  vpn: ["Trojan VPN", "连接状态与客户端配置"], traffic: ["流量记录", "实际目的IP与最近30天流量"],
  certificates: ["证书管理", "自动签发、有效期与证书导入"], settings: ["系统设置", "网站、管理入口与网络范围"],
};
let active = false;
function render(focus = false) {
  const name = location.hash.slice(1);
  const page = Object.hasOwn(pages, name) ? name : "overview";
  if (name !== page) history.replaceState(null, "", `#${page}`);
  for (const section of document.querySelectorAll("[data-page]")) section.hidden = !active || section.dataset.page !== page;
  for (const link of document.querySelectorAll("[data-nav]")) {
    if (link.dataset.nav === page) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  document.querySelector("#page-title").textContent = pages[page][0];
  document.querySelector("#page-description").textContent = pages[page][1];
  document.title = `${pages[page][0]} · 独用代理管理`;
  if (active && focus) { document.querySelector("#page-title").focus(); window.scrollTo(0, 0); }
}
// 只复制聚合状态文字，目的IP表格不会进入总览；不增加后台轮询请求。
function overview() {
  for (const [source, target, fallback] of [
    ["site-current", "overview-entry", "入口尚未配置"], ["vpn-status", "overview-vpn", "正在读取…"],
    ["traffic-speed", "overview-speed", "暂无有效采样"], ["certificate-status", "overview-certificate", "正在读取…"],
  ]) document.getElementById(target).textContent = active ? document.getElementById(source).textContent.replace(/^当前入口：/, "") || fallback : "";
  document.querySelector("#certificates-content").hidden = document.querySelector("#settings-panel").hidden;
}
// 登录后恢复合法菜单深链接，菜单切换不重复加载或覆盖草稿。
export function showWorkspace() { active = true; render(); overview(); }
// 退出和认证失效均关闭所有功能页，并清空总览投影。
export function hideWorkspace() { active = false; render(); overview(); }
window.addEventListener("hashchange", () => render(true));
const observer = new MutationObserver(overview);
for (const id of ["site-current", "vpn-status", "traffic-speed", "certificate-status"]) observer.observe(document.getElementById(id), { childList: true, subtree: true, characterData: true });
observer.observe(document.querySelector("#settings-panel"), { attributes: true, attributeFilter: ["hidden"] });
render();
