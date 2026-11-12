import { request } from "./auth.js";

let revision = 0;
let rules = [];
const message = document.querySelector("#route-message");
const form = document.querySelector("#route-form");
const kind = document.querySelector("#route-kind");

function render() {
  const rows = document.querySelector("#route-rows");
  rows.replaceChildren();
  document.querySelector("#revision").textContent = `已加载修订 ${revision}，当前草稿 ${rules.length} 条`;
  for (const rule of rules) {
    const row = document.createElement("tr");
    const target = rule.kind === "files" ? `目录 ${rule.directory_id}` : `${rule.upstream_ip}:${rule.upstream_port}`;
    for (const value of [rule.name, `${rule.https || rule.port === 443 ? "HTTPS" : "HTTP"} ${rule.port} · ${rule.host || "所有Host"}${rule.path}`, target]) {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    }
    const cell = document.createElement("td");
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "移出草稿";
    remove.addEventListener("click", () => { rules = rules.filter(item => item.id !== rule.id); render(); });
    cell.append(remove); row.append(cell); rows.append(row);
  }
}

function toggleKind() {
  const files = kind.value === "files";
  document.querySelector("#proxy-fields").hidden = files;
  document.querySelector("#files-fields").hidden = !files;
  for (const input of document.querySelectorAll("#proxy-fields input")) input.disabled = files;
  document.querySelector("#directory-id").disabled = !files;
}
kind.addEventListener("change", toggleKind);

export async function refreshRoutes() {
  try {
    const snapshot = await request("/api/routes/list");
    revision = snapshot.revision; rules = snapshot.rules || [];
    document.querySelector("#route-port").min = snapshot.standard_ingress ? "1" : "1024";
    document.querySelector("#route-scope-hint").textContent = snapshot.standard_ingress
      ? "80为网站入口；证书就绪后自动升级到443。自定义端口可选择HTTP或HTTPS；HTTPS需要当前域名及就绪证书。业务发布无需后台登录。"
      : "自定义端口可选择HTTP或HTTPS；HTTPS需要部署域名及有效证书。80/443仍由旧服务持有。业务发布无需后台登录。";
    document.querySelector("#apply-routes").disabled = Boolean(snapshot.pending);
    const directories = document.querySelector("#directory-id"); directories.replaceChildren();
    for (const id of snapshot.directories || []) {
      const option = document.createElement("option"); option.value = id; option.textContent = id; directories.append(option);
    }
    document.querySelector("#files-option").disabled = !directories.options.length;
	if (!directories.options.length && kind.value === "files") kind.value = "proxy";
    document.querySelector("#ack-public").checked = false;
    message.textContent = "已加载实际提交规则。"; render(); toggleKind();
  } catch (error) { message.textContent = error.message; }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const rule = {
    id: crypto.randomUUID(), name: document.querySelector("#route-name").value.trim(),
    port: Number(document.querySelector("#route-port").value), host: document.querySelector("#route-host").value.trim(),
    path: document.querySelector("#route-path").value.trim(), kind: kind.value,
    https: document.querySelector("#route-protocol").value === "https",
    strip_prefix: kind.value === "proxy" && document.querySelector("#strip-prefix").checked,
    browse: kind.value === "files" && document.querySelector("#browse").checked,
  };
  if (rule.kind === "proxy") {
    rule.upstream_ip = document.querySelector("#upstream-ip").value.trim();
    rule.upstream_port = Number(document.querySelector("#upstream-port").value);
  } else { rule.directory_id = document.querySelector("#directory-id").value; }
  rules.push(rule); render(); message.textContent = "已加入草稿，尚未对外生效。";
  form.reset(); toggleKind();
});

document.querySelector("#refresh-routes").addEventListener("click", refreshRoutes);
document.querySelector("#apply-routes").addEventListener("click", async () => {
  if (!document.querySelector("#ack-public").checked) { message.textContent = "请先确认公开访问范围。"; return; }
  const button = document.querySelector("#apply-routes"); button.disabled = true;
  try {
    const before = revision;
    await request("/api/routes/apply", { revision, rules });
    document.dispatchEvent(new CustomEvent("configuration-changed", { detail: { kind: "routes", before, after: before + 1 } }));
    await refreshRoutes(); message.textContent = "配置已生效，已核对网关快照。";
  } catch (error) { message.textContent = error.message; }
  finally { button.disabled = false; }
});

// VPN只改变其自身配置；仅在基线修订一致时推进编号，保留当前反代草稿。
document.addEventListener("configuration-changed", (event) => {
  const change = event.detail;
  if (change.kind === "settings") { refreshRoutes(); return; }
  if (change.kind === "vpn" && revision === change.before) {
    revision = change.after; render();
    message.textContent = "VPN修订已更新，当前反代草稿已保留。";
  }
});
