// 初始化材料仅保存在本页面内存；不写浏览器持久存储或URL。
const $ = (id) => document.getElementById(id);
let session = '';
async function submit(path, body) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), credentials: 'omit', cache: 'no-store' });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || '请求失败');
  return result;
}
async function lock(form, operation) {
  const button = form.querySelector('button'); button.disabled = true;
  try { await operation(); } catch (error) { $('message').textContent = error.message; }
  finally { button.disabled = false; }
}
$('begin').addEventListener('submit', (event) => {
  event.preventDefault();
  lock(event.currentTarget, async () => {
    if ($('password').value !== $('repeat').value) throw new Error('两次口令不一致');
    const result = await submit('/api/setup/begin', { token: $('token').value, password: $('password').value });
    session = result.session;
    $('secret').textContent = result.secret; $('uri').textContent = result.uri; $('codes').textContent = result.recovery.join('\n');
    $('begin').reset(); $('begin').hidden = true; $('materials').hidden = false;
    $('message').textContent = '请在令牌签发后10分钟内完成绑定。';
  });
});
$('finish').addEventListener('submit', (event) => {
  event.preventDefault();
  lock(event.currentTarget, async () => {
    const result = await submit('/api/setup/finish', { session, otp: $('otp').value, saved: $('saved').checked });
    session = ''; $('materials').hidden = true; $('secret').textContent = ''; $('uri').textContent = ''; $('codes').textContent = ''; $('finish').reset();
    $('message').textContent = '绑定完成，初始化入口将关闭。请通过正常后台入口登录；绑定验证码已消费，请等待下一组验证码。';
    const next = document.createElement('a'); next.href = result.login_url; next.textContent = '打开后台登录'; $('message').append(document.createElement('br'), next);
  });
});
