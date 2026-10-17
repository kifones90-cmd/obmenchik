// Cloudflare Worker: уведомления администраторам о новых заявках.
// Переменные: BOT_TOKEN (секрет), ADMIN_IDS (например "8273950789,"), APP_URL (необязательно, ссылка на мини-апп).
const enc = new TextEncoder();

async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', k, data);
}

async function verify(initData, token) {
  const p = new URLSearchParams(initData);
  const hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const check = [...p.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('\n');
  const secret = await hmac(enc.encode('WebAppData'), enc.encode(token));
  const sig = await hmac(secret, enc.encode(check));
  const hex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  if (hex !== hash) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date') || 0) > 86400) return null;
  try { return JSON.parse(p.get('user') || 'null'); } catch (e) { return null; }
}

const cut = (v, n = 200) => String(v ?? '—').slice(0, n);

export default {
  async fetch(req, env) {
    const cors = {
      'Access-Control-Allow-Origin': env.ORIGIN || '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (req.method !== 'POST') return new Response('ok', { headers: cors });

    let body;
    try { body = await req.json(); } catch (e) { return new Response('bad request', { status: 400, headers: cors }); }

    const user = await verify(body.initData || '', env.BOT_TOKEN);
    if (!user) return new Response('unauthorized', { status: 401, headers: cors });

    const o = body.order || {};
    const buy = o.type === 'buy';
    const text = [
      buy ? 'Новая заявка на покупку' : 'Новая заявка на обмен',
      `№${cut(o.id, 20)}`,
      buy ? `Сумма: ${cut(o.amt, 30)} ₽` : `Отдаёт: ${cut(o.amt, 30)} ${cut(o.from, 10)}`,
      `Получит: ${cut(o.out, 30)} ${cut(o.to, 10)}`,
      buy ? `Реквизит: ${cut(o.pay)}` : `Кошелёк клиента: ${cut(o.addr)}`,
      `Клиент: ${cut(user.first_name || '', 60)} ${user.username ? '@' + cut(user.username, 40) : ''} (id ${user.id})`,
    ].join('\n');

    const markup = env.APP_URL
      ? { inline_keyboard: [[{ text: 'Открыть админ-панель', web_app: { url: env.APP_URL } }]] }
      : undefined;

    const ids = String(env.ADMIN_IDS || '').split(',').map(x => x.trim()).filter(Boolean);
    await Promise.all(ids.map(chat_id =>
      fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id, text, reply_markup: markup }),
      }).catch(() => null)
    ));

    return new Response('ok', { headers: cors });
  },
};
