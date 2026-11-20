import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';

import { accountView, loadAccount } from './account';
import { maintenanceSample } from './config';
import { requireCaller } from './auth';
import type { AppEnv } from './env';
import { ApiError, errorResponse } from './errors';
import { fileRoutes } from './files';
import { runMaintenance } from './maintenance';
import { recordRoutes } from './records';

/**
 * TsuDEV Sync (ADR-0001): đồng bộ bản mã dùng chung cho sản phẩm không có máy chủ riêng. Chỉ API JSON + tệp nhị phân
 * cho app gốc; không có trang, không cookie, không CORS (web app sản phẩm cần ⇒ ADR mới).
 */
export const app = new Hono<AppEnv>();

const logError = (e: unknown) => {
  console.error('maintenance', e instanceof Error ? e.name : 'error');
};

app.use('*', async (c, next) => {
  await next();
  if (c.req.path.startsWith('/v1/') && Math.random() < maintenanceSample(c.env)) {
    c.executionCtx.waitUntil(runMaintenance(c.env).catch(logError));
  }
  const h = c.res.headers;
  if (!h.has('Cache-Control')) h.set('Cache-Control', 'no-store');
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('Referrer-Policy', 'no-referrer');
  h.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  h.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  h.set('Cross-Origin-Resource-Policy', 'same-origin');
});

app.get('/v1/health', (c) => c.json({ ok: true, service: 'tsusync', version: '0.2.0' }));

app.get('/v1/account', requireCaller, async (c) => {
  const caller = c.get('caller');
  const a = await loadAccount(c.env, caller, { create: false, allowPurging: true });
  return c.json(accountView(c.env, caller, a));
});

/** Xoá toàn bộ dữ liệu đám mây của tài khoản trong không gian tên này - không cần Pro (quyền của người dùng). */
app.delete('/v1/account', requireCaller, async (c) => {
  const caller = c.get('caller');
  const a = await loadAccount(c.env, caller, { create: false, allowPurging: true });
  if (!a) return c.json({ status: 'deleted' });
  await c.env.DB.prepare('UPDATE accounts SET purge_requested = 1 WHERE ns = ? AND sub_key = ?').bind(caller.ns, caller.subKey).run();
  c.executionCtx.waitUntil(runMaintenance(c.env).catch(logError));
  return c.json({ status: 'purge_requested' }, 202);
});

app.route('/', recordRoutes);
app.route('/', fileRoutes);

app.notFound((c) => c.json({ error: 'not_found', message: 'Không có đường dẫn này.' }, 404));

app.onError((err, c) => {
  if (err instanceof ApiError) return errorResponse(c, err);
  if (err instanceof HTTPException) return c.json({ error: 'http_error', message: 'Yêu cầu không hợp lệ.' }, err.status);
  console.error('unhandled', err.name);
  return c.json({ error: 'internal', message: 'Máy chủ đồng bộ gặp lỗi. Dữ liệu vẫn an toàn trên máy, hãy thử lại sau.' }, 500);
});

export default app;
