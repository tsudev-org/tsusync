/**
 * Máy khách HTTP của TsuDEV Sync (ADR-0001 mục 3, ADR-0002 mục 3.2). Lớp này CHỈ chuyển bản mã - mã hoá nằm ở
 * `crypto.ts`; `SyncSession` ghép hai lớp lại.
 *
 * - `402 pro_required` ⇒ `ProRequiredError` (app hiện màn Pro, KHÔNG thử lại).
 * - `401 reason=stale` ⇒ lấy JWS mới (`getJws(true)`) rồi thử lại ĐÚNG một lần.
 * - Có `dpop` ⇒ `Authorization: DPoP <jws>` + header `DPoP` (bằng chứng ký mới cho mỗi yêu cầu).
 */
import { b64u, decrypt, encrypt, fromB64u, type SyncKeys } from './crypto.ts';

/** Trả bằng chứng DPoP (RFC 9449) cho một yêu cầu - ký bằng khoá P-256 của cài đặt. */
export type DpopProof = (method: string, url: string, jws: string) => Promise<string>;

export interface ClientOptions {
  /** Lấy JWS quyền lợi từ tsudev.com; `forceRefresh` = true khi máy chủ báo JWS cũ (`stale`). */
  getJws: (forceRefresh: boolean) => Promise<string>;
  /** Địa chỉ Worker TsuDEV Sync - chưa có tên miền chính thức (chưa deploy, ADR-0001 mục 4) nên bắt buộc truyền. */
  baseUrl: string;
  /** Mã cài đặt 22 ký tự base64url (header `X-Tsu-Installation`). */
  installationId?: string;
  dpop?: DpopProof;
  fetch?: typeof fetch;
}

export class SyncHttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly reason: string | undefined;
  /** Giây, từ header `Retry-After` (503 `busy`, `entitlements_unavailable`). */
  readonly retryAfter: number | undefined;
  constructor(status: number, code: string, reason?: string, retryAfter?: number) {
    super(`TsuDEV Sync trả ${status} ${code}${reason ? ` (${reason})` : ''}`);
    this.name = 'SyncHttpError';
    this.status = status;
    this.code = code;
    this.reason = reason;
    this.retryAfter = retryAfter;
  }
}
/** Tài khoản không có Pro (`no_pro`) hoặc đã quá 90 ngày sau hết hạn (`grace_expired`). */
export class ProRequiredError extends SyncHttpError {
  constructor(reason?: string) {
    super(402, 'pro_required', reason);
    this.name = 'ProRequiredError';
  }
}

export interface PushItem {
  id: string;
  /** Có ⇒ chỉ ghi khi `rev` hiện tại khớp (0 = chưa tồn tại); không có ⇒ ghi sau thắng. */
  base_rev?: number;
  deleted?: boolean;
  /** Bản mã base64url (không có khi `deleted`). */
  payload?: string;
}
export type PushResult =
  | { id: string; status: 'applied' | 'unchanged' | 'conflict'; rev: number }
  | { id: string; status: 'rejected'; reason: 'invalid_payload' | 'duplicate' };
export interface PullItem {
  id: string;
  rev: number;
  deleted: boolean;
  payload?: string;
}
export interface Page<T> {
  items: T[];
  next: number;
  more: boolean;
}
export interface FileItem {
  id: string;
  rev: number;
  deleted: boolean;
  size?: number;
  digest?: string;
}
export interface WriteResult {
  id: string;
  status: 'applied' | 'unchanged';
  rev: number;
}

const ID = /^[A-Za-z0-9._~:-]{1,128}$/;
const INSTALLATION = /^[A-Za-z0-9_-]{22}$/;

function assertId(id: string): void {
  if (!ID.test(id)) throw new TypeError('Định danh phải 1-128 ký tự [A-Za-z0-9._~:-] và không chứa bản rõ.');
}

export class SyncClient {
  private readonly base: string;
  private readonly f: typeof fetch;
  private readonly opts: ClientOptions;

  constructor(opts: ClientOptions) {
    this.opts = opts;
    this.base = opts.baseUrl.replace(/\/+$/, '');
    this.f = opts.fetch ?? globalThis.fetch.bind(globalThis);
    if (opts.installationId !== undefined && !INSTALLATION.test(opts.installationId)) {
      throw new TypeError('Mã cài đặt phải đúng 22 ký tự base64url.');
    }
  }

  private async send(method: string, path: string, body?: BodyInit, headers: Record<string, string> = {}): Promise<Response> {
    const url = this.base + path;
    for (let attempt = 0; ; attempt++) {
      const jws = await this.opts.getJws(attempt > 0);
      const h: Record<string, string> = { ...headers };
      if (this.opts.installationId) h['X-Tsu-Installation'] = this.opts.installationId;
      if (this.opts.dpop) {
        // `htu` không có query (RFC 9449 mục 4.2).
        h['DPoP'] = await this.opts.dpop(method, url.split('?')[0] ?? url, jws);
        h['Authorization'] = `DPoP ${jws}`;
      } else {
        h['Authorization'] = `Bearer ${jws}`;
      }
      const init: RequestInit = { method, headers: h };
      if (body !== undefined) init.body = body;
      const res = await this.f(url, init);
      if (res.ok) return res;
      let j: { error?: unknown; reason?: unknown } = {};
      try {
        j = (await res.json()) as typeof j;
      } catch {
        /* thân không phải JSON */
      }
      const code = typeof j.error === 'string' ? j.error : 'http_error';
      const reason = typeof j.reason === 'string' ? j.reason : undefined;
      if (res.status === 401 && reason === 'stale' && attempt === 0) continue;
      if (res.status === 402) throw new ProRequiredError(reason);
      const ra = Number(res.headers.get('Retry-After'));
      throw new SyncHttpError(res.status, code, reason, Number.isFinite(ra) && ra > 0 ? ra : undefined);
    }
  }

  async pushRecords(items: PushItem[]): Promise<{ results: PushResult[]; rev: number }> {
    if (items.length === 0 || items.length > 100) throw new TypeError('Mỗi lô 1-100 mục.');
    for (const it of items) assertId(it.id);
    const res = await this.send('POST', '/v1/records', JSON.stringify({ items }), { 'Content-Type': 'application/json' });
    return (await res.json()) as { results: PushResult[]; rev: number };
  }

  async pullRecords(since = 0, limit = 500): Promise<Page<PullItem>> {
    const res = await this.send('GET', `/v1/records?since=${since}&limit=${limit}`);
    return (await res.json()) as Page<PullItem>;
  }

  async listFiles(since = 0, limit = 200): Promise<Page<FileItem>> {
    const res = await this.send('GET', `/v1/files?since=${since}&limit=${limit}`);
    return (await res.json()) as Page<FileItem>;
  }

  async putFile(id: string, ciphertext: Uint8Array): Promise<WriteResult> {
    assertId(id);
    if (ciphertext.length > 64 * 1024 * 1024) throw new TypeError('Tệp > 64 MiB: hãy chia khối ở tầng ứng dụng.');
    const digest = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', ciphertext as BufferSource)));
    const res = await this.send('PUT', `/v1/files/${id}`, ciphertext as BodyInit, {
      'Content-Type': 'application/octet-stream',
      'X-Tsu-Digest': digest,
    });
    return (await res.json()) as WriteResult;
  }

  async getFile(id: string): Promise<Uint8Array> {
    assertId(id);
    const res = await this.send('GET', `/v1/files/${id}`);
    return new Uint8Array(await res.arrayBuffer());
  }

  async deleteFile(id: string): Promise<WriteResult> {
    assertId(id);
    const res = await this.send('DELETE', `/v1/files/${id}`);
    return (await res.json()) as WriteResult;
  }

  async account(): Promise<Record<string, unknown>> {
    return (await (await this.send('GET', '/v1/account')).json()) as Record<string, unknown>;
  }
}

/** Ghép máy khách HTTP với khoá dữ liệu: đẩy/kéo bản rõ, mã hoá với ngữ cảnh `namespace` + loại + `id`. */
export class SyncSession {
  readonly client: SyncClient;
  private readonly keys: SyncKeys;
  /** `client_id` của sản phẩm tại tsudev.com = không gian tên trên TsuDEV Sync. */
  readonly namespace: string;

  constructor(client: SyncClient, keys: SyncKeys, namespace: string) {
    this.client = client;
    this.keys = keys;
    this.namespace = namespace;
  }

  sealRecord(id: string, plaintext: Uint8Array): string {
    const ct = encrypt(this.keys.dataKey, { namespace: this.namespace, kind: 'rec', id }, plaintext);
    if (ct.length > 64 * 1024) throw new TypeError('Bản ghi sau mã hoá vượt 64 KiB: hãy lưu dưới dạng tệp.');
    return b64u(ct);
  }

  openRecord(item: PullItem): Uint8Array | null {
    if (item.deleted || item.payload === undefined) return null;
    return decrypt(this.keys.dataKey, { namespace: this.namespace, kind: 'rec', id: item.id }, fromB64u(item.payload));
  }

  pushPlain(items: { id: string; data?: Uint8Array; deleted?: boolean; base_rev?: number }[]) {
    return this.client.pushRecords(
      items.map((it) => {
        const out: PushItem = { id: it.id };
        if (it.base_rev !== undefined) out.base_rev = it.base_rev;
        if (it.deleted) out.deleted = true;
        else if (it.data) out.payload = this.sealRecord(it.id, it.data);
        return out;
      }),
    );
  }

  async putPlainFile(id: string, data: Uint8Array): Promise<WriteResult> {
    return this.client.putFile(id, encrypt(this.keys.dataKey, { namespace: this.namespace, kind: 'file', id }, data));
  }

  async getPlainFile(id: string): Promise<Uint8Array> {
    return decrypt(this.keys.dataKey, { namespace: this.namespace, kind: 'file', id }, await this.client.getFile(id));
  }
}
