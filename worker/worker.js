/**
 * law-search 점검대상(scope.json) 웹 에디터 백엔드 — Cloudflare Worker
 * ---------------------------------------------------------------------------
 * 정적 GitHub Pages 사이트(index.html)는 서버 쓰기가 없으므로, 직원 편집을
 * "저장"하려면 어딘가 쓰기 가능한 곳이 필요하다. 이 Worker가 그 역할을 한다:
 *   브라우저 → (비밀번호 + 새 scope) POST → 비번 검증 → GitHub Contents API로
 *   루트 scope.json 커밋 → GitHub Pages 재빌드 → 모든 방문자에게 반영.
 *
 * 핵심 보안: 비밀번호와 GitHub 토큰은 **이 Worker(서버)에만** 보관된다.
 *   브라우저로는 토큰이 절대 내려가지 않는다(노출 0). 비번은 매 요청마다
 *   서버에서 검증한다.
 *
 * 비밀(Secrets) — `wrangler secret put` 으로 등록(코드/저장소에 넣지 말 것):
 *   EDIT_PASSWORD  편집 비밀번호
 *   GITHUB_TOKEN   fine-grained PAT — 이 저장소(law-search) 1개,
 *                  권한: Contents = Read and write 만.
 *
 * 변수(Vars) — wrangler.toml [vars]:
 *   GH_OWNER, GH_REPO, GH_BRANCH, GH_PATH, ALLOW_ORIGIN
 *
 * 요청 형식(POST JSON):
 *   { "action": "verify", "password": "...", "remember": true }
 *                                                            → { ok: true, token, exp }
 *   { "action": "verify", "token": "..." }                    → { ok: true }
 *   { "action": "save",   "password"|"token": "...", "scope": {...},
 *     "message": "선택: 커밋 메시지" }                          → { ok: true, commit: "<sha>" }
 *   scope 형식: { "법령ID": { "제5조": "c", ... }, ... }  (값은 항상 "c")
 *
 * 자동 로그인 토큰 — 매번 비번을 넣는 불편을 줄이되 비번 자체는 브라우저에 남기지 않는다.
 *   형식: "v1.<만료시각ms>.<HMAC-SHA256(EDIT_PASSWORD, 'v1.<만료시각ms>')>"
 *   · 서버에 아무것도 저장하지 않는다(DB 없음 유지) — 서명만으로 위조를 막는다.
 *   · 토큰에서 비밀번호를 역산할 수 없다.
 *   · 재발급은 '비밀번호로 인증했을 때'만 한다. 토큰으로 토큰을 갱신하면 유출된 토큰이
 *     무한 연장되므로 금지 — 7일이 지나면 반드시 비번을 다시 넣어야 한다.
 *   · EDIT_PASSWORD를 바꾸면 발급된 토큰이 전부 즉시 무효가 된다(사고 시 회수 경로).
 */

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, cors);

    if (!env.EDIT_PASSWORD || !env.GITHUB_TOKEN) {
      return json({ error: 'server_misconfigured' }, 500, cors);
    }

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'bad_json' }, 400, cors); }

    const { action, password, token } = body || {};
    const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
    const ua = (request.headers.get('User-Agent') || '').slice(0, 120);

    // 인증: 비밀번호(상수시간 비교) 또는 유효한 자동 로그인 토큰.
    // 모든 시도를 IP와 함께 로그에 남긴다(부정 접근 억제·추적).
    let via = null;
    if (typeof password === 'string' && (await safeEqual(password, env.EDIT_PASSWORD))) via = 'password';
    else if (await checkToken(env, token)) via = 'token';
    if (!via) {
      console.log('[scope-editor] DENY ' + JSON.stringify({ action, ip, ua, tried: typeof token === 'string' ? 'token' : 'password' }));
      return json({ error: 'unauthorized' }, 401, cors);
    }
    console.log('[scope-editor] AUTH-OK ' + JSON.stringify({ action, ip, via }));

    if (action === 'verify') {
      const out = { ok: true, via };
      // 토큰 발급은 비밀번호로 인증했을 때만 (토큰 무한 연장 차단)
      if (body.remember === true && via === 'password') {
        const exp = Date.now() + TOKEN_TTL_MS;
        out.token = await issueToken(env, exp);
        out.exp = exp;
      }
      return json(out, 200, cors);
    }

    if (action === 'save') {
      const err = validateScope(body.scope);
      if (err) return json({ error: 'invalid_scope', detail: err }, 400, cors);
      try {
        const res = await commitScope(env, body.scope, { editor: body.editor, note: body.note, count: body.count });
        console.log('[scope-editor] SAVE ' + JSON.stringify({ ip, editor: body.editor, count: body.count, commit: res.commit && res.commit.sha }));
        return json({ ok: true, commit: res.commit && res.commit.sha }, 200, cors);
      } catch (e) {
        return json({ error: 'commit_failed', detail: String((e && e.message) || e) }, 502, cors);
      }
    }

    return json({ error: 'unknown_action' }, 400, cors);
  },
};

// ── CORS ───────────────────────────────────────────────────────────
// 허용 오리진: ALLOW_ORIGIN(쉼표로 여러 개 가능) + 로컬 개발(localhost/127.0.0.1, 포트 무관).
// 비번이 실제 보안 경계이므로 localhost 허용은 안전(로컬 페이지도 비번 없이는 저장 불가).
function pickOrigin(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = String(env.ALLOW_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (allowed.includes('*')) return '*';
  if (origin && allowed.includes(origin)) return origin;
  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return origin;   // 로컬 개발
  return allowed[0] || '';   // 그 외엔 기본(운영) 오리진 — 매칭 실패 시 브라우저가 차단
}
function corsHeaders(request, env) {
  return {
    'Access-Control-Allow-Origin': pickOrigin(request, env),
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, extra || {}),
  });
}

// ── 자동 로그인 토큰 ───────────────────────────────────────────────
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // 7일

async function hmacB64url(key, msg) {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey('raw', enc.encode(String(key)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(String(msg))));
  let bin = '';
  for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// "v1.<exp>.<sig>" — 서버 저장 없음. 서명 키는 EDIT_PASSWORD 자체라 비번 변경 = 전량 무효화.
async function issueToken(env, exp) {
  const head = 'v1.' + exp;
  return head + '.' + (await hmacB64url(env.EDIT_PASSWORD, head));
}

async function checkToken(env, token) {
  if (typeof token !== 'string') return false;
  const m = token.match(/^(v1\.(\d{13,16}))\.([A-Za-z0-9_-]{20,64})$/);
  if (!m) return false;
  const exp = Number(m[2]);
  if (!Number.isFinite(exp) || exp <= Date.now()) return false;      // 만료
  if (exp > Date.now() + TOKEN_TTL_MS + 60000) return false;         // 미래로 조작된 만료시각 차단
  return await safeEqual(m[3], await hmacB64url(env.EDIT_PASSWORD, m[1]));
}

// SHA-256 해시 비교(타이밍 누수 최소화)
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b))),
  ]);
  const va = new Uint8Array(ha), vb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < va.length; i++) diff |= va[i] ^ vb[i];
  return diff === 0;
}

// 들어온 scope 객체 형식 검증(악의·실수 페이로드 차단)
function validateScope(scope) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) return 'scope must be an object';
  const ids = Object.keys(scope);
  if (ids.length > 300) return 'too many laws';
  let total = 0;
  for (const id of ids) {
    if (!/^[A-Za-z0-9_]+$/.test(id)) return 'bad law id: ' + id;
    const m = scope[id];
    if (!m || typeof m !== 'object' || Array.isArray(m)) return 'bad entry for: ' + id;
    for (const art of Object.keys(m)) {
      if (!/^제\d+조(?:의\d+)?$/.test(art)) return 'bad article key: ' + id + ' / ' + art;
      if (m[art] !== 'c') return 'bad value (must be "c"): ' + id + ' / ' + art;
      total++;
    }
  }
  if (total > 10000) return 'too many articles';
  return null;
}

// UTF-8 문자열 → base64 (GitHub Contents API용)
function toBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

// 커밋 메시지: "점검대상 편집: <작성자> — 변경 N건" + (메모는 본문에). 모두 자기기입(검증 신원 아님).
function buildMessage(meta) {
  const who = (meta && meta.editor && String(meta.editor).trim().slice(0, 60)) || '익명';
  const count = (meta && Number(meta.count)) || 0;
  let msg = `점검대상 편집: ${who} — 변경 ${count}건`;
  const note = meta && meta.note && String(meta.note).trim().slice(0, 200);
  if (note) msg += `\n\n${note}`;
  return msg;
}

async function commitScope(env, scope, meta) {
  const owner = env.GH_OWNER, repo = env.GH_REPO;
  const branch = env.GH_BRANCH || 'main';
  const path = env.GH_PATH || 'scope.json';
  const api = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const ghHeaders = {
    'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'law-search-scope-editor',
    'X-GitHub-Api-Version': '2022-11-28',
  };

  // 1) 현재 파일 SHA 조회(있으면 갱신, 없으면 새로 생성)
  let sha;
  const cur = await fetch(`${api}?ref=${encodeURIComponent(branch)}`, { headers: ghHeaders });
  if (cur.status === 200) {
    const j = await cur.json();
    sha = j.sha;
  } else if (cur.status !== 404) {
    throw new Error('read ' + cur.status + ': ' + (await cur.text()).slice(0, 300));
  }

  // 2) build-public-scope.mjs 와 동일 포맷(한 줄 JSON + 개행)으로 커밋
  const content = toBase64(JSON.stringify(scope) + '\n');
  const putBody = { message: buildMessage(meta), content, sha, branch };   // sha undefined면 새 파일 생성
  // 작성자 이름이 있으면 git author로 기록(committer는 토큰 기본값 유지)
  const who = meta && meta.editor && String(meta.editor).trim().slice(0, 60);
  if (who) putBody.author = { name: who, email: env.COMMIT_EMAIL || 'scope-editor@cela.kr' };
  const put = await fetch(api, {
    method: 'PUT',
    headers: Object.assign({ 'Content-Type': 'application/json' }, ghHeaders),
    body: JSON.stringify(putBody),
  });
  if (put.status !== 200 && put.status !== 201) {
    throw new Error('write ' + put.status + ': ' + (await put.text()).slice(0, 300));
  }
  return await put.json();
}

// 단위 테스트용 내보내기(Cloudflare는 default export만 사용 — 무해)
export { validateScope, toBase64, safeEqual, pickOrigin, issueToken, checkToken, hmacB64url, TOKEN_TTL_MS };

