// Cổng lỗ hổng phụ thuộc: production phải sạch (mức >= high); dev chỉ được miễn đúng các GHSA trong
// audit-allowlist.json còn hạn. Chạy: node scripts/audit.mjs  (cần npm 11 qua npx).
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const npm = (args) => {
  try {
    return execFileSync('npx', ['-y', 'npm@11.21.2', ...args], { encoding: 'utf8', maxBuffer: 64 << 20 });
  } catch (e) {
    return e.stdout; // npm audit trả mã khác 0 khi có lỗ hổng
  }
};
const HIGH = new Set(['high', 'critical']);
const advisories = (json) =>
  Object.values(JSON.parse(json).vulnerabilities ?? {})
    .flatMap((v) => v.via.filter((x) => typeof x === 'object'))
    .filter((x) => HIGH.has(x.severity));
const ghsa = (a) => a.url.split('/').pop();

const prod = advisories(npm(['audit', '--omit=dev', '--json']));
if (prod.length) {
  console.error('LỖI: phụ thuộc production có lỗ hổng:', [...new Set(prod.map(ghsa))].join(', '));
  process.exit(1);
}
const { accepted } = JSON.parse(readFileSync(new URL('../audit-allowlist.json', import.meta.url), 'utf8'));
const today = new Date().toISOString().slice(0, 10);
const bad = new Set();
for (const a of advisories(npm(['audit', '--json']))) {
  const id = ghsa(a);
  const ok = accepted[id];
  if (!ok || ok.until < today) bad.add(`${id} (${a.name})${ok ? ' - ngoại lệ đã hết hạn ' + ok.until : ''}`);
}
if (bad.size) {
  console.error('LỖI: lỗ hổng dev chưa được chấp nhận:\n  ' + [...bad].join('\n  '));
  process.exit(1);
}
console.log('Đạt: production sạch; dev chỉ còn ngoại lệ có hạn trong audit-allowlist.json.');
