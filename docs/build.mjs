// docs/build.mjs — md(원본) → docs/index.html(정적 문서 사이트) 생성기.
// 실행: node docs/build.mjs   (의존성 없음, Node 16+)
// 원본은 README.md + docs/*.md. 이 스크립트가 사이드바·테마·라우팅 셸에 끼워 넣어
// 자기완결 단일 HTML(오프라인·더블클릭 열람)을 만든다. index.html은 직접 수정하지 말 것.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const DIR = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(join(DIR, p), 'utf8');

// ── 문서 매니페스트: 앱 사이드바 순서와 1:1 ──
const NAV = [
  { id:'home', idx:'',   group:'',           nav:'개요 (홈)',            icon:'book',   src:'../README.md',  crumb:'개요' },
  { id:'00',   idx:'00', group:'설계 · 운영', nav:'아키텍처 · 빌드 · 운영', icon:'layers', src:'00-아키텍처.md', crumb:'아키텍처 · 빌드 · 운영' },
  { id:'01',   idx:'01', group:'작업공간',    nav:'개요',                icon:'home',   src:'01-개요.md',    crumb:'개요 (Overview)' },
  { id:'02',   idx:'02', group:'작업공간',    nav:'프로젝트',             icon:'folder', src:'02-프로젝트.md', crumb:'프로젝트 (Projects)' },
  { id:'03',   idx:'03', group:'진단',        nav:'정찰',                icon:'radar',  src:'03-정찰.md',    crumb:'정찰 · 대상 파악 (Recon)' },
  { id:'04',   idx:'04', group:'진단',        nav:'스캔',                icon:'scan',   src:'04-스캔.md',    crumb:'스캔 · 자동화 진단 (Scan)' },
  { id:'05',   idx:'05', group:'결과',        nav:'취약점',               icon:'alert',  src:'05-취약점.md',   crumb:'취약점 목록 (Findings)' },
  { id:'06',   idx:'06', group:'결과',        nav:'커버리지',             icon:'checks', src:'06-커버리지.md', crumb:'점검 커버리지 (Coverage)' },
  { id:'07',   idx:'07', group:'결과',        nav:'리포트',               icon:'sheet',  src:'07-리포트.md',   crumb:'리포트 · 도출리스트 (Report)' },
  { id:'08',   idx:'08', group:'결과',        nav:'이행점검',             icon:'redo',   src:'08-이행점검.md', crumb:'이행점검 (Reverify)' },
  { id:'09',   idx:'09', group:'인텔리전스',   nav:'룰 제안',              icon:'bulb',   src:'09-룰제안.md',   crumb:'룰 제안 (Rule Advisor)' },
  { id:'10',   idx:'10', group:'인텔리전스',   nav:'감사',                icon:'scroll', src:'10-감사.md',    crumb:'감사 로그 (Audit)' },
  { id:'11',   idx:'11', group:'관리',        nav:'사용자',               icon:'users',  src:'11-사용자.md',   crumb:'사용자 관리 (Users)' },
];

// md 파일 basename → 섹션 id (내부 링크 변환용)
const LINK = {};
for (const n of NAV) {
  const base = n.src.split('/').pop().replace(/\.md$/i, '');
  LINK[base] = n.id;
}
LINK['README'] = 'home';

// ── 인라인 마크다운 ──
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function inline(raw) {
  const codes = [];
  let s = raw.replace(/`([^`]+)`/g, (_, c) => { codes.push(esc(c)); return String.fromCharCode(0) + (codes.length - 1) + String.fromCharCode(1); });
  s = esc(s);
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, txt, href) => {
    if (/^https?:/i.test(href)) return `<a href="${href}" target="_blank" rel="noopener">${txt}</a>`;
    const base = href.replace(/^.*\//, '').replace(/#.*$/, '').replace(/\.md$/i, '');
    const id = LINK[base];
    if (id) return `<a href="#sec-${id}" data-go="${id}">${txt}</a>`;
    if (href.startsWith('#')) return `<span>${txt}</span>`;
    return `<a href="${href}">${txt}</a>`;
  });
  s = s.replace(new RegExp(String.fromCharCode(0) + "([0-9]+)" + String.fromCharCode(1), "g"), (_, i) => "<code>" + codes[+i] + "</code>");
  return s;
}

// ── 블록 마크다운 → HTML ──
function mdBlocks(lines) {
  const out = [];
  let i = 0;
  const isTableSep = (l) => /^\s*\|?[\s:|-]+\|[\s:|-]*$/.test(l) && l.includes('-');
  while (i < lines.length) {
    let l = lines[i];
    if (!l.trim()) { i++; continue; }

    // fenced code
    const fence = l.match(/^```(\w*)/);
    if (fence) {
      const buf = []; i++;
      while (i < lines.length && !/^```/.test(lines[i])) { buf.push(lines[i]); i++; }
      i++; // closing fence
      out.push(`<pre><code>${esc(buf.join('\n'))}</code></pre>`);
      continue;
    }
    // heading
    const h = l.match(/^(#{2,6})\s+(.*)$/);
    if (h) {
      const lvl = Math.min(h[1].length, 4); // ##→h3, ###→h4, ####→h4
      const tag = lvl === 2 ? 'h3' : 'h4';
      out.push(`<${tag}>${inline(h[2].trim())}</${tag}>`);
      i++; continue;
    }
    // hr
    if (/^---+$/.test(l.trim())) { out.push('<hr>'); i++; continue; }
    // table
    if (/^\s*\|/.test(l) && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const cells = (row) => row.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      const head = cells(l);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) { rows.push(cells(lines[i])); i++; }
      out.push(
        '<div class="table-wrap"><table><thead><tr>' +
        head.map((c) => `<th>${inline(c)}</th>`).join('') +
        '</tr></thead><tbody>' +
        rows.map((r) => '<tr>' + r.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>').join('') +
        '</tbody></table></div>'
      );
      continue;
    }
    // blockquote → callout
    if (/^>\s?/.test(l)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^>\s?/, '')); i++; }
      const text = buf.join(' ');
      const kind = /⚠|주의|금지|경고|위험/.test(text) ? 'warn' : 'info';
      const ico = kind === 'warn'
        ? '<path d="M12 2 2 20h20L12 2z"/><path d="M12 9v5M12 17h.01"/>'
        : '<circle cx="12" cy="12" r="10"/><path d="M12 11v5M12 8h.01"/>';
      out.push(`<div class="callout ${kind}"><span class="ico">${svg(ico, 2)}</span><p>${inline(text)}</p></div>`);
      continue;
    }
    // unordered list
    if (/^\s*[-*]\s+/.test(l)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*[-*]\s+/, '')); i++; }
      out.push('<ul>' + items.map((t) => `<li>${inline(t)}</li>`).join('') + '</ul>');
      continue;
    }
    // ordered list
    if (/^\s*\d+\.\s+/.test(l)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*\d+\.\s+/, '')); i++; }
      out.push('<ol>' + items.map((t) => `<li>${inline(t)}</li>`).join('') + '</ol>');
      continue;
    }
    // paragraph
    const buf = [];
    while (i < lines.length && lines[i].trim() && !/^(#{2,6}\s|```|>\s?|\s*[-*]\s+|\s*\d+\.\s+|\s*\|)/.test(lines[i]) && !/^---+$/.test(lines[i].trim())) {
      buf.push(lines[i]); i++;
    }
    if (buf.length) out.push(`<p>${inline(buf.join(' '))}</p>`);
  }
  return out.join('\n');
}

// ── 문서 1개 → 섹션 HTML ──
function renderDoc(entry) {
  const lines = read(entry.src).split(/\r?\n/);
  // 1) 첫 H1 → 타이틀
  let title = entry.nav;
  const hi = lines.findIndex((l) => /^#\s+/.test(l));
  if (hi >= 0) {
    title = lines[hi].replace(/^#\s+/, '').replace(/^\d+\s*·\s*/, '').trim();
    lines.splice(hi, 1);
  }
  // 2) 타이틀 직후 첫 blockquote → 메타 칩 (사이드바 위치·소스·권한 요약)
  let metaHtml = '';
  let j = hi;
  while (j < lines.length && !lines[j].trim()) j++;
  if (j < lines.length && /^>\s?/.test(lines[j]) && /·/.test(lines[j])) {
    const buf = [];
    let k = j;
    while (k < lines.length && /^>\s?/.test(lines[k])) { buf.push(lines[k].replace(/^>\s?/, '')); k++; }
    const chips = buf.join(' ').split('·').map((s) => s.trim()).filter(Boolean);
    metaHtml = `<div class="meta-row">${chips.map((c) => `<span class="meta-chip">${inline(c)}</span>`).join('')}</div>`;
    lines.splice(j, k - j);
  }
  const eyebrow = entry.id === 'home'
    ? 'AVA · 문서'
    : `${entry.idx}${entry.group ? ' · ' + entry.group : ''}`;
  const body = mdBlocks(lines);
  return `<section class="doc${entry.id === 'home' ? ' active' : ''}" id="sec-${entry.id}">
    <div class="eyebrow">${esc(eyebrow)}</div>
    <h2 class="title">${inline(title)}</h2>
    ${metaHtml}
    ${body}
  </section>`;
}

// ── 아이콘 ──
const I = {
  home:'<path d="M3 9.5 12 3l9 6.5V20a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1z"/>',
  layers:'<path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 17 9 5 9-5"/>',
  folder:'<path d="M4 20h16a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-8l-2-3H4a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1z"/>',
  radar:'<path d="M12 12 4 6"/><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/>',
  scan:'<path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M7 12h10"/>',
  alert:'<path d="M12 2 2 20h20L12 2z"/><path d="M12 9v5M12 17h.01"/>',
  checks:'<path d="m3 7 3 3 5-5"/><path d="m3 17 3 3 5-5"/><path d="M13 6h8M13 18h8"/>',
  sheet:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M4 9h16M4 15h16M10 3v18"/>',
  redo:'<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
  bulb:'<path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.3 1 2.5h6c0-1.2.3-1.8 1-2.5A6 6 0 0 0 12 3z"/>',
  scroll:'<path d="M8 3h9a2 2 0 0 1 2 2v13a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3V6"/><path d="M4 6a2 2 0 0 1 4 0v3H4z"/><path d="M9 8h6M9 12h6M9 16h4"/>',
  users:'<circle cx="9" cy="8" r="3.2"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><path d="M16 5a3 3 0 0 1 0 6M21 20c0-2.5-1.3-4.6-3.3-5.6"/>',
  book:'<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 19a2 2 0 0 1 2-2h13"/>',
  sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5 4 4M19 19l1 1M5 19l-1 1M19 5l1-1"/>',
  moon:'<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
};
function svg(p, w) {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${w || 1.8}" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
}

// ── 사이드바 ──
function buildNav() {
  const groups = [];
  for (const n of NAV) {
    let g = groups.find((x) => x.name === n.group);
    if (!g) { g = { name: n.group, items: [] }; groups.push(g); }
    g.items.push(n);
  }
  return groups.map((g) => `
    <div class="nav-group">
      ${g.name ? `<span class="label">${esc(g.name)}</span>` : ''}
      ${g.items.map((n) => `<a class="nav-link${n.id === 'home' ? ' active' : ''}" href="#sec-${n.id}" data-go="${n.id}">
          <span class="idx">${n.idx || ''}</span>
          <span class="ico">${svg(I[n.icon])}</span>
          <span>${esc(n.nav)}</span>
        </a>`).join('')}
    </div>`).join('');
}

// ── CSS ──
const CSS = `
  :root {
    --bg:#f3f6f9; --panel:#fff; --panel-2:#eef2f7; --panel-3:#e6ecf3;
    --border:#d6dfe9; --border-strong:#c2cedb;
    --text:#14202c; --muted:#5c6b7a; --faint:#8496a6;
    --accent:#0b7a8c; --accent-fg:#fff; --accent-soft:#0b7a8c1a;
    --red:#d1345b; --amber:#c07800; --green:#1f9254; --blue:#2563b8;
    --shadow:0 1px 2px rgba(20,32,44,.06),0 8px 24px rgba(20,32,44,.06);
    --mono:"Cascadia Code","JetBrains Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI","Malgun Gothic","Apple SD Gothic Neo",Roboto,sans-serif;
  }
  @media (prefers-color-scheme:dark){:root{
    --bg:#0c1421; --panel:#121c2b; --panel-2:#1a2536; --panel-3:#223047;
    --border:#253347; --border-strong:#324563;
    --text:#e6eef7; --muted:#93a4b7; --faint:#6b7d92;
    --accent:#38cfe0; --accent-fg:#062028; --accent-soft:#38cfe01f;
    --red:#f4718e; --amber:#f0b429; --green:#4ade80; --blue:#6aa8ff;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 12px 32px rgba(0,0,0,.35);
  }}
  :root[data-theme="light"]{
    --bg:#f3f6f9;--panel:#fff;--panel-2:#eef2f7;--panel-3:#e6ecf3;--border:#d6dfe9;--border-strong:#c2cedb;
    --text:#14202c;--muted:#5c6b7a;--faint:#8496a6;--accent:#0b7a8c;--accent-fg:#fff;--accent-soft:#0b7a8c1a;
    --red:#d1345b;--amber:#c07800;--green:#1f9254;--blue:#2563b8;--shadow:0 1px 2px rgba(20,32,44,.06),0 8px 24px rgba(20,32,44,.06);
  }
  :root[data-theme="dark"]{
    --bg:#0c1421;--panel:#121c2b;--panel-2:#1a2536;--panel-3:#223047;--border:#253347;--border-strong:#324563;
    --text:#e6eef7;--muted:#93a4b7;--faint:#6b7d92;--accent:#38cfe0;--accent-fg:#062028;--accent-soft:#38cfe01f;
    --red:#f4718e;--amber:#f0b429;--green:#4ade80;--blue:#6aa8ff;--shadow:0 1px 2px rgba(0,0,0,.3),0 12px 32px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased;font-size:15px}
  a{color:var(--accent);text-decoration:none}
  a:hover{text-decoration:underline}
  .layout{display:grid;grid-template-columns:274px minmax(0,1fr);min-height:100vh}

  .sidebar{position:sticky;top:0;height:100vh;overflow-y:auto;background:var(--panel);border-right:1px solid var(--border);padding:0 0 40px}
  .brand{display:flex;align-items:center;gap:11px;padding:20px 20px 18px;position:sticky;top:0;background:var(--panel);border-bottom:1px solid var(--border);z-index:2}
  .brand .mark{width:34px;height:34px;flex:none;display:grid;place-items:center;border-radius:9px;background:var(--accent);color:var(--accent-fg)}
  .brand .mark svg{width:19px;height:19px}
  .brand h1{margin:0;font-size:14.5px;font-weight:700;letter-spacing:-.01em;line-height:1.15}
  .brand .sub{font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);margin-top:2px}
  nav{padding:14px 12px 0}
  .nav-group{margin-bottom:16px}
  .nav-group>.label{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);padding:0 10px 6px;display:block}
  .nav-link{display:flex;align-items:center;gap:9px;padding:7px 10px;border-radius:8px;cursor:pointer;color:var(--muted);font-size:13.5px;font-weight:500;border:1px solid transparent;transition:background .12s,color .12s}
  .nav-link:hover{background:var(--panel-2);color:var(--text);text-decoration:none}
  .nav-link.active{background:var(--accent-soft);color:var(--text);border-color:color-mix(in srgb,var(--accent) 35%,transparent);font-weight:600}
  .nav-link .idx{font-family:var(--mono);font-size:10.5px;color:var(--faint);width:18px;text-align:right;flex:none}
  .nav-link.active .idx{color:var(--accent)}
  .nav-link .ico{width:16px;height:16px;flex:none;color:inherit;display:inline-flex}
  .nav-link .ico svg{width:16px;height:16px}

  main{min-width:0}
  .topbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:13px 30px;background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:blur(10px);border-bottom:1px solid var(--border)}
  .crumbs{font-size:12.5px;color:var(--muted);display:flex;align-items:center;gap:8px;min-width:0}
  .crumbs .sep{color:var(--faint)}
  .crumbs b{color:var(--text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .theme-btn{display:inline-flex;align-items:center;gap:7px;cursor:pointer;background:var(--panel);border:1px solid var(--border);color:var(--muted);padding:6px 11px;border-radius:8px;font-size:12px;font-family:var(--sans);font-weight:500}
  .theme-btn:hover{color:var(--text);border-color:var(--border-strong)}
  .theme-btn svg{width:15px;height:15px}
  .menu-btn{display:none}
  .scrim{display:none}

  .content{max-width:860px;margin:0 auto;padding:40px 30px 100px}
  .doc{display:none;animation:fade .22s ease}
  .doc.active{display:block}
  html.no-js .doc{display:block;padding-bottom:40px;border-bottom:1px solid var(--border);margin-bottom:40px}
  @keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  @media (prefers-reduced-motion:reduce){.doc{animation:none}}

  .eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-weight:600;margin-bottom:12px}
  h2.title{font-size:30px;line-height:1.15;letter-spacing:-.02em;margin:0 0 10px;text-wrap:balance;font-weight:700}
  .meta-row{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 30px;padding-bottom:22px;border-bottom:1px solid var(--border)}
  .meta-chip{font-family:var(--mono);font-size:11.5px;color:var(--muted);background:var(--panel-2);border:1px solid var(--border);padding:4px 9px;border-radius:6px}
  .meta-chip strong{color:var(--text);font-weight:600}
  h3{font-size:17px;letter-spacing:-.01em;margin:34px 0 12px;font-weight:700}
  h4{font-size:13.5px;margin:22px 0 8px;font-weight:700;color:var(--text)}
  p{margin:0 0 14px}
  ul,ol{margin:0 0 14px;padding-left:22px}
  li{margin:5px 0}
  li::marker{color:var(--faint)}
  strong{font-weight:650}
  code{font-family:var(--mono);font-size:.86em;background:var(--panel-2);border:1px solid var(--border);padding:1px 5px;border-radius:5px;color:var(--text)}
  hr{border:none;border-top:1px solid var(--border);margin:30px 0}
  pre{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px;overflow-x:auto;margin:0 0 16px;font-family:var(--mono);font-size:12.5px;line-height:1.7;color:var(--text)}
  pre code{background:none;border:none;padding:0;font-size:inherit;color:inherit}

  .table-wrap{overflow-x:auto;margin:0 0 18px;border:1px solid var(--border);border-radius:10px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  thead th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);font-weight:600;padding:10px 13px;background:var(--panel-2);border-bottom:1px solid var(--border);white-space:nowrap}
  tbody td{padding:10px 13px;border-top:1px solid var(--border);vertical-align:top}
  tbody tr:first-child td{border-top:none}

  .callout{display:flex;gap:12px;padding:14px 16px;border-radius:10px;margin:0 0 16px;border:1px solid;font-size:13.5px}
  .callout .ico{flex:none;width:18px;height:18px;margin-top:1px}
  .callout .ico svg{width:18px;height:18px}
  .callout p{margin:0}
  .callout.warn{background:color-mix(in srgb,var(--amber) 10%,var(--panel));border-color:color-mix(in srgb,var(--amber) 40%,var(--border))}
  .callout.warn .ico{color:var(--amber)}
  .callout.info{background:color-mix(in srgb,var(--blue) 9%,var(--panel));border-color:color-mix(in srgb,var(--blue) 35%,var(--border))}
  .callout.info .ico{color:var(--blue)}

  @media (max-width:880px){
    .layout{grid-template-columns:1fr}
    .sidebar{position:fixed;z-index:50;width:274px;transform:translateX(-100%);transition:transform .2s ease;box-shadow:var(--shadow)}
    .sidebar.open{transform:none}
    .menu-btn{display:inline-flex;align-items:center;gap:7px;cursor:pointer;background:var(--panel);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:8px;font-size:12px}
    .menu-btn svg{width:16px;height:16px}
    .content{padding:28px 18px 80px}
    .scrim{position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:40;display:none}
    .scrim.open{display:block}
  }`;

// ── 런타임 JS (경량·정적 섹션 전환) ──
const CRUMBS = Object.fromEntries(NAV.map((n) => [n.id, n.crumb]));
const RUNTIME = `
  document.documentElement.classList.remove('no-js');
  var CRUMBS = ${JSON.stringify(CRUMBS)};
  var secs = [].slice.call(document.querySelectorAll('.doc'));
  var links = [].slice.call(document.querySelectorAll('.nav-link'));
  var crumbEl = document.getElementById('crumb');
  var sidebar = document.getElementById('sidebar');
  var scrim = document.getElementById('scrim');
  function closeMenu(){ if(sidebar) sidebar.classList.remove('open'); if(scrim) scrim.classList.remove('open'); }
  function go(id){
    var sec = document.getElementById('sec-'+id) || document.getElementById('sec-home');
    if(!sec){ return; }
    secs.forEach(function(s){ s.classList.remove('active'); });
    sec.classList.add('active');
    links.forEach(function(a){ a.classList.toggle('active', a.getAttribute('data-go')===id); });
    if(CRUMBS[id] && crumbEl) crumbEl.textContent = CRUMBS[id];
    window.scrollTo(0,0);
    closeMenu();
  }
  function curId(){ var h=(location.hash||'').replace(/^#(sec-)?/,''); return CRUMBS[h]!==undefined ? h : 'home'; }
  document.addEventListener('click', function(e){
    var t = e.target.closest && e.target.closest('[data-go]');
    if(t){ e.preventDefault(); var id=t.getAttribute('data-go');
      if(('#sec-'+id)!==location.hash){ location.hash='#sec-'+id; } else { go(id); } }
  });
  window.addEventListener('hashchange', function(){ go(curId()); });

  var root = document.documentElement;
  var tBtn = document.getElementById('themeBtn'), tIco = document.getElementById('themeIco'), tLbl = document.getElementById('themeLbl');
  var SUN='${I.sun}', MOON='${I.moon}';
  function applyTheme(m){ root.setAttribute('data-theme', m); if(tIco) tIco.innerHTML = (m==='dark'?SUN:MOON); if(tLbl) tLbl.textContent = (m==='dark'?'라이트':'다크'); }
  if(tBtn) tBtn.addEventListener('click', function(){
    var cur = root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
    applyTheme(cur==='dark'?'light':'dark');
  });
  applyTheme(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');

  var menuBtn = document.getElementById('menuBtn');
  if(menuBtn) menuBtn.addEventListener('click', function(){ sidebar.classList.toggle('open'); scrim.classList.toggle('open'); });
  if(scrim) scrim.addEventListener('click', closeMenu);

  go(curId());`;

// ── 조립 ──
const sections = NAV.map(renderDoc).join('\n');
const html = `<!doctype html>
<html lang="ko" class="no-js">
<head>
<meta charset="utf-8">
<title>AVA 문서 — Automated Vulnerability Assessment</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${CSS}</style>
</head>
<body>
<div class="layout">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <span class="mark" aria-hidden="true">${svg('<path d="M4.2 19.5 12 4l7.8 15.5"/><path d="M8 13h8"/><circle cx="12" cy="4" r="1.5" fill="currentColor" stroke="none"/>', 2.2)}</span>
      <div><h1>AVA</h1><div class="sub">Automated Vulnerability Assessment</div></div>
    </div>
    <nav>${buildNav()}</nav>
  </aside>
  <div class="scrim" id="scrim"></div>
  <main>
    <div class="topbar">
      <div style="display:flex;align-items:center;gap:12px;min-width:0">
        <button class="menu-btn" id="menuBtn" aria-label="메뉴"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 12h18M3 6h18M3 18h18"/></svg></button>
        <div class="crumbs"><span class="sep">AVA</span><span class="sep">/</span><b id="crumb">개요</b></div>
      </div>
      <button class="theme-btn" id="themeBtn" aria-label="테마 전환">
        <svg id="themeIco" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></svg>
        <span id="themeLbl">테마</span>
      </button>
    </div>
    <div class="content">
      ${sections}
    </div>
  </main>
</div>
<script>${RUNTIME}</script>
</body>
</html>
`;

writeFileSync(join(DIR, 'index.html'), html, 'utf8');
console.log(`docs/index.html 생성 완료 — 섹션 ${NAV.length}개, ${Buffer.byteLength(html)} bytes`);
