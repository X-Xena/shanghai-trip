// Encrypts src/page.html with a password and writes index.html (the only page served).
// Usage:  SHTRIP_PW=<password> node build.mjs
// src/ is git-ignored, so the readable itinerary never reaches the public repo.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const pw = process.env.SHTRIP_PW;
if (!pw) { console.error('SHTRIP_PW 환경변수에 비밀번호를 넣어주세요'); process.exit(1); }

const body = readFileSync(new URL('./src/page.html', import.meta.url), 'utf8');
const head = '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
  '<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}' +
  'body{margin:0;font:14px/1.5 system-ui,sans-serif}img{max-width:100%}[hidden]{display:none!important}</style></head><body>';
const plain = head + body + '</body></html>';

const enc = new TextEncoder();
const ITER = 600000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));

// round-trip check before writing
const back = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
if (back !== plain) { console.error('암호화 확인 실패'); process.exit(1); }

const b64 = (u) => Buffer.from(u).toString('base64');
const payload = JSON.stringify({ s: b64(salt), i: b64(iv), c: b64(ct), n: ITER });
const tpl = readFileSync(new URL('./gate.html', import.meta.url), 'utf8');
writeFileSync(new URL('./index.html', import.meta.url), tpl.replace('__PAYLOAD__', payload));
console.log('index.html 생성 완료 (' + Math.round(ct.length / 1024) + ' KB 암호문)');
