// Masks sensitive values in log/text files with Pre/Post rules: the value between a rule's
// Pre text and Post text is replaced. Runs in the browser (and Node for tests); nothing is
// sent anywhere.
//
// Modes:
//   replace   the value becomes the rule's Mask text (e.g. <<USER_ID>>)
//   last4     every character but the last 4 letters/digits becomes X (length kept)
//   consistent the same value always becomes the same fake value of the same shape
//              (digits stay digits, hex stays hex, separators kept), from an HMAC with a
//              local secret key, so a masked session ID still links the lines of a session.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TraceMask = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const r = (name, pre, post, mode, mask = '') => ({ on: true, name, pre, post, mode, mask });
  const DEFAULT_RULES = [
    r('Password', '"password":"', '"', 'replace', '***'),
    r('Encrypted password', '"encryptedPassword":"', '"', 'replace', '<<ENCRYPTED_PASSWORD>>'),
    r('OTP', '"twoFAotp":"', '"', 'replace', '***'),
    r('Token data', '"tokenData":"', '"', 'replace', '***'),
    r('Soft token serial', '"softTokenSerialNumber":"', '"', 'last4'),
    r('User ID', '"userId":"', '"', 'replace', '<<USER_ID>>'),
    r('User identity', '"userIdentity":"', '"', 'replace', '<<USER_ID>>'),
    r('Requester user', '"requesterUserIdentity":"', '"', 'replace', '<<USER_ID>>'),
    r('Customer name', '"customerName":"', '"', 'replace', '<<CUST_NAME>>'),
    r('First name', '"firstName":"', '"', 'replace', '<<CUST_NAME>>'),
    r('Birth date', '"birthDate":"', '"', 'replace', '<<DOB>>'),
    r('Mobile number', '"mobileNumber":"', '"', 'last4'),
    r('Email', '"email":"', '"', 'replace', '<<EMAIL>>'),
    r('Legal identity', '"legalIdentity":"', '"', 'replace', '<<LEGAL_ID>>'),
    r('CIF number', '"CIFNumber":"', '"', 'replace', '<<CIF_NUM>>'),
    r('Account number', '"accountNumber":"', '"', 'last4'),
    r('Card number', '"cardNumber":"', '"', 'last4'),
    r('Device ID', '"deviceId":"', '"', 'consistent'),
    r('Push token', '"pushToken":"', '"', 'replace', '<<PUSH_TOKEN>>'),
    r('Client IP', '"clientIpAddress":"', '"', 'replace', '<<IP>>'),
    r('Session ID', '"sessionId":"', '"', 'consistent'),
    r('Session identity', '"sessionIdentity":"', '"', 'consistent'),
    r('Parent session ID', '"parentSessionId":"', '"', 'consistent'),
    r('SSO session identity', '"ssoSessionIdentity":"', '"', 'consistent'),
    r('Session (eComm header)', '[SPLMessage][', ']', 'consistent'),
    r('Session (Enterprise header)', '[SPLHostMessage][', ']', 'consistent'),
    r('Session (WS header)', 'WLS:', ' |', 'consistent'),
    r('User (WS header)', 'UId:', ' |', 'replace', '<<USER_ID>>'),
    r('CIF (WS header)', 'CIF:', ' |', 'replace', '<<CIF_NUM>>'),
    r('Journal ID (WS header)', 'JId:', ' |', 'consistent'),
    r('WS request ID (WS header)', 'WSReqId:', ' |', 'consistent'),
    r('Reference number', '"referenceNumber":"', '"', 'consistent'),
    r('Transaction reference', '"transactionReferenceNumber":"', '"', 'consistent'),
    r('Requester reference', '"requesterReferenceNumber":"', '"', 'consistent'),
    r('Journal identity', '"journalIdentity":"', '"', 'consistent'),
    r('API token', '"apiToken":"', '"', 'replace', '<<API_TOKEN>>'),
    r('Transaction reference (XML)', '<TxnRef>', '</TxnRef>', 'consistent'),
    r('Service request ID (XML)', '<SvcRqId>', '</SvcRqId>', 'consistent'),
    r('User ID (XML)', '<UserId>', '</UserId>', 'replace', '<<USER_ID>>'),
    r('CIF (XML)', '<CIFNo>', '</CIFNo>', 'replace', '<<CIF_NUM>>'),
    r('Customer name (XML)', '<CustName1>', '</CustName1>', 'replace', '<<CUST_NAME>>'),
    r('Account (XML)', '<AcctId>', '</AcctId>', 'last4'),
    r('Birth date (XML)', '<DOB>', '</DOB>', 'replace', '<<DOB>>'),
  ];

  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Pre and Post are literal text; whitespace after ':', '=', ']' or '>' and runs of spaces are
  // flexible, so "tokenData":"x" and "tokenData": "x" both match, as do [SPLHostMessage][id] and
  // [SPLHostMessage] [id]. Case is ignored. The value is the shortest text up to Post on the
  // same line; with an empty Post, the next run of non-spaces.
  function ruleRegex(rule) {
    const flex = (s) => escapeRe(s).replace(/\s+/g, '\\s*').replace(/([:=>]|\\\])(?!\\s\*)/g, '$1\\s*');
    const pre = flex(rule.pre);
    if (!pre) return null;
    const value = rule.post ? '([^\\r\\n]*?)' : '(\\S+)';
    const post = rule.post ? `(?=${flex(rule.post)})` : '';
    return new RegExp(`(${pre})${value}${post}`, 'gi');
  }

  const isPlaceholder = (v) => /^<<[A-Za-z0-9_]+>>$/.test(v) || /^\*+$/.test(v);

  function last4(v) {
    let keep = 4;
    const out = [];
    for (let i = v.length - 1; i >= 0; i--) {
      const c = v[i];
      if (/[A-Za-z0-9]/.test(c)) out.push(keep-- > 0 ? c : 'X');
      else out.push(c);
    }
    return out.reverse().join('');
  }

  // Same shape as the input: digit -> digit, hex (in a hex value) -> hex, letter -> letter.
  // A value of digits only (a reference number) stays digits only.
  function shaped(v, bytes) {
    const hexOnly = /^[0-9a-fA-F-]+$/.test(v) && /[a-fA-F]/.test(v);
    let k = 0;
    const next = () => bytes[(k++) % bytes.length];
    return [...v].map((c) => {
      if (/[0-9]/.test(c) && !hexOnly) return String(next() % 10);
      if (hexOnly && /[0-9a-f]/.test(c)) return '0123456789abcdef'[next() % 16];
      if (hexOnly && /[A-F]/.test(c)) return '0123456789ABCDEF'[next() % 16];
      if (/[a-z]/.test(c)) return String.fromCharCode(97 + (next() % 26));
      if (/[A-Z]/.test(c)) return String.fromCharCode(65 + (next() % 26));
      return c;
    }).join('');
  }

  const subtle = () => (typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : require('crypto').webcrypto.subtle);

  async function hmac(key, value) {
    const enc = new TextEncoder();
    const k = await subtle().importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const a = new Uint8Array(await subtle().sign('HMAC', k, enc.encode(value)));
    const b = new Uint8Array(await subtle().sign('HMAC', k, enc.encode(value + '\u0000more')));
    return [...a, ...b];
  }

  // Masks one text. Returns { text, marked, counts: [n per rule], fakes: Set of consistent outputs }.
  // `marked` is the same text with each masked value wrapped in \u0001...\u0002 (for previews).
  async function maskText(text, rules, { key = 'tracezline' } = {}) {
    const fakes = new Map(); // value -> consistent replacement
    const counts = rules.map(() => 0);
    // \u0001/\u0002 mark replacements while rules run, so a later rule cannot re-mask them.
    let out = text.replace(/[\u0001\u0002]/g, '');
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!rule.on) continue;
      const re = ruleRegex(rule);
      if (!re) continue;
      if (rule.mode === 'consistent') {
        for (const m of out.matchAll(re)) {
          const v = m[2];
          if (v && !isPlaceholder(v) && !/[\u0001\u0002]/.test(v) && !fakes.has(v)) fakes.set(v, shaped(v, await hmac(key, v)));
        }
      }
      out = out.replace(re, (all, pre, v) => {
        if (!v || isPlaceholder(v) || /[\u0001\u0002]/.test(v)) return all;
        counts[i]++;
        const masked = rule.mode === 'last4' ? last4(v) : rule.mode === 'consistent' ? fakes.get(v) : (rule.mask || '***');
        return pre + '\u0001' + masked + '\u0002';
      });
    }
    return { text: out.replace(/[\u0001\u0002]/g, ''), marked: out, counts, fakes: new Set(fakes.values()) };
  }

  // What still looks sensitive after masking: [{ kind, line, value }]. Values produced by
  // consistent masking and <<PLACEHOLDERS>> are not reported.
  const LEFTOVER = [
    ['email', /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g],
    ['IP address', /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g],
    ['UUID', /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi],
    // not a group inside a hyphenated ID such as a UUID
    ['long number', /(?<![\w-])\d{12,19}(?![\w-])/g],
  ];
  function leftovers(text, fakes = new Set()) {
    const found = [];
    const lines = text.split('\n');
    lines.forEach((line, i) => {
      for (const [kind, re] of LEFTOVER) {
        for (const m of line.matchAll(re)) {
          if (fakes.has(m[0]) || /^0+$/.test(m[0]) || /^(\d)\1+$/.test(m[0])) continue;
          // epoch milliseconds (2001-2036), e.g. StartTime:1700000000000, are times, not data
          if (kind === 'long number' && m[0].length === 13 && +m[0] >= 1e12 && +m[0] < 2.1e12) continue;
          // yyyyMMddHHmmss, e.g. requestTimeInGMT
          if (kind === 'long number' && /^(19|20)\d\d(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])[0-5]\d[0-5]\d$/.test(m[0])) continue;
          found.push({ kind, line: i + 1, value: m[0] });
        }
      }
    });
    return found;
  }

  // "app.log" -> "app.masked.log"
  const maskedName = (name) => (/\.[^./\\]+$/.test(name) ? name.replace(/(\.[^./\\]+)$/, '.masked$1') : name + '.masked');

  return { DEFAULT_RULES, ruleRegex, maskText, leftovers, maskedName, last4 };
});
