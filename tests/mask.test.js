'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { DEFAULT_RULES, ruleRegex, autoMask, maskText, leftovers, maskedName, last4 } = require('../js/mask.js');

const rule = (pre, post, mode, mask) => ({ on: true, name: 'r', pre, post, mode, mask });

test('Pre/Post match with flexible spacing after : and = and ignore case', () => {
  const re = ruleRegex(rule('"tokenData":"', '"', 'replace', '***'));
  assert.strictEqual('{"tokenData": "458169"}'.replace(re, '$1***'), '{"tokenData": "***"}');
  assert.strictEqual('{"TOKENDATA":"1"}'.replace(ruleRegex(rule('"tokenData":"', '"')), '$1*'), '{"TOKENDATA":"*"}');
});

test('replace, keep-last-4 and consistent modes', async () => {
  const text = '{"userId":"alice","accountNumber":"2020-1234-5678","sessionId":"0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"}\n'
    + 'WLS:0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0 | next';
  const rules = [
    rule('"userId":"', '"', 'replace', '<<USER_ID>>'),
    rule('"accountNumber":"', '"', 'last4'),
    rule('"sessionId":"', '"', 'consistent'),
    rule('WLS:', ' |', 'consistent'),
  ];
  const r = await maskText(text, rules, { key: 'k1' });
  assert.match(r.text, /"userId":"<<USER_ID>>"/);
  assert.match(r.text, /"accountNumber":"XXXX-XXXX-5678"/);
  const sid = r.text.match(/"sessionId":"([^"]+)"/)[1];
  assert.match(sid, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  assert.notStrictEqual(sid, '0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0');
  assert.ok(r.text.includes(`WLS:${sid} |`), 'same session ID masks to the same value everywhere');
  assert.deepStrictEqual(r.counts, [1, 1, 1, 1]);
  // another key gives other pseudonyms; the same key the same ones
  assert.notStrictEqual((await maskText(text, rules, { key: 'k2' })).text, r.text);
  assert.strictEqual((await maskText(text, rules, { key: 'k1' })).text, r.text);
});

test('already masked values and placeholders are left alone', async () => {
  const r = await maskText('"userId":"<<USER_ID>>" "pin":"***"', [rule('"userId":"', '"', 'replace', 'X'), rule('"pin":"', '"', 'replace', 'Y')]);
  assert.strictEqual(r.text, '"userId":"<<USER_ID>>" "pin":"***"');
  assert.deepStrictEqual(r.counts, [0, 0]);
});

test('a value masked by one rule is not masked again by a later rule', async () => {
  const r = await maskText('"a":"secret"', [rule('"a":"', '"', 'replace', '<<A>>'), rule('"a":"', '"', 'replace', '<<B>>')]);
  assert.strictEqual(r.text, '"a":"<<A>>"');
});

test('default rules mask the sample formats (JSON, headers, XML)', async () => {
  const text = [
    '2026-10-26 09:10:55.931 [http-nio-8443-exec-138] INFO',
    '[SPLMessage][0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0][u1] -/login - Request -',
    '{"data":{"encryptedPassword":"abc123","twoFAotp":"458169","userId":"jdoe","device":{"deviceId":"DEV-12345"}},"meta":{"requestContext":{"sessionId":"0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"}}}',
    '... | CIF:12345678 | WLS:0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0 | SSO:',
    '<UserId>jdoe</UserId> <CIFNo>12345678</CIFNo> <AcctId>2021234567890</AcctId> <DOB>12101984</DOB>',
    '{"email":"j.doe@example.com","mobileNumber":"+84912345678","clientIpAddress":"203.0.113.41"}',
  ].join('\n');
  const r = await maskText(text, DEFAULT_RULES, { key: 'k' });
  for (const secret of ['abc123', '458169', 'jdoe', 'DEV-12345', '12345678', '12101984', 'j.doe@example.com', '203.0.113.41', '0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0']) {
    assert.ok(!r.text.includes(secret), `still contains ${secret}`);
  }
  assert.match(r.text, /<AcctId>\*{13}<\/AcctId>/);
  assert.match(r.text, /<UserId><<MASK_USERID>><\/UserId>/);
  assert.match(r.text, /"mobileNumber":"\+XXXXXXX5678"/);
  assert.deepStrictEqual(leftovers(r.text, r.fakes), []);
});

test('leftover scan reports what still looks sensitive, not consistent fakes or placeholders', () => {
  const found = leftovers('ok <<EMAIL>>\nmail me@x.com from 10.1.2.3\nref 2601010000000003', new Set());
  assert.deepStrictEqual(found.map((f) => [f.kind, f.line]), [['email', 2], ['IP address', 2], ['long number', 3]]);
  assert.deepStrictEqual(leftovers('id 0a1b2c3d-0000-4000-8000-000000000001', new Set(['0a1b2c3d-0000-4000-8000-000000000001'])), []);
});

test('helpers: masked file name and keep-last-4', () => {
  assert.strictEqual(maskedName('combined.log'), 'combined.masked.log');
  assert.strictEqual(maskedName('notes'), 'notes.masked');
  assert.strictEqual(last4('1234 5678 9012'), 'XXXX XXXX 9012');
});

test('split headers, reference numbers and epoch times', async () => {
  const text = '[SPLHostMessage] [0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0]|[u]\n'
    + '{"transactionReferenceNumber":"2601010000000001","referenceNumber":"26010100000000051"} WSReqId:26010100000000052 | <TxnRef>2601010000000002</TxnRef> | JId:26010100000000000004 | StartTime:1790000000123 |';
  const r = await maskText(text, DEFAULT_RULES, { key: 'k' });
  assert.ok(!r.text.includes('0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0'));
  for (const v of ['26010100000000051', '26010100000000052', '2601010000000001', '2601010000000002', '26010100000000000004']) assert.ok(!r.text.includes(v), v);
  assert.match(r.text, /"transactionReferenceNumber":"\d{16}"/);
  assert.ok(r.text.includes('StartTime:1790000000123'), 'epoch time kept');
  assert.deepStrictEqual(leftovers('{"requestTimeInGMT":"20261026091055"} 20261399999999'), [{ kind: 'long number', line: 1, value: '20261399999999' }]);
  assert.deepStrictEqual(leftovers(r.text, r.fakes), []);
});

test('rule types: exact text, JSON key, XML tag, with the automatic <<MASK_NAME>>', async () => {
  const t = (type, pre, mode, mask = '') => ({ on: true, name: 'r', type, pre, post: '', mode, mask });
  const rules = [
    t('text', 'ABC Company', 'replace', '<<MASKED_COMPANY_NAME>>'),
    t('json', 'userId', 'replace'),
    t('xml', '<UserId>', 'replace'),
    t('json', 'accountNumber', 'digits'),
    t('xml', 'AcctId', 'digits'),
  ];
  const text = 'ABC Company and ABC Companys\n'
    + '{"userId":"jdoe","parentUserId":"keep","accountNumber": "2020-1234-5678","x":{"accountNumber":123456}}\n'
    + '{\\"userId\\":\\"esc\\"}\n'
    + '<UserId>jdoe</UserId> <ns:AcctId type="x">2021234567890</ns:AcctId> <AcctId>12<<ACCOUNT_NUM1>></AcctId> <UserId/>';
  const r = await maskText(text, rules);
  assert.strictEqual(r.text, '<<MASKED_COMPANY_NAME>> and ABC Companys\n'
    + '{"userId":"<<MASK_USERID>>","parentUserId":"keep","accountNumber": "****-****-****","x":{"accountNumber":******}}\n'
    + '{\\"userId\\":\\"<<MASK_USERID>>\\"}\n'
    + '<UserId><<MASK_USERID>></UserId> <ns:AcctId type="x">*************</ns:AcctId> <AcctId>**<<ACCOUNT_NUM1>></AcctId> <UserId/>');
  assert.deepStrictEqual(r.counts, [1, 2, 1, 2, 2]);
  assert.strictEqual(autoMask(t('json', '"clientIpAddress"', 'replace')), '<<MASK_CLIENTIPADDRESS>>');
  assert.strictEqual(autoMask(t('prepost', 'UId:', 'replace')), '***');
});
