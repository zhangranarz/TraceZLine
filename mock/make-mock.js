// Generates mock raw logs in the formats seen in the desensitised sample:
//   mock/spl-banking-mock.log  eComm [SPLMessage] and Enterprise [SPLHostMessage]
//   mock/spl-ms-mock.log       WS [*WSAppLog] and Host/EAI [*MQLog] XML
// All IDs, users and values are fake. Run: node mock/make-mock.js
'use strict';
const fs = require('fs');
const path = require('path');

const USER = 'MOCKUSER01';
const CIF = 'MOCKCIF01';
const BASE = Date.UTC(2026, 9, 26, 9, 30, 0, 0); // timestamps are written as local wall-clock time

const SESSIONS = {
  login: 'aaaaaaaa-0000-4000-8000-000000000001',
  cardTxn: 'bbbbbbbb-0000-4000-8000-000000000002',
  billPay: 'cccccccc-0000-4000-8000-000000000003',
};

const pad = (n, w = 2) => String(n).padStart(w, '0');
function ts(ms) {
  const d = new Date(BASE + ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} `
    + `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)}`;
}
let seq = 0;
const trace = () => (0xfeed0000 + ++seq).toString(16) + '0'.repeat(24);
const jid = () => '9990000000000000' + pad(seq, 4);

// ---------- event templates ----------

function ecommReq(t, sid, p, thread) {
  return { t, file: 'banking', text: `${ts(t)} [http-nio-8443-exec-${thread}] INFO
[SPLMessage][${sid}][${USER}][VN][9.14][${trace()}][Android-SPL][][] -${p} - Request -
{"data":{"device":{"deviceId":"MOCK-DEVICE","platform":"Android","version":"16"}},"meta":{"requestContext":{"appVersion":"19.14.0","countryCode":"VN","sessionId":"${sid}"}}}` };
}

function ecommRes(t, sid, p, thread, ms, code = '00000000', desc = 'Success', err = '') {
  return { t, file: 'banking', text: `${ts(t)} [http-nio-8443-exec-${thread}] INFO
[SPLMessage][${sid}][${USER}][VN][9.14][${trace()}][Android-SPL][][${ms}ms] -${p} -
{"response":{"responseHeader":{"responseContext":{"responseCode":"${code}","responseDescription":"${desc}"${err}}},"requesterContext":{"sessionId":"${sid}"}}}` };
}

// Enterprise header styles from the sample:
//   std   [SPLHostMessage][sid][user]...[Android-SPL][12ms] -/path - [Request]:
//   split [SPLHostMessage] [sid]|[user]|... then [Android-SPL] - /path - [Request]: on the next line
//   nosid [SPLHostMessage][VN][12ms] - /path - [Request]:  (sessionId only in the JSON body)
function entHeader(style, sid, p, ms, dir) {
  if (style === 'split') return `[SPLHostMessage] [${sid}]|[${USER}]|[VN]|[9.14][${trace()}]
[Android-SPL] - ${p} - [${dir}]:`;
  if (style === 'nosid') return `[SPLHostMessage][VN][${ms}] - ${p} - [${dir}]:`;
  return `[SPLHostMessage][${sid}][${USER}][VN][9.14][${trace()}][Android-SPL][${ms}] -${p} - [${dir}]:`;
}

function entReq(t, sid, p, thread, txnCode, style = 'std') {
  const tc = txnCode ? `, "transactionCode": "${txnCode}"` : '';
  return { t, file: 'banking', text: `${ts(t)} [http-nio-8443-exec-${thread}] INFO
${entHeader(style, sid, p, '', 'Request')} { "serviceRequestHeader": { "requesterContext": { "applicationCode": "SPL", "countryCode": "VN", "sessionIdentity": "${sid}"${tc} } }, "data": { } }` };
}

function entRes(t, sid, p, thread, ms, { code = '00000000', desc = 'Success', txnCode, txnRef, err = '', style = 'std' } = {}) {
  const tc = txnCode ? `,"transactionCode":"${txnCode}"` : '';
  const tr = txnRef ? `,"transactionReferenceNumber":"${txnRef}"` : '';
  return { t, file: 'banking', text: `${ts(t)} [http-nio-8443-exec-${thread}] INFO
${entHeader(style, sid, p, `${ms}ms`, 'Response')}
{"traceId":"${trace()}","httpStatus":200,"serviceResponseHeader":{"responseContext":{"responseCode":"${code}","responseDescription":"${desc}"${err}},"requesterContext":{"sessionIdentity":"${sid}"${tc}${tr}}}}` };
}

// WS service tag, DGE endpoint and URL, e.g. ws('ENQ', 'dge-enq:enq.card.transactions.VN.V2.0', '/dge-enq/enq/card/transactions')
function wsReq(t, sid, w, thread, txnCode) {
  const tc = txnCode ? `,"transactionCode":"${txnCode}"` : '';
  return { t, file: 'ms', text: `${ts(t)} [http-nio-9443-exec-${thread}] [INFO ] [${w.tag}WSAppLog] [${trace()}] - [::${w.dge}] - RestEndPointUFWAspect: | URL is ${w.url} request:
{"serviceRequestHeader":{"requesterContext":{"applicationCode":"SPL","requesterUserIdentity":"${USER}","sessionIdentity":"${sid}"${tc}}}}` };
}

function wsRes(t, sid, w, thread, { code = '00000000', desc = 'Success', txnCode, txnRef, oneLine = false } = {}) {
  const tc = txnCode ? `,"transactionCode":"${txnCode}"` : '';
  const tr = txnRef ? `,"transactionReferenceNumber":"${txnRef}"` : '';
  return { t, file: 'ms', text: `${ts(t)} [http-nio-9443-exec-${thread}] [INFO ] [${w.tag}WSAppLog] [${trace()}] - [::${w.dge.replace(':', '.')}] - WebLogUFWAspect: UId:${USER} | JId:${jid()} | CIF:${CIF} | WLS:${sid} | SSO: | URL:${w.url} | StartTime:1700000000000 | Response Code:${code} |${oneLine ? ' ' : '\n'}Response:{"serviceResponseHeader":{"responseContext":{"responseCode":"${code}","responseDescription":"${desc}"},"requesterContext":{"sessionIdentity":"${sid}"${tc}${tr}}}}` };
}

// Host/EAI: svc is the main SvcCode, subs the SubSvc codes (one or more).
function hostReq(t, sid, w, thread, svc, subs) {
  const subXml = subs.map((s, i) => `<SubSvc>
<SubSvcSeq>${i + 1}</SubSvcSeq>
<SubSvcRqHeader>
<SvcCode>${s}</SvcCode>
<TxnRef>99900000000${pad(seq * 10 + i, 5)}</TxnRef>
</SubSvcRqHeader>
</SubSvc>`).join('\n');
  return { t, file: 'ms', text: `${ts(t)} [http-nio-9443-exec-${thread}] [INFO ] [${w.tag}MQLog] [] - [::${w.dge}] - MQAdapterServiceOnlineImpl: UId:${USER} | JId:${jid()} | CIF:${CIF} | WLS:${sid} | SERVICE CODE:${svc}  USER ID:${USER}  Request Q
Name::/MOCKQMGR/MOCK.EAI.REQ?targetClient=1&version=6
Request Message:<?xml version="1.0" encoding="UTF-8" ?> <EAI>
<SvcRq>
<ChannelId>MOCK</ChannelId> <SvcCode>${svc}</SvcCode> <SvcRqId>9990${pad(seq, 10)}</SvcRqId>
<SvcRqHdr>
${subXml}
</SvcRqHdr>
<UserId>${USER}</UserId> <CIFNo>${CIF}</CIFNo>
</SvcRq>
</EAI>` };
}

function hostRes(t, sid, w, thread, svc, subs, { status = '00000000', errCode = '', errDesc = '' } = {}) {
  const err = errCode ? `<ErrorCode>${errCode}</ErrorCode> <ErrorDesc>${errDesc}</ErrorDesc>` : '<ErrorCode/> <ErrorDesc/>';
  const subXml = subs.map((s, i) => `<SubSvcRs>
<SubSvcSeq>${i + 1}</SubSvcSeq>
<SubSvcRsHeader>
<SvcCode>${s}</SvcCode>
<StatusCode>${status}</StatusCode>
${err}
</SubSvcRsHeader>
</SubSvcRs>`).join('\n');
  return { t, file: 'ms', text: `${ts(t)} [http-nio-9443-exec-${thread}] [INFO ] [${w.tag}MQLog] [] - [::${w.dge}] - MQAdapterServiceOnlineImpl: UId:${USER} | JId:${jid()} | CIF:${CIF} | WLS:${sid} | SERVICE_CODE:${svc}  USER ID:${USER}  RESPONSE Q
NAME::queue://MOCKQMGR/MOCK.EAI.REPLY?targetClient=1&version=6
Response Message:<?xml version="1.0" encoding="UTF-8"?> <EAI>
<SvcRs>
<ChannelId>MOCK</ChannelId> <SvcCode>${svc}</SvcCode> <StatusCode>${status}</StatusCode> ${err}
${subXml}
</SvcRs>
</EAI>` };
}

// ---------- scenarios ----------

const WS = {
  idm: { tag: 'IDM', dge: 'dge-idm:idm.user.profile.get.VN.V7.6', url: '/dge-idm/idm/user/profile/get' },
  portfolio: { tag: 'ENQ', dge: 'dge-enq:enq.customer.portfolio.VN.V2.3', url: '/dge-enq/enq/customer/portfolio' },
  card: { tag: 'ENQ', dge: 'dge-enq:enq.card.transactions.VN.V2.0', url: '/dge-enq/enq/card/transactions' },
  payee: { tag: 'BFS', dge: 'dge-bfs:bfs.payee.list.VN.V1.0', url: '/dge-bfs/bfs/payee/list' },
  bpInit: { tag: 'BFS', dge: 'dge-bfs:bfs.quick.bp.initiate.VN.V1.0', url: '/dge-bfs/bfs/bp/initiate' },
};

const events = [];
const add = (...e) => events.push(...e);

// Session 1 (login): A, B, D, E.
{
  const s = SESSIONS.login;
  const login = '/spl-banking/services/vn/security/auth/v2/login';
  add(
    // A: eComm internal processing only
    ecommReq(0, s, '/spl-banking/services/vn/security/preLogin', 149),
    ecommRes(4, s, '/spl-banking/services/vn/security/preLogin', 149, 4),
    ecommReq(3000, s, login, 138),
    // B: Enterprise -> WS, no Host
    entReq(3001, s, '/idm/user/profile/get', 138, 'SEC02'),
    wsReq(3008, s, WS.idm, 2, 'SEC02'),
    wsRes(3053, s, WS.idm, 2, { txnCode: 'SEC02', txnRef: '9990000000000101', oneLine: true }),
    entRes(3065, s, '/idm/user/profile/get', 138, 64, { txnCode: 'SEC02', txnRef: '9990000000000101', style: 'split' }),
    // D + E: one EAI call with a single subservice, then one with multiple subservices
    entReq(3070, s, '/enq/customer/portfolio', 138, 'AES01'),
    wsReq(3075, s, WS.portfolio, 4, 'AES01'),
    hostReq(3110, s, WS.portfolio, 4, 'BA_ACCT_INFO_N3', ['BA_ACCT_INFO_N3']),
    hostRes(3507, s, WS.portfolio, 4, 'BA_ACCT_INFO_N3', ['BA_ACCT_INFO_N3']),
    hostReq(3520, s, WS.portfolio, 4, 'AC_ACCT_SUM_X', ['AC_RBK_SUMM_N', 'AC_VSA_SUMM_N']),
    hostRes(4620, s, WS.portfolio, 4, 'AC_ACCT_SUM_X', ['AC_RBK_SUMM_N', 'AC_VSA_SUMM_N'], { status: '0005000' }),
    wsRes(4748, s, WS.portfolio, 4, { txnCode: 'AES01' }),
    entRes(4757, s, '/enq/customer/portfolio', 138, 1687, { txnCode: 'AES01' }),
    ecommRes(5110, s, login, 138, 2110),
  );
}

// Session 2 (card transactions), interleaved with session 1 in time (H):
// G2 EAI error status, G3 Enterprise HTTP 200 with a business error, G4 eComm non-success code.
{
  const s = SESSIONS.cardTxn;
  const p = '/spl-banking/services/vn/pfm/enriched/transactions';
  add(
    ecommReq(3200, s, p, 151),
    entReq(3202, s, '/enq/card/transactions', 151, 'AES06'),
    wsReq(3206, s, WS.card, 7, 'AES06'),
    hostReq(3230, s, WS.card, 7, 'CC_INFO_STMT_X', ['CC_CC_STMT_N']),
    hostRes(4060, s, WS.card, 7, 'CC_INFO_STMT_X', ['CC_CC_STMT_N'], { status: 'E0012', errCode: 'CC012', errDesc: 'Card statement not found' }),
    wsRes(4081, s, WS.card, 7, { code: 'E0012', desc: 'Downstream error', txnCode: 'AES06' }),
    entRes(4085, s, '/enq/card/transactions', 151, 883, { code: '00000000', desc: 'Success', txnCode: 'AES06',
      err: ',"errorCode":"ENQ-4001","errorDescription":"Card statement not available"' }),
    ecommRes(4090, s, p, 151, 890, '40010001', 'Failed', ',"errorDescription":"Unable to load transactions"'),
  );
}

// Session 3 (bill payment): C two Enterprise APIs in sequence, G1 WS timeout (no WS response),
// I one Enterprise API succeeds and the next fails in the same session.
{
  const s = SESSIONS.billPay;
  const p = '/spl-banking/services/vn/payment/precapture';
  add(
    ecommReq(10000, s, p, 160),
    entReq(10002, s, '/bfs/payee/list/bp', 160, 'PMT02', 'nosid'),
    wsReq(10006, s, WS.payee, 9, 'PMT02'),
    wsRes(10042, s, WS.payee, 9, { txnCode: 'PMT02', txnRef: '9990000000000301' }),
    entRes(10046, s, '/bfs/payee/list/bp', 160, 44, { txnCode: 'PMT02', txnRef: '9990000000000301', style: 'nosid' }),
    entReq(10050, s, '/bfs/quick/bp/initiate', 160, 'PMT20'),
    wsReq(10055, s, WS.bpInit, 9, 'PMT20'),
    // no WS response: timeout
    entRes(40056, s, '/bfs/quick/bp/initiate', 160, 30006, { code: '99999999', desc: 'Timeout', txnCode: 'PMT20',
      err: ',"errorCode":"BFS-TIMEOUT","errorDescription":"Downstream timeout after 30000ms"' }),
    ecommRes(40060, s, p, 160, 30060, '99999999', 'Timeout', ',"errorDescription":"Request timed out"'),
  );
}

events.sort((a, b) => a.t - b.t);
for (const [file, name] of [['banking', 'spl-banking-mock.log'], ['ms', 'spl-ms-mock.log']]) {
  const body = events.filter((e) => e.file === file).map((e) => e.text).join('\n') + '\n';
  fs.writeFileSync(path.join(__dirname, name), body);
  console.log(`${name}: ${events.filter((e) => e.file === file).length} events`);
}
