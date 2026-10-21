// Browser verdict regression using synthetic HTTP and ICE observations; no network.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '..', 'webrtc-leak-test.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
async function check(candidate, httpIp, expected) {
  const elements = {};
  const document = { title: '', getElementById: id => elements[id] ||= {} };
  const timers = [];
  function Peer() {
    this.createDataChannel = () => {};
    this.createOffer = () => Promise.resolve({});
    this.setLocalDescription = () => {
      if (candidate) this.onicecandidate({ candidate: { candidate: `candidate:1 1 udp 1 ${candidate} 123 typ srflx` } });
      this.iceGatheringState = 'complete';
      this.onicegatheringstatechange();
      return Promise.resolve();
    };
  }
  vm.runInNewContext(script, { document, RTCPeerConnection: Peer,
    setTimeout: fn => timers.push(fn),
    fetch: () => httpIp ? Promise.resolve({ json: () => Promise.resolve({ ip: httpIp }) }) : Promise.reject(new Error('timeout')) });
  for (let n = 0; n < 12; n++) await Promise.resolve();
  timers.forEach(fn => fn());
  assert.equal(document.title, `WEBRTC RESULT:${expected}`);
  assert.doesNotMatch(elements.verdict.innerHTML, /无泄露|安全|真实地址/);
}
(async () => {
  await check(null, '192.0.2.1', 'NO_SRFLX');
  await check('192.0.2.1', null, 'SRFLX_NO_EXITREF');
  await check('192.0.2.1', '192.0.2.1', 'OK');
  await check('192.0.2.2', '192.0.2.1', 'DIFFERENT');
  console.log('webrtc: 4 synthetic scenarios passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
