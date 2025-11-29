#!/usr/bin/env node
// Regenerates the self-sealed TLS 1.3 records that tests/test_tls_decrypt.cpp uses for the paths the RFC 8448 trace does
// not exercise (64-bit sequence numbers, a record header with another version, padding, a Finished or KeyUpdate cut
// across records, KeyUpdate generations). It prints one JSON object {name: hex of the record bytes after the 5 byte header};
// the test constants are these values. They are SELF-CONSISTENCY vectors: sealed by Node's crypto (an implementation other
// than the one under test) from the RFC 8448 secrets, following RFC 8446 sections 5.2, 5.3 and 7.2, not taken from a
// published trace. The RFC's own records are in the same test file and come from RFC 8448 itself.
//
//   usage: node tools/make_tls_sealed_vectors.js
//
// AES-128-GCM only (the RFC 8448 suite); the other suites are covered by the OpenSSL connections in tests/data/tls.
const crypto = require('crypto');
const hex = (s) => Buffer.from(s.replace(/\s/g, ''), 'hex');
const EMPTY = Buffer.alloc(0);

// HKDF-Expand-Label(secret, label, context, length) with SHA-256 (RFC 8446 section 7.1)
function expandLabel(secret, label, context, length) {
  const full = Buffer.concat([Buffer.from('tls13 '), Buffer.from(label)]);
  const info = Buffer.concat([Buffer.from([length >> 8, length & 255, full.length]), full, Buffer.from([context.length]), context]);
  let t = EMPTY, okm = EMPTY;
  for (let i = 1; okm.length < length; i++) {
    t = crypto.createHmac('sha256', secret).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, length);
}

// One protected record: inner plaintext = content || content type || `pad` zero bytes; nonce = iv XOR sequence (64 bit,
// right aligned); additional data = the record header (type 23, record version, ciphertext length).
function seal(secret, sequence, type, content, pad = 0, version = 0x0303) {
  const key = expandLabel(secret, 'key', EMPTY, 16);
  const nonce = Buffer.from(expandLabel(secret, 'iv', EMPTY, 12));
  let s = BigInt(sequence);
  for (let i = 11; i >= 4; i--) { nonce[i] ^= Number(s & 0xffn); s >>= 8n; }
  const inner = Buffer.concat([content, Buffer.from([type]), Buffer.alloc(pad)]);
  const header = Buffer.from([0x17, version >> 8, version & 255, 0, 0]);
  header.writeUInt16BE(inner.length + 16, 3);
  const cipher = crypto.createCipheriv('aes-128-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(header);
  return Buffer.concat([cipher.update(inner), cipher.final(), cipher.getAuthTag()]).toString('hex');
}

// RFC 8448 section 3 secrets
const serverHandshake = hex('b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38');
const serverApplication = hex('a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643');
const encryptedExtensions = hex('080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000');   // RFC 8448
const finished = Buffer.concat([hex('14000020'), Buffer.alloc(32, 0xaa)]);   // a Finished header and made-up verify_data
const keyUpdate = hex('1800000100');                                          // KeyUpdate(update_not_requested)

const gen1 = expandLabel(serverApplication, 'traffic upd', EMPTY, 32);
const gen2 = expandLabel(gen1, 'traffic upd', EMPTY, 32);

const out = {
  // Finished cut inside its header, then the rest
  finishedSplitInHeader1: seal(serverHandshake, 0, 22, Buffer.concat([encryptedExtensions, finished.subarray(0, 2)])),
  finishedSplitInHeader2: seal(serverHandshake, 1, 22, finished.subarray(2)),
  // Finished cut right after its complete 4 byte header, the body in the next record
  finishedSplitInBody1: seal(serverHandshake, 0, 22, Buffer.concat([encryptedExtensions, finished.subarray(0, 4)])),
  finishedSplitInBody2: seal(serverHandshake, 1, 22, finished.subarray(4)),
  afterFinished: seal(serverApplication, 0, 23, Buffer.from('server data after Finished')),
  sequence64: seal(serverApplication, 0x0102030405060708n, 23, Buffer.from('sequence number test')),
  padded: seal(serverApplication, 0, 23, Buffer.from('padded'), 7),
  emptyContent: seal(serverApplication, 0, 23, EMPTY),
  versionInHeader0301: seal(serverApplication, 0, 23, Buffer.from('version in header'), 0, 0x0301),
  keyUpdate0: seal(serverApplication, 0, 23, Buffer.from('before update')),
  keyUpdate1: seal(serverApplication, 1, 22, keyUpdate),
  keyUpdate2: seal(gen1, 0, 23, Buffer.from('generation one')),
  keyUpdate3: seal(gen1, 1, 22, keyUpdate),
  keyUpdate4: seal(gen2, 0, 23, Buffer.from('generation two')),
  // KeyUpdate cut after its header: the body byte comes in the next record, still under the old key
  keyUpdateSplit1: seal(serverApplication, 0, 22, keyUpdate.subarray(0, 4)),
  keyUpdateSplit2: seal(serverApplication, 1, 22, keyUpdate.subarray(4)),
  keyUpdateSplit3: seal(gen1, 0, 23, Buffer.from('after split update')),
};

// all-zero inner plaintext (no content type at all): sealed by hand because seal() always appends the type byte
{
  const key = expandLabel(serverApplication, 'key', EMPTY, 16), iv = expandLabel(serverApplication, 'iv', EMPTY, 12);
  const header = Buffer.from([0x17, 3, 3, 0, 36]);
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(header);
  out.allZeroInner = Buffer.concat([cipher.update(Buffer.alloc(20)), cipher.final(), cipher.getAuthTag()]).toString('hex');
}
console.log(JSON.stringify(out, null, 1));
