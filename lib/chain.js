'use strict';

const assert = require('assert');
const sodium = require('sodium-universal');
const signatures = require('sodium-signatures');

const Buffer = require('buffer').Buffer;

const VERSION = 1;

const VERSION_SIZE = 1;
const PUBLIC_KEY_SIZE = 32;
const PRIVATE_KEY_SIZE = 64;
const SIGNATURE_SIZE = 64;
const EXPIRATION_SIZE = 8;
const NONCE_SIZE = 32;

const TBS_SIZE = VERSION_SIZE + PUBLIC_KEY_SIZE + EXPIRATION_SIZE + NONCE_SIZE;
const LINK_SIZE = TBS_SIZE + SIGNATURE_SIZE;

const HASH_SIZE = 32;
const HASH_KEY = Buffer.from('---hyperbloom---');

const MAX_CHAIN_LENGTH = 5;

function Chain(options) {
  this.options = options;

  assert(Buffer.isBuffer(this.options.root), 'options.root MUST be a Buffer');
  assert.equal(this.options.root.length, PUBLIC_KEY_SIZE,
               `options.root MUST have length=${PUBLIC_KEY_SIZE}`);

  this.root = this.options.root;
}
module.exports = Chain;

Chain.prototype._hash = function _hash(input) {
  const out = Buffer.alloc(HASH_SIZE);
  sodium.crypto_generichash(out, input, HASH_KEY);
  return out;
};

Chain.prototype.verify = function verify(chain, nonce, signature) {
  let pub = this.root;
  const now = Date.now() / 1e3;

  if (chain.length > MAX_CHAIN_LENGTH)
    throw new Error(`Maximum chain length is ${MAX_CHAIN_LENGTH}`);

  for (let i = 0; i < chain.length; i++) {
    const link = this.parseLink(chain[i]);

    if (link.version !== VERSION)
      throw new Error('Invalid Trust Link version');

    if (link.expiration < now)
      throw new Error(`Trust Link #${i} has expired`);

    const verified = signatures.verify(this._hash(link.tbs), link.signature,
                                       pub);
    if (!verified)
      throw new Error(`Failed to verify Trust Link #${i}`);

    pub = link.publicKey;
  }

  // Verify `signature`
  const verified = signatures.verify(nonce, signature, pub);
  if (!verified)
    throw new Error('Failed to verify signature');

  return true;
};

Chain.prototype.parseLink = function parseLink(link) {
  if (link.length !== LINK_SIZE)
    throw new Error('Invalid Trust Link size');

  let offset = 0;

  const version = link[offset];
  offset += VERSION_SIZE;

  const publicKey = link.slice(offset, offset + PUBLIC_KEY_SIZE);
  offset += PUBLIC_KEY_SIZE;

  const expiration = link.readDoubleBE(offset);
  offset += EXPIRATION_SIZE;

  const nonce = link.slice(offset, offset + NONCE_SIZE);
  offset += NONCE_SIZE;

  const signature = link.slice(offset);
  assert.equal(signature.length, SIGNATURE_SIZE);

  const tbs = link.slice(0, TBS_SIZE);

  return { version, publicKey, expiration, nonce, signature, tbs };
};

Chain.prototype.issueLink = function issueLink(options, privateKey) {
  assert.equal(typeof options, 'object', 'options MUST be an Object');

  assert(Buffer.isBuffer(options.publicKey),
         'options.publicKey MUST be a Buffer');
  assert.equal(options.publicKey.length, PUBLIC_KEY_SIZE,
               `options.publicKey MUST have length=${PUBLIC_KEY_SIZE}`);

  assert(Buffer.isBuffer(privateKey), 'privateKey MUST be a Buffer');
  assert.equal(privateKey.length, PRIVATE_KEY_SIZE,
               `privateKey MUST have length=${PRIVATE_KEY_SIZE}`);

  const link = Buffer.alloc(TBS_SIZE + SIGNATURE_SIZE);
  const tbs = link.slice(0, TBS_SIZE);

  let offset = 0;
  tbs[offset] = VERSION;
  offset += VERSION_SIZE;

  offset += options.publicKey.copy(tbs, offset, 0, PUBLIC_KEY_SIZE);

  let expiration;
  if (options.expiration instanceof Date) {
    expiration = options.expiration / 1000;
  } else {
    assert.equal(typeof options.expiration, 'number',
                 'options.expiration MUST be either a Date or a Number');
    expiration = options.expiration;
  }

  tbs.writeDoubleBE(expiration, offset);
  offset += EXPIRATION_SIZE;

  sodium.randombytes_buf(tbs.slice(offset, offset + NONCE_SIZE));
  offset += NONCE_SIZE;

  assert.equal(offset, tbs.length);

  const sign = signatures.sign(this._hash(tbs), privateKey);
  assert.equal(sign.length, SIGNATURE_SIZE);

  sign.copy(link, TBS_SIZE);

  return link;
};
