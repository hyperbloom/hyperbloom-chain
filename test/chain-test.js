'use strict';

const assert = require('assert');
const sodium = require('sodium-universal');
const signatures = require('sodium-signatures');

const Chain = require('../');

describe('Chain', () => {
  let root;
  let chain;

  beforeEach(() => {
    root = signatures.keyPair();
    chain = new Chain({ root: root.publicKey });
  });

  it('should issue and parse link', () => {
    const desc = signatures.keyPair();

    const expiration = new Date(Date.now() + 1e9);

    const link = chain.issueLink({
      expiration: expiration,
      publicKey: desc.publicKey
    }, root.secretKey);

    const info = chain.parseLink(link);

    assert.equal(info.version, 1);
    assert.equal(info.expiration, expiration / 1000);
    assert(info.publicKey.equals(desc.publicKey));
  });

  it('should issue several links and verify chain', () => {
    const expiration = new Date(Date.now() + 1e9);

    let priv = root.secretKey;
    let pair;
    const links = [];
    for (let i = 0; i < 5; i++) {
      pair = signatures.keyPair();

      const link = chain.issueLink({
        expiration: expiration,
        publicKey: pair.publicKey
      }, priv);

      priv = pair.secretKey;

      links.push(link);
    }

    const nonce = Buffer.alloc(32);
    sodium.randombytes_buf(nonce);

    let sign = signatures.sign(nonce, priv);

    assert.doesNotThrow(() => {
      chain.verify(links, nonce, sign);
    });

    // Now use invalid signature
    sodium.randombytes_buf(nonce);
    assert.throws(() => {
      chain.verify(links, nonce, sign);
    }, /verify signature/);

    // Now use incomplete chain
    sign = signatures.sign(nonce, priv);

    links.splice(1, 1);
    assert.throws(() => {
      chain.verify(links, nonce, sign);
    }, /verify trust link #1/i);
  });
});
