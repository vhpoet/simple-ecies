'use strict';

var Promise = require('bluebird');
var secp256k1 = require('secp256k1/elliptic');
var crypto = require('crypto');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

/**
 * Compute the public key for a given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Buffer} A 65-byte public key.
 * @function
 */
function getPublic(privateKey) {
  assert(privateKey.length === 32, "Bad private key");
  // See https://github.com/wanderer/secp256k1-node/issues/46
  var compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.publicKeyConvert(compressed, false);
}

function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}

function aes256CbcEncrypt(iv, key, plaintext) {
  var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(plaintext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

/**
 * Derive shared secret for given private and public keys.
 * @param {Buffer} privateKeyA - Sender's private key (32 bytes)
 * @param {Buffer} publicKeyB - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived
 * shared secret (Px, 32 bytes) and rejects on bad key.
 */
function derive(privateKeyA, publicKeyB) {
  return new Promise(function(resolve) {
    resolve(secp256k1.ecdh(publicKeyB, privateKeyA));
  });
}

/**
 * Input/output structure for ECIES operations.
 * @typedef {Object} Ecies
 * @property {Buffer} iv - Initialization vector (16 bytes)
 * @property {Buffer} ephemPublicKey - Ephemeral public key (65 bytes)
 * @property {Buffer} ciphertext - The result of encryption (variable size)
 * @property {Buffer} mac - Message authentication code (32 bytes)
 */

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also
 * specify initialization vector (16 bytes) and ephemeral private key
 * (32 bytes) to get deterministic results.
 * @return {Promise.<Ecies>} - A promise that resolves with the ECIES
 * structure on successful encryption and rejects on failure.
 */
exports.encrypt = function(publicKeyTo, msg, opts) {
  opts = opts || {};
  // Tmp variable to save context from flat promises;
  var ephemPublicKey;
  return new Promise(function(resolve) {
    var ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  }).then(function(Px) {
    var hash = sha512(Px);
    var iv = opts.iv || crypto.randomBytes(16);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
    var dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
    var mac = hmacSha256(macKey, dataToMac);
    return {
      iv: iv,
      ephemPublicKey: ephemPublicKey,
      ciphertext: ciphertext,
      mac: mac
    };
  });
};

/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Ecies} opts - ECIES structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
exports.decrypt = function(privateKey, opts) {
  return derive(privateKey, opts.ephemPublicKey).then(function(Px) {
    var hash = sha512(Px);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var dataToMac = Buffer.concat([
      opts.iv,
      opts.ephemPublicKey,
      opts.ciphertext
    ]);
    var realMac = hmacSha256(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), "Bad MAC");
    return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  });
};

exports.publicKeyConvert = secp256k1.publicKeyConvert;
