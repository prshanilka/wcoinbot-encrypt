
const { Buffer } = require('buffer');
const crypto = require('crypto');

require('dotenv').config();

const pb = process.env.PUB_KEY 
const encryptData = async (data) => {
  const publicKey = pb.replaceAll('\\n', '\n');
  try {
    const rsaPublicKey = await importPublicKey(publicKey);
    const symmetricKey = await generateSymmetricKey();
    const { ciphertext, iv, authTag } = await encryptWithSymmetricKey(symmetricKey, JSON.stringify(data));
    const encryptedSymmetricKey = await encryptSymmetricKey(rsaPublicKey, symmetricKey);

    return {
      encryptedData: Buffer.from(ciphertext).toString('base64'),
      encryptedSymmetricKey: Buffer.from(encryptedSymmetricKey).toString('base64'),
      iv: Buffer.from(iv).toString('base64'),
      authTag: Buffer.from(authTag).toString('base64'),
    };
  } catch (err) {
    console.error('ENCRYPTING ERROR', err);
  }

  return null;
};

const importPublicKey = (pem) => {

  const binaryDerString = Buffer.from(pem, 'base64').toString('binary');
  const binaryDer = Buffer.from(binaryDerString, 'binary');

  return crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['encrypt'],
  );
};

const generateSymmetricKey = async () => {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt'],
  );
};

const encryptWithSymmetricKey = async (key, data) => {
  const encodedData = Buffer.from(data, 'utf8');
  const iv = crypto.randomBytes(12); // Initialization vector
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    encodedData,
  );
  const encryptedBytes = Buffer.from(encryptedData);
  const tagLength = 16; // AES-GCM tag length is 16 bytes
  const ciphertext = encryptedBytes.slice(0, -tagLength);
  const authTag = encryptedBytes.slice(-tagLength);

  return { ciphertext, iv, authTag };
};

const encryptSymmetricKey = async (rsaPublicKey, symmetricKey) => {
  const exportedKey = await crypto.subtle.exportKey('raw', symmetricKey);
  const encryptedKey = await crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    rsaPublicKey,
    exportedKey,
  );
  return encryptedKey;
};
module.exports = {
  encryptData
};
