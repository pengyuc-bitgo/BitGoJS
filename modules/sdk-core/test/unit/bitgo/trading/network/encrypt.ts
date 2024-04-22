import assert from 'assert';
import crypto from 'crypto';
import { encryptRsaWithAesGcm } from '../../../../../src/bitgo/trading/network/encrypt';

describe('network encrypt', () => {
  const { publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const publicKeyString = publicKey
    .export({
      type: 'spki',
      format: 'pem',
    })
    .toString();

  it('should encrypt', async () => {
    const password = 'password';
    const encrypted = await encryptRsaWithAesGcm(publicKeyString, password);

    assert(encrypted);
  });
});
