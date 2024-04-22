import crypto from 'crypto';

async function computeKey(pass: string | Buffer, salt: Buffer): Promise<Buffer> {
  let resolvePromise: (result: Buffer) => void;
  let rejectPromise: (reject: unknown) => void;

  const promise: Promise<Buffer> = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  crypto.pbkdf2(pass, salt, 200000, 32, 'sha256', (err, derivedKey) => {
    if (err !== null) {
      rejectPromise(err);
    } else {
      resolvePromise(derivedKey);
    }
  });

  return promise;
}

async function encryptAesGcm(secret: string | Buffer, text: string): Promise<string> {
  const version = Buffer.alloc(1, 1);

  const salt = crypto.randomBytes(16);

  const iv = crypto.randomBytes(12);
  const key = await computeKey(secret, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

  const authTag = cipher.getAuthTag();

  return Buffer.concat([version, salt, iv, encrypted, authTag]).toString('base64');
}

function encryptRsa(publicKey: string, text: string): string {
  const key = crypto.createPublicKey(publicKey);
  const encryptedData = crypto.publicEncrypt(
    {
      key,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(text)
  );

  return encryptedData.toString('base64');
}

export function decryptRsa(publicKey: string, text: string): string {
  const key = crypto.createPublicKey(publicKey);
  const encryptedData = crypto.publicDecrypt(
    {
      key,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(text)
  );

  return encryptedData.toString('base64');
}

/**
 * Provided an X.509/ OpenSSL PEM public key, and a string of text to encrypt,
 * This function will
 * 1. Generate a random 256-bit key
 * 2. Encrypt the text using AES-GCM with the generated key
 * 3. Encrypt the generated key using RSA-OAEP with the provided public key
 * 4. Return the encrypted key and the encrypted text in the format `${encryptedKey}\n${encryptedText}`
 *
 * @param callWithRetryServiceContext - service dependent context @see {@link CallWithRetryServiceContext}
 * @param callWithRetryCallContext - call dependent context @see {@link CallWithRetryCallContext<Params, Response>}
 * @params callWithRetryParams - params to invoke the call @see {@link CallWithRetryParams<Params>}
 * @returns TE.TaskEither<Error, Response['body']> from call
 *
 * @example
 * const publicKey = '-----BEGIN PUBLIC KEY-----\n.....\n-----END PUBLIC KEY-----';
 * const text = 'This text contains sensitive information';
 * const encrypted = await encryptRsaWithAesGcm(publicKey, text);
 */
export async function encryptRsaWithAesGcm(publicKey: string, text: string): Promise<string> {
  const gcmKey = crypto.randomBytes(32).toString('base64');

  const encrypted = await encryptAesGcm(gcmKey, text);

  return `${encryptRsa(publicKey, Buffer.from(gcmKey).toString('base64'))}\n${encrypted}`;
}
