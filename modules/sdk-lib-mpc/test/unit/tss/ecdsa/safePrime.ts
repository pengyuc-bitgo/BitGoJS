import 'should';
import { bitLength, isProbablyPrime } from 'bigint-crypto-utils';
import { generateSafePrime } from '../../../../src';
import { loadWebAssembly } from '@bitgo/sdk-opensslbytes';

const openSSLBytes = loadWebAssembly().buffer;

describe('safePrime', function () {
  it('should generate a safe prime number of a certain bitLength', async function () {
    const safePrime = await generateSafePrime(512, openSSLBytes);
    bitLength(safePrime).should.equal(512);
  });

  it('should generate a safe prime number', async function () {
    const safePrime = await generateSafePrime(512, openSSLBytes);
    let isPrime = await isProbablyPrime(safePrime);
    isPrime.should.be.true();
    isPrime = await isProbablyPrime((safePrime - BigInt(1)) / BigInt(2));
    isPrime.should.be.true();
  });
});
