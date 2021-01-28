import { KeyPair } from '../../../src/coin/cspr';

export const ACCOUNT_FROM_SEED = {
  seed: 'cd1eac3bc52716f3177bc7f9c5d7de10b98c74c6c1ace2c874e0e09f47469023',
  accountHash: 'f068b89fbd03587a1bedb79ead98d1c8f4c2f3181a6eddbc10ae98d0dd874e94',
  xPublicKey:
    'xpub661MyMwAqRbcEzDE55AJUGhMKJJ2nw1hnF1fBoaw2T47DQsJzhLXbygpggTXpkWPVENnzPYbgLRVPtmwjQQAiY9AbHX5Ys4KpLRuFtVNFtC',
  xPrivateKey:
    'xprv9s21ZrQH143K2W8ky3dJ78kcmGTYPUHrR264PRBKU7X8LcYATA2H4BNLqNDYi4mhSiJXRUAttHaJYBynN7iMU2vkJjEG4SK6xVJkymYUEyG',
  publicKey: '03DC13CBBF29765C7745578D9E091280522F37684EF0E400B86B1C409BC454F1F3',
  privateKey: '353ED4C9DB2A13B8EB319618EAF7A61DC5AB74AF79020C9C21D06E768A6D3E24',
};

export const ACCOUNT_1 = {
  accountHash: 'fa1e526fdfa0065c84ec3cf1f88ddcd05c5a22160332e99954891c4956fef6a5',
  publicKey: '02DCAB323A8F9A31D3095FAAA611139A70DEE2D326C8DB8BD94FBDDAD202B6B740',
  privateKey: 'D6EB5C34E5A4815513DB7A629A235B820762D56DC7BC0D06FB64ACB4120C5FA4',
};

export const ACCOUNT_2 = {
  accountHash: '9884fd0a8a9dd71fe6820e2507bd847cbcae8003195120d472294b0ea77f4435',
  publicKey: '022FC98A97E780944B08E365A27BC8F181770FE431181667128B604A541E1C9CC7',
  privateKey: '61FEFC7C21737AF8081FEF8E377C3B4660C0520998DC6AFD79884770EE4CAE96',
};

export const ACCOUNT_3 = {
  accountHash: 'fbba1c5277d27546060925b80c780aa708cf12bcb8a4c0c34ce22af15de7ac9c',
  publicKey: '021a08bb34f8a5d978ac8dbecabd4b0e8edf2e1cf1800bade6de3baa4dddfe3449',
  privateKey: '06a8f3e2bf2d9104c61af9ea0d72e36bab0730ecccf94817e5b746332d849c0b',
};

export const ROOT_ACCOUNT = {
  accountHash: 'd632e4ed12fd838e361bcd1982da9a43b903631be38b3ed698559603c2e9faf6',
  publicKey: '025360ED570343B858C860801354EAAE4CDCD390EB3215A1C8C623CC55B63E442B',
  privateKey: '8161C06516BE5ECC0A9ED4F400D89A1F734FC604CD958141C371632592E8B0E0',
};

export const GAS_LIMIT = '123';

export const FEE = { gasLimit: '10000000', gasPrice: '10' };

export const INVALID_SHORT_KEYPAIR_KEY = '82A34E';

export const INVALID_LONG_KEYPAIR_PRV = ACCOUNT_FROM_SEED.privateKey + 'F1';

export const INVALID_PRIVATE_KEY_ERROR_MESSAGE = 'Unsupported private key';

export const INVALID_PUBLIC_KEY_ERROR_MESSAGE = 'Unsupported public key:';

export const ERROR_INVALID_ADDRESS = 'Invalid address';

export const ERROR_REPEATED_SIGNATURE = 'Repeated sign';

export const ERROR_INVALID_AMOUNT = 'Invalid amount';

export const ERROR_MISSING_TRANSFER_TARGET = 'Invalid transaction: missing to';

export const ERROR_MISSING_TRANSFER_AMOUNT = 'Invalid transaction: missing amount';

export const VALID_ADDRESS = '025360ED570343B858C860801354EAAE4CDCD390EB3215A1C8C623CC55B63E442B';

export const INVALID_ADDRESS = '608e43c3gg3f44200ec59Y7ZXC461d3e5aa4e823c595848a5d280f831ce8de302';

export const INVALID_ADDRESS_EMPTY = '';

export const INVALID_ADDRESS_EMPTY_W_SPACES = '   ';

export const INVALID_KEYPAIR_PRV = new KeyPair({
  prv: '8CAA00AE63638B0542A304823D66D96FF317A576F692663DB2F85E60FAB2590C',
});

export const KEYPAIR_PRV = new KeyPair({
  prv: '353ED4C9DB2A13B8EB319618EAF7A61DC5AB74AF79020C9C21D06E768A6D3E24',
});

export const WALLET_SIGNED_TRANSACTION = '';

export const SECP256K1_PREFIX = '02';

export const EXTERNAL_SIGNATURE = {
  publicKey: '02c436d422737f2470b92882ae6268cf4fb3547a8837fba778aea0bc42580a30a1',
  signature:
    '0208437432526364c9fc59313c9eec1e7070de68d96922b66c56a9f97503574ac56b1807d7bf580d1f9d2461a4fe6314c6e2e037b1457ad2a5590bf2398fb9d936',
};
