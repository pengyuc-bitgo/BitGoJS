import { ECDSA } from '../../../../account-lib/mpc/tss';
import { ECDSAMethodTypes } from '../../../tss/ecdsa';
import { BackupKeyShare, CreateKeychainParamsBase } from '../baseTypes';
import { Key, SerializedKeyPair } from 'openpgp';

export type KeyShare = ECDSA.KeyShare;
export type DecryptableNShare = ECDSAMethodTypes.DecryptableNShare;

export type CreateEcdsaKeychainParams = CreateKeychainParamsBase & {
  userKeyShare: ECDSA.KeyShare;
  backupGpgKey: SerializedKeyPair<string>;
  backupKeyShare: BackupKeyShare;
  isThirdPartyBackup?: boolean;
  backupProvider?: string;
  bitgoPublicGpgKey: Key;
};

export type CreateEcdsaBitGoKeychainParams = Omit<CreateEcdsaKeychainParams, 'bitgoKeychain'>;

export type TrustBackupConstants = {
  trustBackupGPGPubKey: string;
};
