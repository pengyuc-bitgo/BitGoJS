import { TransactionExplanation as BaseTransactionExplanation, TransactionType } from '@bitgo/sdk-core';
import { SuiObjectRef } from './mystenlab/types';
import { MoveCallCommand, Transaction as ProgrammableTransaction } from './mystenlab/builder';

export enum SuiTransactionType {
  Pay = 'Pay',
  PaySui = 'PaySui',
  PayAllSui = 'PayAllSui',
  AddStake = 'AddStake',
  WithdrawStake = 'WithdrawStake',
}

export interface TransactionExplanation extends BaseTransactionExplanation {
  type: TransactionType;
}

export type ObjectId = string;
export type SuiAddress = string;

export type SuiJsonValue = boolean | number | string | SuiObjectRef | SharedObjectRef | CallArg | Array<unknown>;

/**
 * Kind of a TypeTag which is represented by a Move type identifier.
 */
export type StructTag = {
  address: string;
  module: string;
  name: string;
  typeParams: TypeTag[];
};

/**
 * Sui TypeTag object. A decoupled `0x...::module::Type<???>` parameter.
 */
export type TypeTag =
  | { bool: null }
  | { u8: null }
  | { u64: null }
  | { u128: null }
  | { address: null }
  | { signer: null }
  | { vector: TypeTag }
  | { struct: StructTag }
  | { u16: null }
  | { u32: null }
  | { u256: null };

/**
 * A reference to a shared object.
 */
export type SharedObjectRef = {
  /** Hex code as string representing the object id */
  objectId: string;

  /** The version the object was shared at */
  initialSharedVersion: number;

  /** Whether reference is mutable */
  mutable: boolean;
};

export type ImmOrOwnedArg = { ImmOrOwned: SuiObjectRef };
export type SharedArg = { Shared: SharedObjectRef };
export type ObjectArg = ImmOrOwnedArg | SharedArg;
export type ObjVecArg = { ObjVec: ArrayLike<ObjectArg> };
/**
 * An object argument.
 */
export type CallArg = { Pure: ArrayLike<number> } | { Object: ObjectArg } | ObjVecArg;

export type TxDetails = PayTxDetails | PaySuiTxDetails | PayAllSuiTxDetails | MoveCallTxDetails;

export interface PayTxDetails {
  Pay: {
    coins: SuiObjectRef[];
    recipients: string[];
    amounts: number[];
  };
}

export interface PaySuiTxDetails {
  PaySui: {
    coins: SuiObjectRef[];
    recipients: string[];
    amounts: number[];
  };
}

export interface PayAllSuiTxDetails {
  PayAllSui: {
    coins: SuiObjectRef[];
    recipient: string;
  };
}

// ========== Move Call Tx ===========

/**
 * Transaction type used for calling Move modules' functions.
 * Should be crafted carefully, because the order of type parameters and
 * arguments matters.
 */
export interface MoveCallTxDetails {
  Call: {
    package: SuiAddress;
    module: string;
    function: string;
    typeArguments: TypeTag[];
    arguments: SuiJsonValue[];
  };
}

export interface GasData {
  owner: string; // Gas Object's owner
  price: number;
  budget: number;
  payment?: SuiObjectRef;
}

/**
 * The transaction data returned from the toJson() function of a transaction
 */
export interface TxData {
  id?: string;
  kind: { Single: TxDetails };
  sender: string;
  gasData: GasData;
}

export interface PayTx {
  coins: SuiObjectRef[];
  recipients: string[];
  amounts: number[];
}

export interface MoveCallTx {
  package: SuiAddress;
  module: string;
  function: string;
  typeArguments: TypeTag[];
  arguments: SuiJsonValue[];
}

export interface BitGoSuiTransaction<T = ProgrammableTransaction> {
  type: SuiTransactionType;
  sender: string;
  tx: T;
  gasData: GasData;
}

// Staking DTOs
export interface RequestAddStake {
  coins: SuiObjectRef[];
  amount: number;
  validatorAddress: SuiAddress;
}

export interface RequestWithdrawStake {
  stakedSuiObjectId: ObjectId;
  amount: number;
}

/**
 * Method names for the transaction method. Names change based on the type of transaction e.g 'request_add_delegation_mul_coin' for the staking transaction
 */
export enum MethodNames {
  /**
   * Add stake to a validator's staking pool.
   *
   * @see https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/docs/sui_system.md#function-request_add_stake
   */
  RequestAddStake = 'request_add_stake',
  /**
   * Add stake to a validator's staking pool using multiple coins..
   *
   * @see https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/docs/sui_system.md#function-request_add_stake_mul_coin
   */
  RequestAddStakeMulCoin = 'request_add_stake_mul_coin',
  /**
   * Withdraw some portion of a stake from a validator's staking pool.
   *
   * @see https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/docs/sui_system.md#function-request_withdraw_stake
   */
  RequestWithdrawStake = 'request_withdraw_stake',
}

/**
 * Sui modules
 */
export enum ModulesNames {
  /**
   * Module 0x2::sui_system
   *
   * @see https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/docs/sui_system.md
   */
  SuiSystem = 'sui_system',
}
