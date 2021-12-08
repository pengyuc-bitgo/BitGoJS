/**
 * User webhook handler for v2 coins and tokens
 *
 * @prettier
 */

import * as _ from 'lodash';
import { BitGo } from '../bitgo';

import { validateParams } from '../common';
import { BaseCoin } from './baseCoin';

export interface AddOptions {
  url: string;
  type: string;
}

export interface RemoveOptions {
  url: string;
  type: string;
}

export interface ListNotificationsOptions {
  prevId?: string;
  limit?: number;
}

export interface SimulateOptions {
  webhookId: string;
  blockId: string;
}

export class Webhooks {
  private bitgo: BitGo;
  private baseCoin: BaseCoin;
  public constructor(bitgo: BitGo, baseCoin: BaseCoin) {
    this.bitgo = bitgo;
    this.baseCoin = baseCoin;
  }

  /**
   * Fetch list of user webhooks
   *
   * @returns {*}
   */
  async list(): Promise<any> {
    return await this.bitgo.get(this.baseCoin.url('/webhooks')).result();
  }

  /**
   * Add new user webhook
   *
   * @param params
   * @returns {*}
   */
  async add(params: AddOptions): Promise<any> {
    validateParams(params, ['url', 'type'], []);
    return await this.bitgo.post(this.baseCoin.url('/webhooks')).send(params).result();
  }

  /**
   * Remove user webhook
   *
   * @param params
   * @returns {*}
   */
  async remove(params: RemoveOptions): Promise<any> {
    validateParams(params, ['url', 'type'], []);

    return this.bitgo.del(this.baseCoin.url('/webhooks')).send(params).result();
  }

  /**
   * Fetch list of webhook notifications for the user
   *
   * @param params
   * @returns {*}
   */
  async listNotifications(params: ListNotificationsOptions = {}): Promise<any> {
    const queryProperties: (keyof ListNotificationsOptions)[] = [];
    if (params.prevId) {
      if (!_.isString(params.prevId)) {
        throw new Error('invalid prevId argument, expecting string');
      }
      queryProperties.push('prevId');
    }
    if (params.limit) {
      if (!_.isNumber(params.limit)) {
        throw new Error('invalid limit argument, expecting number');
      }
      queryProperties.push('limit');
    }
    const query = _.pick(params, queryProperties);

    return this.bitgo.get(this.baseCoin.url('/webhooks/notifications')).query(query).result();
  }

  /**
   * Simulate a user webhook
   *
   * @param params
   * @returns {*}
   */
  async simulate(params: SimulateOptions): Promise<any> {
    validateParams(params, ['webhookId', 'blockId'], []);

    const webhookId = params.webhookId;
    return this.bitgo
      .post(this.baseCoin.url('/webhooks/' + webhookId + '/simulate'))
      .send(params)
      .result();
  }
}
