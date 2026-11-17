/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { containsWhereOperator, ordersCollection } from '../../data/mongodb'
const expect = chai.expect

describe('mongodb', () => {
  describe('containsWhereOperator', () => {
    it('detects top-level $where', () => {
      expect(containsWhereOperator({ $where: 'this.product == 1' })).to.equal(true)
    })

    it('detects $where nested in logical operators', () => {
      expect(containsWhereOperator({ $or: [{ _id: 'a' }, { $where: 'true' }] })).to.equal(true)
      expect(containsWhereOperator({ $and: [{ $nor: [{ $where: 'true' }] }] })).to.equal(true)
    })

    it('detects $where nested in field selectors', () => {
      expect(containsWhereOperator({ likedBy: { $elemMatch: { $where: 'true' } } })).to.equal(true)
    })

    it('detects function selectors', () => {
      expect(containsWhereOperator(() => true)).to.equal(true)
    })

    it('allows plain selectors', () => {
      expect(containsWhereOperator({ _id: 'abc' })).to.equal(false)
      expect(containsWhereOperator({ product: { $in: [1, '1'] } })).to.equal(false)
      expect(containsWhereOperator(undefined)).to.equal(false)
      expect(containsWhereOperator('abc')).to.equal(false)
    })
  })

  describe('collections', () => {
    for (const method of ['find', 'findOne', 'update', 'remove', 'count', 'ids']) {
      it(`reject $where selectors in ${method} without evaluating them`, async () => {
        await ordersCollection.insert({ orderId: 'spec-where' })
        for (const selector of [{ $where: 'global.marsdbWhereEvaluated = true' }, { $or: [{ $where: 'global.marsdbWhereEvaluated = true' }] }]) {
          try {
            await ordersCollection[method](selector, {})
            expect.fail(`${method} accepted a $where selector`)
          } catch (err) {
            expect((err as Error).message).to.equal('Unsupported query operator: $where')
          }
        }
        expect((global as any).marsdbWhereEvaluated).to.equal(undefined)
        await ordersCollection.remove({ orderId: 'spec-where' })
      })
    }

    it('still support equality selectors', async () => {
      await ordersCollection.insert({ orderId: 'spec-1' })
      const orders = await ordersCollection.find({ orderId: 'spec-1' })
      expect(orders).to.have.length(1)
      await ordersCollection.remove({ orderId: 'spec-1' })
    })
  })
})
