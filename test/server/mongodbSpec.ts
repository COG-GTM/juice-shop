/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { containsCodeSelector, reviewsCollection } from '../../data/mongodb'
const expect = chai.expect

describe('mongodb', () => {
  const marker = 'marsdbWhereExecuted'

  afterEach(() => {
    delete (globalThis as any)[marker]
  })

  it('flags $where at any nesting depth and function selectors', () => {
    expect(containsCodeSelector({ $where: 'true' })).to.equal(true)
    expect(containsCodeSelector({ _id: { $where: 'true' } })).to.equal(true)
    expect(containsCodeSelector({ $or: [{ product: 1 }, { $where: 'true' }] })).to.equal(true)
    expect(containsCodeSelector(() => true)).to.equal(true)
  })

  it('accepts plain equality and operator selectors', () => {
    expect(containsCodeSelector({ product: 1 })).to.equal(false)
    expect(containsCodeSelector({ _id: 'abc', author: 'a@b.c' })).to.equal(false)
    expect(containsCodeSelector({ _id: { $ne: -1 } })).to.equal(false)
    expect(containsCodeSelector(undefined)).to.equal(false)
  })

  for (const method of ['find', 'findOne', 'count', 'update', 'remove'] as const) {
    it(`rejects a $where selector in ${method} without executing it`, async () => {
      const selector = { _id: { $where: `globalThis.${marker} = true` } }
      const args: unknown[] = method === 'update' ? [selector, { $set: { message: 'x' } }] : [selector]
      let error: Error | undefined
      try {
        await (reviewsCollection as any)[method](...args)
      } catch (err) {
        error = err as Error
      }
      expect(error?.message).to.equal('JavaScript selectors ($where) are not allowed')
      expect((globalThis as any)[marker]).to.equal(undefined)
    })
  }

  it('still runs plain selectors', async () => {
    const _id = await reviewsCollection.insert({ product: 4242, message: 'm', author: 'a@b.c', likesCount: 0, likedBy: [] })
    const reviews = await reviewsCollection.find({ product: 4242 })
    expect(reviews.map((r: { _id: string }) => r._id)).to.deep.equal([_id])
    await reviewsCollection.remove({ _id })
  })
})
