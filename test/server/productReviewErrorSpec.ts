/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import * as security from '../../lib/insecurity'
import * as db from '../../data/mongodb'
import { likeProductReviews } from '../../routes/likeProductReviews'
import { updateProductReviews } from '../../routes/updateProductReviews'
const expect = chai.expect
chai.use(sinonChai)

describe('productReviewErrors', () => {
  let req: any
  let res: any
  let json: sinon.SinonSpy

  beforeEach(() => {
    req = { body: { id: 'someReviewId', message: 'test' } }
    json = sinon.spy()
    res = { json: sinon.spy(), status: sinon.stub().returns({ json }) }
    sinon.stub(security.authenticatedUsers, 'from').returns({ data: { email: 'test@juice-sh.op' } } as any)
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should not expose error details when updating a review fails', async () => {
    sinon.stub(db.reviewsCollection, 'update').rejects(new Error('database exploded at /secret/path.ts:42'))

    updateProductReviews()(req, res, () => {})
    await new Promise(resolve => setImmediate(resolve))

    expect(res.status).to.have.been.calledWith(500)
    expect(json).to.have.been.calledOnceWithExactly({ error: 'Internal Server Error' })
  })

  it('should not expose error details when liking a review fails', async () => {
    const findOne = sinon.stub(db.reviewsCollection, 'findOne')
    findOne.onFirstCall().resolves({ likedBy: [] })
    findOne.onSecondCall().rejects(new Error('database exploded at /secret/path.ts:42'))
    sinon.stub(db.reviewsCollection, 'update').resolves({})

    await likeProductReviews()(req, res, () => {})

    expect(res.status).to.have.been.calledWith(500)
    expect(json).to.have.been.calledOnceWithExactly({ error: 'Internal Server Error' })
  })
})
