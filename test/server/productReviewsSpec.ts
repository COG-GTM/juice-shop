/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import * as db from '../../data/mongodb'
import { authenticatedUsers } from '../../lib/insecurity'
import { createProductReviews } from '../../routes/createProductReviews'
import { updateProductReviews } from '../../routes/updateProductReviews'
import { likeProductReviews } from '../../routes/likeProductReviews'
const expect = chai.expect
chai.use(sinonChai)

describe('productReviews', () => {
  const internalError = new Error('MarsDB internal failure at /juice-shop/node_modules/marsdb/dist/Collection.js:42')
  let req: any
  let res: any

  beforeEach(() => {
    req = { params: { id: '1' }, body: { id: 'abc', message: 'Great', author: 'admin@juice-sh.op' }, headers: {}, cookies: {} }
    res = { json: sinon.spy() }
    res.status = sinon.stub().returns(res)
  })

  afterEach(() => {
    sinon.restore()
  })

  const expectNoErrorDetails = () => {
    expect(res.status).to.have.been.calledWith(500)
    expect(res.json).to.have.been.calledOnceWith('Unexpected server error')
    expect(JSON.stringify(res.json.firstCall.args)).to.not.include('MarsDB')
  }

  it('createProductReviews does not expose error details when inserting fails', async () => {
    sinon.stub(db.reviewsCollection, 'insert').rejects(internalError)

    await createProductReviews()(req, res)

    expectNoErrorDetails()
  })

  it('updateProductReviews does not expose error details when updating fails', async () => {
    sinon.stub(db.reviewsCollection, 'update').rejects(internalError)

    updateProductReviews()(req, res, sinon.spy())
    await new Promise(resolve => setImmediate(resolve))

    expectNoErrorDetails()
  })

  it('likeProductReviews does not expose error details when saving the like fails', async () => {
    sinon.stub(authenticatedUsers, 'from').returns({ data: { email: 'jim@juice-sh.op' } } as any)
    const findOne = sinon.stub(db.reviewsCollection, 'findOne')
    findOne.onFirstCall().resolves({ likedBy: [] })
    findOne.onSecondCall().resolves({ likedBy: [] })
    const update = sinon.stub(db.reviewsCollection, 'update')
    update.onFirstCall().resolves({ modified: 1 })
    update.onSecondCall().rejects(internalError)

    await likeProductReviews()(req, res, sinon.spy())

    expectNoErrorDetails()
  })
})
