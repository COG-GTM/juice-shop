/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { reviewsCollection } from '../../data/mongodb'
import { createProductReviews } from '../../routes/createProductReviews'
const expect = chai.expect
chai.use(sinonChai)

describe('createProductReviews', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { params: { id: '1' }, body: { message: 'Great juice!', author: 'jim@juice-sh.op' }, headers: {}, cookies: {} }
    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
  })

  afterEach(() => {
    sinon.restore()
  })

  it('responds with 201 when the review was stored', async () => {
    sinon.stub(reviewsCollection, 'insert').resolves({})

    await createProductReviews()(req, res)

    expect(res.status).to.have.been.calledWith(201)
    expect(res.json).to.have.been.calledWith({ status: 'success' })
  })

  it('responds with a generic 500 instead of the internal error when storing fails', async () => {
    sinon.stub(reviewsCollection, 'insert').rejects(new Error('MarsDB write failed: collection "reviews" index corrupt'))

    await createProductReviews()(req, res)

    expect(res.status).to.have.been.calledWith(500)
    expect(res.json).to.have.been.calledWith('Internal Server Error')
    expect(JSON.stringify(res.json.firstCall.args[0])).to.not.contain('MarsDB')
  })
})
