/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { authenticatedUsers } from '../../lib/insecurity'
import { orderConfirmationPath, orderConfirmationsDir, serveOrderConfirmation } from '../../routes/orderConfirmation'
import { type UserModel } from '../../models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('orderConfirmation', () => {
  const orderId = '1a2b-0123456789abcdef'
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    req = { params: { orderId }, headers: { authorization: 'Bearer owner-token' } }
    next = sinon.spy()
    authenticatedUsers.put('owner-token', { data: { id: 4711 } as unknown as UserModel })
    authenticatedUsers.put('other-token', { data: { id: 4712 } as unknown as UserModel })
    fs.mkdirSync(path.dirname(orderConfirmationPath(4711, orderId)), { recursive: true })
    fs.writeFileSync(orderConfirmationPath(4711, orderId), '%PDF')
  })

  afterEach(() => {
    fs.rmSync(path.join(orderConfirmationsDir, '4711'), { recursive: true, force: true })
  })

  it('should store order confirmations outside of the public /ftp folder', () => {
    expect(orderConfirmationPath(4711, orderId)).to.not.match(/[/\\]ftp[/\\]/)
  })

  it('should serve the order confirmation to the customer who placed the order', () => {
    serveOrderConfirmation()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(orderConfirmationPath(4711, orderId))
  })

  it('should reject unauthenticated requests', () => {
    req.headers = {}

    serveOrderConfirmation()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(401)
  })

  it('should not serve the order confirmation of another customer', () => {
    req.headers.authorization = 'Bearer other-token'

    serveOrderConfirmation()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(404)
  })

  it('should reject malformed order ids', () => {
    req.params.orderId = '../../../package.json'

    serveOrderConfirmation()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(400)
  })
})
