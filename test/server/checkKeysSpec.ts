/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import type { Request, Response } from 'express'
import { checkKeys } from '../../routes/checkKeys'
import * as utils from '../../lib/utils'
const expect = chai.expect
chai.use(sinonChai)

describe('checkKeys', () => {
  it('responds with a generic 500 message instead of the error details', async () => {
    const req = {
      get body () {
        throw new Error('SQLITE_ERROR at /juice-shop/build/routes/checkKeys.js:16:30')
      }
    } as unknown as Request
    const json = sinon.spy()
    const res = { status: sinon.stub().returns({ json }) } as unknown as Response

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(500)
    expect(json).to.have.been.calledOnceWithExactly(utils.unexpectedErrorMessage)
  })
})
