/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { ImageCaptchaModel } from '../../models/imageCaptcha'
import * as security from '../../lib/insecurity'
import { imageCaptchas, verifyImageCaptcha } from '../../routes/imageCaptcha'

const expect = chai.expect
chai.use(sinonChai)

describe('imageCaptcha', () => {
  const token = 'imageCaptchaSpecToken'
  let req: any
  let res: any
  let next: any

  before(() => {
    security.authenticatedUsers.put(token, { data: { id: 7 } } as any)
  })

  beforeEach(() => {
    req = { headers: { authorization: `Bearer ${token}` }, body: {} }
    res = { json: sinon.spy(), status: sinon.stub(), send: sinon.spy(), __: sinon.stub().returnsArg(0) }
    res.status.returns(res)
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('imageCaptchas', () => {
    it('should create and persist an SVG CAPTCHA for the logged-in user', async () => {
      const save = sinon.stub().resolves()
      const build = sinon.stub(ImageCaptchaModel, 'build').returns({ save } as any)

      await imageCaptchas()(req, res)

      const captcha = res.json.firstCall.args[0]
      expect(captcha.UserId).to.equal(7)
      expect(captcha.image).to.match(/^<svg/)
      expect(captcha.answer).to.have.lengthOf(5)
      expect(build).to.have.been.calledWith(captcha)
      expect(save).to.have.been.calledWith()
    })

    it('should respond with 401 when no user is logged in', async () => {
      const build = sinon.stub(ImageCaptchaModel, 'build')
      req.headers = {}

      await imageCaptchas()(req, res)

      expect(res.status).to.have.been.calledWith(401)
      expect(res.send).to.have.been.calledWith('You need to be logged in to request a CAPTCHA.')
      expect(build).to.have.not.been.calledWith(sinon.match.any)
    })

    it('should respond with 400 when CAPTCHA cannot be persisted', async () => {
      sinon.stub(ImageCaptchaModel, 'build').returns({ save: sinon.stub().rejects(new Error('DB down')) } as any)

      await imageCaptchas()(req, res)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.send).to.have.been.calledWith('Unable to create CAPTCHA. Please try again.')
    })
  })

  describe('verifyImageCaptcha', () => {
    it('should look up the most recent CAPTCHA of the logged-in user', async () => {
      const findAll = sinon.stub(ImageCaptchaModel, 'findAll').resolves([])

      await verifyImageCaptcha()(req, res, next)

      expect(findAll).to.have.been.calledWith(sinon.match({ limit: 1, where: sinon.match({ UserId: 7 }), order: [['createdAt', 'DESC']] }))
    })

    it('should pass on to next middleware when user has no recent CAPTCHA', async () => {
      sinon.stub(ImageCaptchaModel, 'findAll').resolves([])

      await verifyImageCaptcha()(req, res, next)

      expect(next).to.have.been.calledWithExactly()
    })

    it('should pass on to next middleware for correct answer', async () => {
      sinon.stub(ImageCaptchaModel, 'findAll').resolves([{ answer: 'aB3dE' }] as any)
      req.body.answer = 'aB3dE'

      await verifyImageCaptcha()(req, res, next)

      expect(next).to.have.been.calledWithExactly()
    })

    it('should respond with 401 for wrong answer', async () => {
      sinon.stub(ImageCaptchaModel, 'findAll').resolves([{ answer: 'aB3dE' }] as any)
      req.body.answer = 'wrong'

      await verifyImageCaptcha()(req, res, next)

      expect(res.status).to.have.been.calledWith(401)
      expect(res.send).to.have.been.calledWith('Wrong answer to CAPTCHA. Please try again.')
      expect(next).to.have.not.been.calledWith(sinon.match.any)
    })

    it('should respond with 401 on database errors', async () => {
      sinon.stub(ImageCaptchaModel, 'findAll').rejects(new Error('DB down'))

      await verifyImageCaptcha()(req, res, next)

      expect(res.status).to.have.been.calledWith(401)
      expect(res.send).to.have.been.calledWith('Something went wrong while submitting CAPTCHA. Please try again.')
    })
  })
})
