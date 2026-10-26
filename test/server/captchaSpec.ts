/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { CaptchaModel } from '../../models/captcha'
import { captchas, verifyCaptcha } from '../../routes/captcha'

const expect = chai.expect
chai.use(sinonChai)

describe('captcha', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { json: sinon.spy(), status: sinon.stub(), send: sinon.spy(), __: sinon.stub().returnsArg(0) }
    res.status.returns(res)
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('captchas', () => {
    it('should create and persist a math expression with its correct answer', async () => {
      const save = sinon.stub().resolves()
      const build = sinon.stub(CaptchaModel, 'build').returns({ save } as any)
      req = { app: { locals: { captchaId: 5 } } }

      await captchas()(req, res)

      const captcha = res.json.firstCall.args[0]
      expect(captcha.captchaId).to.equal(5)
      expect(captcha.captcha).to.match(/^\d{1,2}[*+-]\d{1,2}[*+-]\d{1,2}$/)
      expect(captcha.answer).to.equal(eval(captcha.captcha).toString()) // eslint-disable-line no-eval
      expect(build).to.have.been.calledWith(captcha)
      expect(save).to.have.been.calledWith()
      expect(req.app.locals.captchaId).to.equal(6)
    })
  })

  describe('verifyCaptcha', () => {
    it('should pass on to next middleware for correct answer', async () => {
      const findOne = sinon.stub(CaptchaModel, 'findOne').resolves({ answer: '42' } as any)
      req = { body: { captchaId: 1, captcha: '42' } }

      await verifyCaptcha()(req, res, next)

      expect(findOne).to.have.been.calledWith({ where: { captchaId: 1 } })
      expect(next).to.have.been.calledWithExactly()
      expect(res.status).to.have.not.been.calledWith(sinon.match.any)
    })

    it('should respond with 401 for wrong answer', async () => {
      sinon.stub(CaptchaModel, 'findOne').resolves({ answer: '42' } as any)
      req = { body: { captchaId: 1, captcha: '41' } }

      await verifyCaptcha()(req, res, next)

      expect(res.status).to.have.been.calledWith(401)
      expect(res.send).to.have.been.calledWith('Wrong answer to CAPTCHA. Please try again.')
      expect(next).to.have.not.been.calledWith(sinon.match.any)
    })

    it('should respond with 401 for unknown CAPTCHA id', async () => {
      sinon.stub(CaptchaModel, 'findOne').resolves(null)
      req = { body: { captchaId: 999, captcha: '42' } }

      await verifyCaptcha()(req, res, next)

      expect(res.status).to.have.been.calledWith(401)
    })

    it('should pass database errors to next', async () => {
      const error = new Error('DB down')
      sinon.stub(CaptchaModel, 'findOne').rejects(error)
      req = { body: { captchaId: 1, captcha: '42' } }

      await verifyCaptcha()(req, res, next)

      expect(next).to.have.been.calledWith(error)
    })
  })
})
