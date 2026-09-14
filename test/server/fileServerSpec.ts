/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { servePublicFiles } from '../../routes/fileServer'
import * as security from '../../lib/insecurity'
import * as mongodb from '../../data/mongodb'
import { type Challenge } from 'data/types'
const expect = chai.expect
chai.use(sinonChai)

describe('fileServer', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    req = { params: {}, query: {}, headers: {}, cookies: {} }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should serve PDF files from folder /ftp', () => {
    req.params.file = 'test.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]test\.pdf/))
  })

  it('should deny order confirmation PDFs to anonymous requests', async () => {
    req.params.file = 'order_1234-0123456789abcdef.pdf'

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should deny order confirmation PDFs of other customers', async () => {
    const token = security.authorize({ data: { email: 'a@juice-sh.op' } })
    req.headers.cookie = 'token=' + token
    req.params.file = 'order_1234-0123456789abcdef.pdf'
    sinon.stub(mongodb.ordersCollection, 'findOne').resolves({ orderId: '1234-0123456789abcdef', email: 'b@j**c*-sh.*p' })

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should deny order confirmation PDFs for an unknown order', async () => {
    const token = security.authorize({ data: { email: 'a@juice-sh.op' } })
    req.headers.cookie = 'token=' + token
    req.params.file = 'order_1234-0123456789abcdef.pdf'
    sinon.stub(mongodb.ordersCollection, 'findOne').resolves(null)

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should deny order confirmation PDFs with a matching email but a different hash prefix', async () => {
    const email = 'a@juice-sh.op'
    const token = security.authorize({ data: { email } })
    req.headers.cookie = 'token=' + token
    req.params.file = 'order_zzzz-0123456789abcdef.pdf'
    sinon.stub(mongodb.ordersCollection, 'findOne').resolves({ orderId: 'zzzz-0123456789abcdef', email: '*@j**c*-sh.*p' })

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should use a valid bearer token when the cookie token is invalid', async () => {
    const email = 'a@juice-sh.op'
    const token = security.authorize({ data: { email } })
    const orderId = security.hash(email).slice(0, 4) + '-0123456789abcdef'
    req.headers.cookie = 'token=invalid-token'
    req.headers.authorization = 'Bearer ' + token
    req.params.file = 'order_' + orderId + '.pdf'
    sinon.stub(mongodb.ordersCollection, 'findOne').resolves({ orderId, email: '*@j**c*-sh.*p' })

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]order_/))
  })

  it('should deny malformed cookie tokens without throwing', async () => {
    req.headers.cookie = 'token=%E0%A4%A'
    req.params.file = 'order_1234-0123456789abcdef.pdf'

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should serve order confirmation PDFs to the customer who placed the order', async () => {
    const email = 'a@juice-sh.op'
    const token = security.authorize({ data: { email } })
    const orderId = security.hash(email).slice(0, 4) + '-0123456789abcdef'
    req.headers.cookie = 'token=' + token
    req.params.file = 'order_' + orderId + '.pdf'
    sinon.stub(mongodb.ordersCollection, 'findOne').resolves({ orderId, email: '*@j**c*-sh.*p' })

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]order_/))
  })

  it('should serve Markdown files from folder /ftp', () => {
    req.params.file = 'test.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]test\.md/))
  })

  it('should serve incident-support.kdbx files from folder /ftp', () => {
    req.params.file = 'incident-support.kdbx'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]incident-support\.kdbx/))
  })

  it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for disallowed file type', () => {
    req.params.file = 'nice.try'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should solve "directoryListingChallenge" when requesting acquisitions.md', () => {
    challenges.directoryListingChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'acquisitions.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]acquisitions\.md/))
    expect(challenges.directoryListingChallenge.solved).to.equal(true)
  })

  it('should solve "easterEggLevelOneChallenge" when requesting eastere.gg with Poison Null Byte attack', () => {
    challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'eastere.gg%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]eastere\.gg/))
    expect(challenges.easterEggLevelOneChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenDevBackupChallenge" when requesting package.json.bak with Poison Null Byte attack', () => {
    challenges.forgottenDevBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'package.json.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]package\.json\.bak/))
    expect(challenges.forgottenDevBackupChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenBackupChallenge" when requesting coupons_2013.md.bak with Poison Null Byte attack', () => {
    challenges.forgottenBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'coupons_2013.md.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]coupons_2013\.md\.bak/))
    expect(challenges.forgottenBackupChallenge.solved).to.equal(true)
  })

  it('should solve "misplacedSignatureFileChallenge" when requesting suspicious_errors.yml with Poison Null Byte attack', () => {
    challenges.misplacedSignatureFileChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'suspicious_errors.yml%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]suspicious_errors\.yml/))
    expect(challenges.misplacedSignatureFileChallenge.solved).to.equal(true)
  })
})
