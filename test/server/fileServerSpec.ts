/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as db from '../../data/mongodb'
import { servePublicFiles } from '../../routes/fileServer'
import { type Challenge } from 'data/types'
const expect = chai.expect
chai.use(sinonChai)

describe('fileServer', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  before(() => {
    security.authenticatedUsers.put('fileServerSpecAdmin', { data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } } as any)
    security.authenticatedUsers.put('fileServerSpecJim', { data: { id: 2, email: 'jim@juice-sh.op', role: 'customer' } } as any)
    security.authenticatedUsers.put('fileServerSpecBender', { data: { id: 3, email: 'bender@juice-sh.op', role: 'customer' } } as any)
  })

  afterEach(() => {
    sinon.restore()
  })

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    req = { params: {}, query: {}, cookies: {}, headers: { authorization: 'Bearer fileServerSpecAdmin' } }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  it('should serve PDF files from folder /ftp', async () => {
    req.params.file = 'test.pdf'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]test\.pdf/))
  })

  it('should serve Markdown files from folder /ftp', async () => {
    req.params.file = 'test.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]test\.md/))
  })

  it('should serve incident-support.kdbx files from folder /ftp', async () => {
    req.params.file = 'incident-support.kdbx'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]incident-support\.kdbx/))
  })

  it('should raise error for slashes in filename', async () => {
    req.params.file = '../../../../nice.try'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for disallowed file type', async () => {
    req.params.file = 'nice.try'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should solve "directoryListingChallenge" when requesting acquisitions.md', async () => {
    challenges.directoryListingChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'acquisitions.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]acquisitions\.md/))
    expect(challenges.directoryListingChallenge.solved).to.equal(true)
  })

  it('should solve "easterEggLevelOneChallenge" when requesting eastere.gg with Poison Null Byte attack', async () => {
    challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'eastere.gg%00.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]eastere\.gg/))
    expect(challenges.easterEggLevelOneChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenDevBackupChallenge" when requesting package.json.bak with Poison Null Byte attack', async () => {
    challenges.forgottenDevBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'package.json.bak%00.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]package\.json\.bak/))
    expect(challenges.forgottenDevBackupChallenge.solved).to.equal(true)
  })

  it('should solve "forgottenBackupChallenge" when requesting coupons_2013.md.bak with Poison Null Byte attack', async () => {
    challenges.forgottenBackupChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'coupons_2013.md.bak%00.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]coupons_2013\.md\.bak/))
    expect(challenges.forgottenBackupChallenge.solved).to.equal(true)
  })

  it('should solve "misplacedSignatureFileChallenge" when requesting suspicious_errors.yml with Poison Null Byte attack', async () => {
    challenges.misplacedSignatureFileChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'suspicious_errors.yml%00.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]suspicious_errors\.yml/))
    expect(challenges.misplacedSignatureFileChallenge.solved).to.equal(true)
  })

  it('should reject anonymous requests for non-public files with 401', async () => {
    req.headers = {}
    req.params.file = 'acquisitions.md'

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should reject non-admin users for non-public files with 403', async () => {
    req.headers = { authorization: 'Bearer fileServerSpecJim' }
    req.params.file = 'acquisitions.md'

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
  })

  it('should reject a Poison Null Byte request by a non-admin user', async () => {
    req.headers = { authorization: 'Bearer fileServerSpecJim' }
    req.params.file = 'coupons_2013.md.bak%00.md'

    await servePublicFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
  })

  it('should serve legal.md to anonymous users', async () => {
    req.headers = {}
    req.params.file = 'legal.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md/))
  })

  it('should accept the token cookie for authentication', async () => {
    req.headers = {}
    req.cookies = { token: 'fileServerSpecAdmin' }
    req.params.file = 'acquisitions.md'

    await servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]acquisitions\.md/))
  })

  describe('order confirmation PDFs', () => {
    const orderId = security.hash('jim@juice-sh.op').slice(0, 4) + '-0123456789abcdef'

    beforeEach(() => {
      sinon.stub(db.ordersCollection, 'findOne').resolves({ orderId, email: 'j*m@j**c*-sh.*p' })
      req.params.file = `order_${orderId}.pdf`
    })

    it('should be served to the customer who placed the order', async () => {
      req.headers = { authorization: 'Bearer fileServerSpecJim' }

      await servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.been.calledWith(sinon.match(new RegExp(`ftp[/\\\\]order_${orderId}\\.pdf`)))
    })

    it('should not be served to another customer', async () => {
      req.headers = { authorization: 'Bearer fileServerSpecBender' }

      await servePublicFiles()(req, res, next)

      expect(res.status).to.have.been.calledWith(403)
      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    })

    it('should not be served anonymously', async () => {
      req.headers = {}

      await servePublicFiles()(req, res, next)

      expect(res.status).to.have.been.calledWith(401)
      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    })

    it('should not be served when no matching order exists', async () => {
      (db.ordersCollection.findOne as sinon.SinonStub).resolves(undefined)
      req.headers = { authorization: 'Bearer fileServerSpecJim' }

      await servePublicFiles()(req, res, next)

      expect(res.status).to.have.been.calledWith(403)
      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    })
  })
})
