/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { servePublicFiles } from '../../routes/fileServer'
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
    req = { params: {}, query: {} }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  it('should serve PDF files from folder /ftp', () => {
    req.params.file = 'test.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]test\.pdf/))
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

  for (const file of ['eastere.gg%00.md', 'package.json.bak%00.md', 'coupons_2013.md.bak%00.pdf', 'suspicious_errors.yml%00.md', 'encrypt.pyc%00.md']) {
    it(`should reject Poison Null Byte attack ${file} without serving the truncated file`, () => {
      challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
      challenges.forgottenDevBackupChallenge = { solved: false, save } as unknown as Challenge
      challenges.forgottenBackupChallenge = { solved: false, save } as unknown as Challenge
      challenges.misplacedSignatureFileChallenge = { solved: false, save } as unknown as Challenge
      challenges.nullByteChallenge = { solved: false, save } as unknown as Challenge
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
      expect(challenges.easterEggLevelOneChallenge.solved).to.equal(false)
      expect(challenges.forgottenDevBackupChallenge.solved).to.equal(false)
      expect(challenges.forgottenBackupChallenge.solved).to.equal(false)
      expect(challenges.misplacedSignatureFileChallenge.solved).to.equal(false)
      expect(challenges.nullByteChallenge.solved).to.equal(false)
    })
  }

  it('should reject raw null bytes in file names', () => {
    req.params.file = 'package.json.bak\0.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('should reject the KeePass file name with a Poison Null Byte suffix', () => {
    req.params.file = 'incident-support.kdbx%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
  })
})
