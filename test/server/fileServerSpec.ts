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

  it('should raise error for disallowed file type hidden behind a Poison Null Byte', () => {
    req.params.file = 'package.json.bak%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for any file name containing a Poison Null Byte', () => {
    for (const file of ['legal.md%00.pdf', 'coupons_2013.md.bak\0.md', 'eastere.gg%00']) {
      res.sendFile.resetHistory()
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.sendFile, file).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status, file).to.have.been.calledWith(403)
    }
  })

  for (const [challenge, file] of [
    ['easterEggLevelOneChallenge', 'eastere.gg'],
    ['forgottenDevBackupChallenge', 'package.json.bak'],
    ['forgottenBackupChallenge', 'coupons_2013.md.bak'],
    ['misplacedSignatureFileChallenge', 'suspicious_errors.yml']
  ] as const) {
    it(`should solve "${challenge}" but not serve ${file} on a Poison Null Byte attack`, () => {
      challenges[challenge] = { solved: false, save } as unknown as Challenge
      req.params.file = `${file}%00.md`

      servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
      expect(challenges[challenge].solved).to.equal(true)
    })
  }

  it('should not solve "easterEggLevelOneChallenge" for a Poison Null Byte without an allowlisted suffix', () => {
    challenges.easterEggLevelOneChallenge = { solved: false, save } as unknown as Challenge
    req.params.file = 'eastere.gg%00'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(challenges.easterEggLevelOneChallenge.solved).to.equal(false)
  })

  it('should solve "nullByteChallenge" but not serve encrypt.pyc on a Poison Null Byte attack', () => {
    for (const challenge of ['easterEggLevelOneChallenge', 'forgottenDevBackupChallenge', 'forgottenBackupChallenge', 'misplacedSignatureFileChallenge', 'nullByteChallenge'] as const) {
      challenges[challenge] = { solved: false, save } as unknown as Challenge
    }
    req.params.file = 'encrypt.pyc%00.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(challenges.nullByteChallenge.solved).to.equal(true)
  })
})
