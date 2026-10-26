/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
import sinon from 'sinon'
import config from 'config'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleXmlUpload } from '../../routes/fileUpload'

const expect = chai.expect

describe('fileUpload', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    req = { file: { originalname: '' } }
    res = {}
    save = () => ({
      then () { }
    })
  })

  describe('should not solve "uploadSizeChallenge" when file size is', () => {
    const sizes = [0, 1, 100, 1000, 10000, 99999, 100000]
    sizes.forEach(size => {
      it(`${size} bytes`, () => {
        challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
        req.file.size = size

        checkUploadSize(req, res, () => {})

        expect(challenges.uploadSizeChallenge.solved).to.equal(false)
      })
    })
  })

  it('should solve "uploadSizeChallenge" when file size exceeds 100000 bytes', () => {
    challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
    req.file.size = 100001

    checkUploadSize(req, res, () => {})

    expect(challenges.uploadSizeChallenge.solved).to.equal(true)
  })

  it('should solve "uploadTypeChallenge" when file type is not PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.exe'

    checkFileType(req, res, () => {})

    expect(challenges.uploadTypeChallenge.solved).to.equal(true)
  })

  it('should not solve "uploadTypeChallenge" when file type is PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.pdf'

    checkFileType(req, res, () => {})

    expect(challenges.uploadTypeChallenge.solved).to.equal(false)
  })

  describe('handleXmlUpload', () => {
    const xxeForLinux = fs.readFileSync(path.resolve(__dirname, '../files/xxeForLinux.xml'))
    const xxeChallenge = () => ({ solved: false, save, disabledEnv: ['Docker', 'Heroku', 'Gitpod'] }) as unknown as Challenge
    let status: sinon.SinonSpy
    let safetyMode: string

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.xxeFileDisclosureChallenge = xxeChallenge()
      challenges.xxeDosChallenge = xxeChallenge()
      status = sinon.spy()
      res = { status }
      const get = config.get.bind(config)
      sinon.stub(config, 'get').callsFake((key: string) => key === 'challenges.safetyMode' ? safetyMode : get(key))
    })

    afterEach(() => {
      sinon.restore()
    })

    function upload (buffer: Buffer, originalname: string) {
      const errors: Error[] = []
      handleXmlUpload({ file: { originalname, buffer } } as any, res, (err?: unknown) => { if (err instanceof Error) errors.push(err) })
      return errors
    }

    it('should not parse uploaded XML when the XXE challenges are disabled by safety mode', () => {
      safetyMode = 'enabled'

      const errors = upload(xxeForLinux, 'xxeForLinux.xml')

      expect(status.calledWith(410)).to.equal(true)
      expect(errors).to.have.length(1)
      expect(errors[0].message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons (xxeForLinux.xml)')
      expect(challenges.deprecatedInterfaceChallenge.solved).to.equal(true)
    })

    it('should not expand external entities when the XXE challenges are enabled', () => {
      safetyMode = 'disabled'

      const errors = upload(xxeForLinux, 'xxeForLinux.xml')

      expect(status.calledWith(410)).to.equal(true)
      expect(errors).to.have.length(1)
      expect(errors[0].message).to.not.match(/root:x?:0:0:/)
      expect(errors[0].message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons (xxeForLinux.xml)')
      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(false)
    })

    it('should not reflect parser errors for malformed XML', () => {
      safetyMode = 'disabled'

      const errors = upload(Buffer.from('<foo><bar></foo>'), 'malformed.xml')

      expect(status.calledWith(410)).to.equal(true)
      expect(errors[0].message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons: invalid XML document (malformed.xml)')
    })
  })
})
