/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import config from 'config'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleXmlUpload, handleYamlUpload } from '../../routes/fileUpload'

const expect = chai.expect
chai.use(sinonChai)

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

  describe('deprecated B2B interface', () => {
    const yamlBomb = 'a: &a ["x","x","x","x","x","x","x","x","x"]\n' +
      'b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n' +
      'c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n' +
      'd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n'
    const xmlEntityExpansion = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>'
    let configStub: sinon.SinonStub
    let errors: Error[]

    function upload (handler: typeof handleYamlUpload, originalname: string, content: string) {
      req.file = { originalname, buffer: Buffer.from(content) }
      res = { status: sinon.stub().returnsThis(), end: sinon.stub() }
      handler(req, res, (err?: unknown) => { if (err instanceof Error) errors.push(err) })
    }

    function setSafetyMode (safetyMode: string) {
      configStub = sinon.stub(config, 'get').callThrough()
      configStub.withArgs('challenges.safetyMode').returns(safetyMode)
    }

    beforeEach(() => {
      errors = []
      challenges.deprecatedInterfaceChallenge = { solved: true, save } as unknown as Challenge
      for (const key of ['yamlBombChallenge', 'xxeDosChallenge', 'xxeFileDisclosureChallenge'] as const) {
        challenges[key] = { solved: false, save, disabledEnv: ['Docker', 'Heroku', 'Gitpod'] } as unknown as Challenge
      }
    })

    afterEach(() => {
      configStub?.restore()
    })

    it('should not parse YAML when "yamlBombChallenge" is disabled by safety mode', () => {
      setSafetyMode('enabled')

      upload(handleYamlUpload, 'bomb.yml', yamlBomb)

      expect(res.status).to.have.been.calledWith(410)
      expect(errors).to.have.lengthOf(1)
      expect(errors[0].message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons (bomb.yml)')
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })

    it('should not parse XML when "xxeDosChallenge" and "xxeFileDisclosureChallenge" are disabled by safety mode', () => {
      setSafetyMode('enabled')

      upload(handleXmlUpload, 'lolz.xml', xmlEntityExpansion)

      expect(res.status).to.have.been.calledWith(410)
      expect(errors).to.have.lengthOf(1)
      expect(errors[0].message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons (lolz.xml)')
      expect(challenges.xxeDosChallenge.solved).to.equal(false)
    })

    it('should still parse YAML when "yamlBombChallenge" is enabled', () => {
      setSafetyMode('disabled')

      upload(handleYamlUpload, 'complaint.yml', 'complaint: broken juice')

      expect(res.status).to.have.been.calledWith(410)
      expect(errors[0].message).to.contain('{"complaint":"broken juice"}')
    })
  })
})
