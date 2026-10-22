/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleYamlUpload } from '../../routes/fileUpload'

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

  describe('handleYamlUpload', () => {
    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: true, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: true, save } as unknown as Challenge
      res = { status: () => res, end: () => {} }
    })

    it('should not construct or invoke !!js/function values from uploaded YAML', () => {
      (globalThis as any).yamlFunctionInvoked = false
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from('toJSON: !!js/function "function () { globalThis.yamlFunctionInvoked = true; return \'pwned\' }"') }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: Error) => { error = err })

      expect((globalThis as any).yamlFunctionInvoked).to.equal(false)
      expect(error?.message).to.contain('unknown tag')
      delete (globalThis as any).yamlFunctionInvoked
    })

    it('should still echo plain YAML content in the deprecation error', () => {
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from('message: hello') }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: Error) => { error = err })

      expect(error?.message).to.contain('{"message":"hello"}')
    })
  })
})
