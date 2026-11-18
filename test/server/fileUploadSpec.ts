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
      res = { status () { return this }, end () {} }
    })

    it('should not execute !!js/function payloads from uploaded YAML', () => {
      let error: any
      const marker = '__juiceShopYamlRce'
      delete (globalThis as any)[marker]
      req.file = {
        originalname: 'note.yml',
        buffer: Buffer.from(`toJSON: !!js/function "function () { globalThis.${marker} = true; return 'pw' + 'ned' }"`)
      }

      handleYamlUpload(req, res, (err: any) => { error = err })

      expect((globalThis as any)[marker]).to.equal(undefined)
      expect(error.message).to.not.contain('pwned')
      expect(error.message).to.contain('unknown tag')
    })

    it('should still parse regular YAML', () => {
      let error: any
      req.file = { originalname: 'complaint.yaml', buffer: Buffer.from('message: Hello') }

      handleYamlUpload(req, res, (err: any) => { error = err })

      expect(error.message).to.contain('{"message":"Hello"}')
    })
  })
})
