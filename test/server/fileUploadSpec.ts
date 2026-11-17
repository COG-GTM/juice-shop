/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
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
    let nextError: Error | undefined

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
      res = { status (code: number) { res.statusCode ??= code; return res }, end () {} }
      nextError = undefined
    })

    it('should reject a Billion Laughs-style YAML without expanding it and solve "yamlBombChallenge"', () => {
      req.file.originalname = 'yamlBomb.yml'
      req.file.buffer = fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml'))

      const start = Date.now()
      handleYamlUpload(req, res, (err?: Error) => { nextError ??= err })

      expect(Date.now() - start).to.be.below(1000)
      expect(res.statusCode).to.equal(503)
      expect(nextError?.message).to.equal('Sorry, we are temporarily not available! Please try again later.')
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should echo regular YAML content in the deprecation error', () => {
      req.file.originalname = 'complaint.yaml'
      req.file.buffer = Buffer.from('a: &a [1, 2]\nb: [*a, *a]\n')

      handleYamlUpload(req, res, (err?: Error) => { nextError ??= err })

      expect(res.statusCode).to.equal(410)
      expect(nextError?.message).to.contain('{"a":[1,2],"b":[[1,2],[1,2]]}')
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })
  })
})
