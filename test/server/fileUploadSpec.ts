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
    let statusCode: number | undefined
    let error: Error | undefined

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
      statusCode = undefined
      error = undefined
      res = { status: (code: number) => { statusCode = statusCode ?? code; return res }, end: () => res }
    })

    function uploadYaml (content: string) {
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from(content) }
      handleYamlUpload(req, res, (err?: Error) => { error = error ?? err })
    }

    it('should still echo plain YAML content in the deprecation error', () => {
      uploadYaml('name: Jim\nitems: [1, 2]\n')

      expect(statusCode).to.equal(410)
      expect(error?.message).to.contain('{"name":"Jim","items":[1,2]}')
      expect(challenges.deprecatedInterfaceChallenge.solved).to.equal(true)
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })

    it('should not construct a !!js/function toJSON that JSON.stringify would invoke', () => {
      const globals = globalThis as Record<string, unknown>
      delete globals.yamlUploadPwned
      uploadYaml('toJSON: !!js/function "function () { globalThis.yamlUploadPwned = true; return \'pwned\' }"\n')

      expect(globals.yamlUploadPwned).to.equal(undefined)
      expect(statusCode).to.equal(410)
      expect(error?.message).to.contain('unknown tag')
    })

    it('should reject JavaScript-specific tags like !!js/regexp and !!js/undefined', () => {
      uploadYaml('a: !!js/regexp /pwned/\nb: !!js/undefined ""\n')

      expect(statusCode).to.equal(410)
      expect(error?.message).to.contain('unknown tag')
    })

    it('should reject aliased content that expands beyond the size limit and solve "yamlBombChallenge"', () => {
      const lines = ['a: &a "' + 'x'.repeat(1000) + '"', 'b: [' + new Array(2000).fill('*a').join(',') + ']']
      uploadYaml(lines.join('\n'))

      expect(statusCode).to.equal(503)
      expect(error?.message).to.equal('Sorry, we are temporarily not available! Please try again later.')
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should solve "yamlBombChallenge" for the Billion Laughs file without expanding it', () => {
      uploadYaml(fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml'), 'utf8'))

      expect(statusCode).to.equal(503)
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })
  })
})
