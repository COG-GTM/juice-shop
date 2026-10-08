/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
import yaml from 'js-yaml'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, estimateJsonLength, handleYamlUpload } from '../../routes/fileUpload'

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

  describe('estimateJsonLength', () => {
    it('should not underestimate the serialized length of a document without aliases', () => {
      const document = yaml.load('a: 1\nb:\n  - two\n  - 3\n')

      expect(estimateJsonLength(document)).to.be.within(JSON.stringify(document).length, JSON.stringify(document).length + 5)
    })

    it('should count aliased nodes once per reference', () => {
      const document = yaml.load('a: &x [1, 2, 3]\nb: *x\nc: *x\n')

      expect(estimateJsonLength(document)).to.be.at.least(JSON.stringify(document).length)
    })

    it('should exceed the limit for a Billion Laughs-style YAML bomb', () => {
      const bomb = fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml'), 'utf8')

      expect(estimateJsonLength(yaml.load(bomb))).to.be.above(1000000)
    })

    it('should exceed the limit when a long scalar is aliased only a few thousand times', () => {
      const levels = ['a: &a "' + 'x'.repeat(60000) + '"']
      for (const [level, previous] of [['b', 'a'], ['c', 'b'], ['d', 'c'], ['e', 'd']]) {
        levels.push(`${level}: &${level} [${Array(9).fill('*' + previous).join(',')}]`)
      }

      expect(estimateJsonLength(yaml.load(levels.join('\n')))).to.be.above(1000000)
    })

    it('should treat cyclic aliases as exceeding the limit', () => {
      const cyclic: any[] = []
      cyclic.push(cyclic)

      expect(estimateJsonLength(cyclic)).to.equal(Number.POSITIVE_INFINITY)
    })
  })

  describe('handleYamlUpload', () => {
    const upload = (buffer: Buffer) => {
      const statusCodes: number[] = []
      const response: any = { status: (code: number) => { statusCodes.push(code); return response }, end: () => {} }
      const errors: Error[] = []

      handleYamlUpload({ file: { originalname: 'complaint.yml', buffer } } as any, response, (err: Error) => { errors.push(err) })

      return { statusCode: statusCodes[0], error: errors[0] }
    }

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
    })

    it('should reject YAML files above the size limit without parsing them', () => {
      const { statusCode, error } = upload(Buffer.from('a: '.padEnd(100001, 'b')))

      expect(statusCode).to.equal(413)
      expect(error.message).to.contain('too large')
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })

    it('should solve "yamlBombChallenge" without serializing a YAML bomb', () => {
      const stringify = JSON.stringify
      let serialized = false
      JSON.stringify = (...args: Parameters<typeof JSON.stringify>) => { serialized = true; return stringify(...args) }
      try {
        const { statusCode } = upload(fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml')))

        expect(statusCode).to.equal(503)
      } finally {
        JSON.stringify = stringify
      }
      expect(serialized).to.equal(false)
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should still echo a harmless aliased document', () => {
      const { statusCode, error } = upload(Buffer.from('a: &x [1, 2, 3]\nb: *x\n'))

      expect(statusCode).to.equal(410)
      expect(error.message).to.contain('{"a":[1,2,3],"b":[1,2,3]}')
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })
  })
})
