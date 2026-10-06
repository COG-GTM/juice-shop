/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleXmlUpload, handleYamlUpload, expandedYamlLength } from '../../routes/fileUpload'

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

  describe('YAML uploads', () => {
    function yamlBomb (levels: number) {
      let doc = 'a0: &a0 ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]\n'
      for (let i = 1; i < levels; i++) {
        doc += `a${i}: &a${i} [${Array(9).fill(`*a${i - 1}`).join(',')}]\n`
      }
      return doc
    }

    function uploadYaml (content: string) {
      const response: { status?: number, error?: Error } = {}
      let currentStatus: number | undefined
      res = { status (code: number) { currentStatus = code; return this }, end () {} }
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from(content) }
      handleYamlUpload(req, res, (err?: Error) => {
        if (err != null) {
          response.status = currentStatus
          response.error = err
        }
      })
      return response
    }

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
    })

    it('should measure the expanded JSON length of aliased YAML without expanding it', () => {
      const leaf = ['lol', 'lol']
      const shared = [leaf, leaf]
      expect(expandedYamlLength({ a: shared, b: shared })).to.equal(JSON.stringify({ a: shared, b: shared }).length)
      expect(expandedYamlLength({ k: 1, n: null, t: true })).to.equal(JSON.stringify({ k: 1, n: null, t: true }).length)
    })

    it('should measure scalars the way JSON.stringify serializes them', () => {
      const value = { 'tab\tkey': ['a\t"b"\n', Infinity, NaN, new Date(0)], empty: {}, list: [] }
      expect(expandedYamlLength(value)).to.equal(JSON.stringify(value).length)
    })

    it('should reject aliased escape-heavy strings that only exceed the limit once JSON-escaped', () => {
      const response = uploadYaml(`s: &s "${'\\t'.repeat(40000)}"\nr: [${Array(15).fill('*s').join(',')}]\n`)

      expect(response.status).to.equal(503)
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should not treat self-referencing YAML as a memory bomb', () => {
      const response = uploadYaml('a: &a [*a]\n')

      expect(response.status).to.equal(410)
      expect(response.error?.message).to.contain('circular structure')
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })

    it('should reject an alias bomb before serializing it and solve "yamlBombChallenge"', () => {
      const response = uploadYaml(yamlBomb(7)) // expands to ~33 MB of JSON

      expect(response.status).to.equal(503)
      expect(response.error?.message).to.equal('Sorry, we are temporarily not available! Please try again later.')
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should reject the shipped test/files/yamlBomb.yml', () => {
      const response = uploadYaml(fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml'), 'utf8'))

      expect(response.status).to.equal(503)
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should still echo small YAML documents', () => {
      const response = uploadYaml('complaint: "juice was warm"\nitems: [1, 2]\n')

      expect(response.status).to.equal(410)
      expect(response.error?.message).to.contain('{"complaint":"juice was warm","items":[1,2]}')
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })

    it('should not construct JavaScript-specific YAML types', () => {
      const response = uploadYaml('fn: !!js/function "function () { return 42 }"\n')

      expect(response.status).to.equal(410)
      expect(response.error?.message).to.contain('unknown tag')
    })
  })

  describe('XML uploads', () => {
    function uploadXml (buffer: Buffer) {
      const errors: Error[] = []
      res = { status () { return this } }
      req.file = { originalname: 'complaint.xml', buffer }
      handleXmlUpload(req, res, (err?: Error) => { if (err != null) errors.push(err) })
      return errors
    }

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.xxeFileDisclosureChallenge = { solved: false, save } as unknown as Challenge
      challenges.xxeDosChallenge = { solved: false, save } as unknown as Challenge
    })

    it('should not resolve entities that have to be fetched over the network', () => {
      const errors = uploadXml(Buffer.from('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:1/secret">]><foo>&xxe;</foo>'))

      expect(errors).to.have.length(1)
      expect(errors[0].message).to.not.contain('secret')
    })

    it('should still expand local file entities so "xxeFileDisclosureChallenge" stays solvable', () => {
      const errors = uploadXml(fs.readFileSync(path.resolve(__dirname, '../files/xxeForLinux.xml')))

      expect(errors).to.have.length(1)
      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(true)
    })
  })
})
