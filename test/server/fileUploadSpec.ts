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
import { checkUploadSize, checkFileType, containsXmlDtd, assertYamlWithinLimits } from '../../routes/fileUpload'

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

  describe('containsXmlDtd', () => {
    it('should detect the DTD of the Billion Laughs attack file', () => {
      const data = fs.readFileSync(path.resolve(__dirname, '../files/xxeBillionLaughs.xml'), 'utf8')
      expect(containsXmlDtd(data)).to.equal(true)
    })

    it('should detect lowercase or entity-only declarations', () => {
      expect(containsXmlDtd('<!doctype foo><foo/>')).to.equal(true)
      expect(containsXmlDtd('<!ENTITY x "y">')).to.equal(true)
    })

    it('should not flag declaration text inside comments, CDATA sections or processing instructions', () => {
      expect(containsXmlDtd('<complaint><![CDATA[The manual says <!DOCTYPE invoice>]]></complaint>')).to.equal(false)
      expect(containsXmlDtd('<!-- <!DOCTYPE foo> --><complaint/>')).to.equal(false)
      expect(containsXmlDtd('<?note <!ENTITY x "y"> ?><complaint/>')).to.equal(false)
    })

    it('should detect a DTD that follows a comment', () => {
      expect(containsXmlDtd('<?xml version="1.0"?><!-- hi --><!DOCTYPE foo [<!ENTITY x "y">]><foo>&x;</foo>')).to.equal(true)
    })

    it('should not flag plain XML', () => {
      expect(containsXmlDtd('<?xml version="1.0"?><complaint>XML all the way!</complaint>')).to.equal(false)
    })
  })

  describe('assertYamlWithinLimits', () => {
    it('should reject the YAML bomb attack file without expanding it', () => {
      const document = yaml.safeLoad(fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml'), 'utf8'), { schema: yaml.JSON_SCHEMA })
      expect(() => { assertYamlWithinLimits(document) }).to.throw('YAML aliases are not allowed')
    })

    it('should reject documents with more than 10000 nodes', () => {
      expect(() => { assertYamlWithinLimits(new Array(10000).fill('lol')) }).to.throw('exceeds 10000 nodes')
    })

    it('should reject documents nested deeper than 100 levels', () => {
      let document: unknown = 'lol'
      for (let i = 0; i < 101; i++) document = [document]
      expect(() => { assertYamlWithinLimits(document) }).to.throw('nesting depth')
    })

    it('should accept regular complaint documents', () => {
      const document = yaml.safeLoad('complaint:\n  customer: jim\n  items: [1, 2, 3]\n  message: "the juice was sour"\n', { schema: yaml.JSON_SCHEMA })
      expect(() => { assertYamlWithinLimits(document) }).to.not.throw()
    })
  })
})
