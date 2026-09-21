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
import { checkUploadSize, checkFileType, countExpandedNodes } from '../../routes/fileUpload'

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

  describe('countExpandedNodes', () => {
    it('should count every node of YAML without aliases', () => {
      expect(countExpandedNodes(yaml.load('a: 1\nb:\n  - 2\n  - 3\n'))).to.equal(5)
    })

    it('should count aliased nodes once per reference', () => {
      expect(countExpandedNodes(yaml.load('a: &x [1, 2, 3]\nb: *x\nc: *x\n'))).to.equal(13)
    })

    it('should not count quoted text that looks like anchors and aliases', () => {
      expect(countExpandedNodes(yaml.load('a: "&x [1, 2, 3]"\nb: "*x *x *x"\n'))).to.equal(3)
    })

    it('should exceed the node limit for a Billion Laughs-style YAML bomb', () => {
      const bomb = fs.readFileSync(path.resolve(__dirname, '../files/yamlBomb.yml'), 'utf8')

      expect(countExpandedNodes(yaml.load(bomb))).to.be.above(200000)
    })
  })
})
