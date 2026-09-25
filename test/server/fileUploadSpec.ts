/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import yaml from 'js-yaml'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, expandedNodeCount, exceedsEntityExpansionLimit } from '../../routes/fileUpload'

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

  describe('expandedNodeCount', () => {
    it('counts the nodes of a regular YAML document', () => {
      expect(expandedNodeCount(yaml.load('a: 1\nb:\n  - 2\n  - 3\n'))).to.equal(5)
    })

    it('counts aliased nodes as often as they are referenced', () => {
      const document = 'a: &a [1, 1]\nb: &b [*a, *a]\nc: [*b, *b]\n'

      expect(expandedNodeCount(yaml.load(document))).to.equal(26)
    })

    it('exceeds the node limit for a YAML bomb', () => {
      let document = 'a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]\n'
      for (const [index, previous] of ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].entries()) {
        const current = String.fromCharCode('b'.charCodeAt(0) + index)
        document += `${current}: &${current} [${Array(9).fill('*' + previous).join(',')}]\n`
      }

      expect(expandedNodeCount(yaml.load(document))).to.be.above(200000)
    })

    it('treats cyclic aliases as infinitely large', () => {
      const cyclic: any[] = []
      cyclic.push(cyclic)

      expect(expandedNodeCount(cyclic)).to.equal(Number.POSITIVE_INFINITY)
    })
  })

  describe('exceedsEntityExpansionLimit', () => {
    it('accepts XML without entity declarations', () => {
      expect(exceedsEntityExpansionLimit('<?xml version="1.0"?><order><product>Juice</product></order>')).to.equal(false)
    })

    it('accepts XML with harmless entity declarations', () => {
      expect(exceedsEntityExpansionLimit('<!DOCTYPE order [<!ENTITY product "Juice">]><order>&product;</order>')).to.equal(false)
    })

    it('rejects an entity bomb', () => {
      let document = '<!DOCTYPE lolz [<!ENTITY lol "lol">'
      for (let level = 1; level <= 9; level++) {
        document += `<!ENTITY lol${level} "${Array(10).fill(level === 1 ? '&lol;' : `&lol${level - 1};`).join('')}">`
      }
      document += ']><lolz>&lol9;</lolz>'

      expect(exceedsEntityExpansionLimit(document)).to.equal(true)
    })

    it('rejects recursive entity declarations', () => {
      expect(exceedsEntityExpansionLimit('<!DOCTYPE a [<!ENTITY a "&b;"><!ENTITY b "&a;">]><a>&a;</a>')).to.equal(true)
    })
  })
})
