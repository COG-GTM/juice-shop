/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import yaml from 'js-yaml'
import { PassThrough } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, expandedYamlSize, decompressionLimiter, DecompressionLimitError } from '../../routes/fileUpload'

const expect = chai.expect

async function decompress (chunks: Buffer[], budget: { remaining: number }) {
  const source = new PassThrough()
  const sink = new PassThrough()
  sink.resume()
  for (const chunk of chunks) { source.write(chunk) }
  source.end()
  await pipeline(source, decompressionLimiter(budget), sink)
}

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

  describe('expandedYamlSize', () => {
    it('measures aliased nodes as often as they are referenced', () => {
      const aliased = expandedYamlSize(yaml.load('a: &a [1, 1]\nb: [*a, *a]\n'))
      const expanded = expandedYamlSize(yaml.load('a: [1, 1]\nb: [[1, 1], [1, 1]]\n'))
      expect(aliased).to.equal(expanded)
    })

    it('exceeds the size limit for a YAML bomb', () => {
      let document = 'a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]\n'
      for (const [index, previous] of ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].entries()) {
        const current = String.fromCharCode('b'.charCodeAt(0) + index)
        document += `${current}: &${current} [${Array(9).fill('*' + previous).join(',')}]\n`
      }
      expect(expandedYamlSize(yaml.load(document))).to.be.above(1000000)
    })

    it('treats cyclic aliases as infinitely large', () => {
      const cyclic: any[] = []
      cyclic.push(cyclic)
      expect(expandedYamlSize(cyclic)).to.equal(Number.POSITIVE_INFINITY)
    })
  })

  describe('decompressionLimiter', () => {
    it('passes content that stays within the limits', async () => {
      await decompress([Buffer.alloc(1000)], { remaining: 5000000 })
    })

    it('rejects an entry that exceeds the per-entry limit', async () => {
      try {
        await decompress([Buffer.alloc(1000000), Buffer.alloc(1)], { remaining: 5000000 })
        expect.fail('expected the entry to be rejected')
      } catch (err) {
        expect(err).to.be.an.instanceOf(DecompressionLimitError)
      }
    })

    it('rejects an entry that exhausts the archive budget', async () => {
      try {
        await decompress([Buffer.alloc(1000)], { remaining: 999 })
        expect.fail('expected the entry to be rejected')
      } catch (err) {
        expect(err).to.be.an.instanceOf(DecompressionLimitError)
      }
    })
  })
})
