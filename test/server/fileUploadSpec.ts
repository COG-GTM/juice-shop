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
    const { deprecatedInterfaceChallenge, yamlBombChallenge } = challenges

    afterEach(() => {
      challenges.deprecatedInterfaceChallenge = deprecatedInterfaceChallenge
      challenges.yamlBombChallenge = yamlBombChallenge
    })

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: true, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: true, save } as unknown as Challenge
      res = { status: () => res, end: () => {} }
    })

    it('should not construct or invoke !!js/function values from uploaded YAML', () => {
      (globalThis as any).yamlFunctionInvoked = false
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from('toJSON: !!js/function "function () { globalThis.yamlFunctionInvoked = true; return \'pwned\' }"') }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: unknown) => { error = err as Error })

      expect((globalThis as any).yamlFunctionInvoked).to.equal(false)
      expect(error?.message).to.contain('unknown tag')
      delete (globalThis as any).yamlFunctionInvoked
    })

    for (const tag of ['!!js/undefined ""', '!!js/regexp /pwned/']) {
      it(`should reject ${tag.split(' ')[0]} tags from uploaded YAML`, () => {
        req.file = { originalname: 'complaint.yml', buffer: Buffer.from(`value: ${tag}`) }
        let error: Error | undefined

        handleYamlUpload(req, res, (err?: unknown) => { error = err as Error })

        expect(error?.message).to.contain('unknown tag')
      })
    }

    it('should not echo the offending YAML source in parse errors', () => {
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from('toJSON: !!js/function \'function(){ return 42 }\'') }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: unknown) => { error = err as Error })

      expect(error?.message).to.contain('unknown tag')
      expect(error?.message).to.not.contain('42')
    })

    it('should still echo plain YAML content in the deprecation error', () => {
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from('message: hello') }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: unknown) => { error = err as Error })

      expect(error?.message).to.contain('{"message":"hello"}')
    })

    it('should stop expanding YAML alias bombs at the output size limit and solve "yamlBombChallenge"', () => {
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
      const levels = 'abcdefghi'.split('').map((name, i) => `${name}: &${name} [${Array(9).fill(i === 0 ? '"lol"' : `*${'abcdefghi'[i - 1]}`).join(',')}]`)
      req.file = { originalname: 'bomb.yml', buffer: Buffer.from(levels.join('\n')) }
      const statuses: number[] = []
      res = { status: (s: number) => { statuses.push(s); return res }, end: () => {} }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: unknown) => { error ??= err as Error })

      expect(statuses[0]).to.equal(503)
      expect(error?.message).to.contain('temporarily not available')
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should treat a long string repeated through aliases as exceeding the output size limit', () => {
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from(`a: &a "${'x'.repeat(50000)}"\nb: [*a, *a, *a, *a]`) }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: unknown) => { error ??= err as Error })

      expect(error?.message).to.contain('temporarily not available')
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should not treat large YAML documents without alias expansion as a bomb', () => {
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
      const items = Array.from({ length: 4000 }, (_, i) => `k${i}: [1, 2, "${'x'.repeat(i % 5)}"]`)
      req.file = { originalname: 'complaint.yml', buffer: Buffer.from(`message: "${'x'.repeat(120000)}"\n${items.join('\n')}`) }
      const statuses: number[] = []
      res = { status: (s: number) => { statuses.push(s); return res }, end: () => {} }
      let error: Error | undefined

      handleYamlUpload(req, res, (err?: unknown) => { error ??= err as Error })

      expect(statuses[0]).to.equal(410)
      expect(error?.message).to.contain('{"message":"xxx')
      expect(challenges.yamlBombChallenge.solved).to.equal(false)
    })
  })
})
