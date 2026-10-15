/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleXmlUpload, handleYamlUpload } from '../../routes/fileUpload'

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

  describe('XML and YAML complaint uploads', () => {
    let errors: Error[]
    let status: number | undefined

    const upload = (handler: typeof handleXmlUpload, fixture: string, content?: string) => {
      errors = []
      status = undefined
      req.file = { originalname: fixture, buffer: content !== undefined ? Buffer.from(content) : fs.readFileSync(path.resolve(__dirname, '../files', fixture)) }
      res = {
        status (code: number) { status = status ?? code; return res },
        end () {}
      }
      handler(req, res, (err?: any) => { if (err != null) errors.push(err) })
      return errors.map(e => e.message).join('\n')
    }

    beforeEach(() => {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.xxeFileDisclosureChallenge = { solved: false, save } as unknown as Challenge
      challenges.xxeDosChallenge = { solved: false, save } as unknown as Challenge
      challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
    })

    it('should not resolve external entities or echo file contents for XXE uploads', () => {
      const message = upload(handleXmlUpload, 'xxeForLinux.xml')

      expect(status).to.equal(410)
      expect(message).to.not.match(/root:.*:0:0:/)
      expect(message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons (xxeForLinux.xml)')
      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(true)
    })

    it('should not solve the XXE challenge for XML without a sensitive external entity', () => {
      upload(handleXmlUpload, 'complaint.xml', '<?xml version="1.0"?><complaint>hello</complaint>')

      expect(status).to.equal(410)
      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(false)
    })

    it('should not expand internal entities or echo parser errors for Billion Laughs XML uploads', () => {
      const message = upload(handleXmlUpload, 'xxeBillionLaughs.xml')

      expect(status).to.equal(410)
      expect(message).to.not.include('lol')
      expect(message).to.not.include('entity')
      expect(challenges.xxeDosChallenge.solved).to.equal(false)
    })

    it('should reject YAML alias bombs without expanding them', () => {
      const started = Date.now()
      const message = upload(handleYamlUpload, 'yamlBomb.yml')

      expect(Date.now() - started).to.be.below(1000)
      expect(status).to.equal(413)
      expect(message).to.equal('Uploaded YAML document is too large (yamlBomb.yml)')
      expect(challenges.yamlBombChallenge.solved).to.equal(true)
    })

    it('should stop counting wide aliased YAML documents at the node limit', () => {
      const wide = 'a: &a [' + Array(5000).fill('x').join(', ') + ']\nb: [' + Array(5000).fill('*a').join(', ') + ']\n'
      const started = Date.now()
      upload(handleYamlUpload, 'wide.yml', wide)

      expect(Date.now() - started).to.be.below(1000)
      expect(status).to.equal(413)
    })

    it('should not echo YAML document contents', () => {
      const message = upload(handleYamlUpload, 'complaint.yml', 'secret: s3cr3t-value\n')

      expect(status).to.equal(410)
      expect(message).to.not.include('s3cr3t-value')
    })
  })
})
