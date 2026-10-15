/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleXmlUpload } from '../../routes/fileUpload'

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

  describe('handleXmlUpload', () => {
    const passwdEntity = '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>'

    function uploadXml (xml: string) {
      challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
      challenges.xxeFileDisclosureChallenge = { solved: false, save } as unknown as Challenge
      req.file = { originalname: 'complaint.xml', buffer: Buffer.from(xml) }
      res.status = () => res
      const errors: Error[] = []
      handleXmlUpload(req, res, (err?: any) => { if (err instanceof Error) errors.push(err) })
      return errors.map(err => err.message).join('\n')
    }

    it('should not expand external entities into the error message', () => {
      const message = uploadXml(`<?xml version="1.0"?>${passwdEntity}<foo>&xxe;</foo>`)

      expect(message).to.not.match(/root:.*:0:0:/)
      expect(message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons (complaint.xml)')
    })

    it('should not echo external parameter entity content via parser errors', () => {
      const message = uploadXml('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo/>')

      expect(message).to.not.match(/root:.*:0:0:/)
      expect(message).to.not.include('/etc/passwd')
    })

    it('should not echo parser error details', () => {
      const message = uploadXml('<foo><bar></foo>')

      expect(message).to.equal('B2B customer complaints via file upload have been deprecated for security reasons (complaint.xml)')
    })

    it('should solve "xxeFileDisclosureChallenge" when a sensitive SYSTEM entity is referenced without resolving it', () => {
      const message = uploadXml(`<?xml version="1.0"?>${passwdEntity}<foo>&xxe;</foo>`)

      expect(message).to.not.match(/root:.*:0:0:/)
      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(true)
    })

    it('should solve "xxeFileDisclosureChallenge" for the Windows system.ini path', () => {
      uploadXml('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/system.ini" >]><foo>&xxe;</foo>')

      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(true)
    })

    it('should not solve "xxeFileDisclosureChallenge" for unrelated files sharing the target basenames', () => {
      for (const path of ['file:///tmp/system.ini', 'file:///home/user/etc/passwd', 'file:///D:/temp/win.ini']) {
        uploadXml(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "${path}" >]><foo>&xxe;</foo>`)

        expect(challenges.xxeFileDisclosureChallenge.solved, path).to.equal(false)
      }
    })

    it('should not solve "xxeFileDisclosureChallenge" for benign XML', () => {
      uploadXml('<?xml version="1.0"?><foo>bar</foo>')

      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(false)
    })

    it('should not solve "xxeFileDisclosureChallenge" when the entity reference is only CDATA text', () => {
      uploadXml(`<?xml version="1.0"?>${passwdEntity}<foo><![CDATA[&xxe;]]></foo>`)

      expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(false)
    })
  })
})
