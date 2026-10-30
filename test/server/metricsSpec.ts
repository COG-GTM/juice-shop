/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'

import { fileTypeLabel } from '../../routes/metrics'

const expect = chai.expect

describe('metrics', () => {
  describe('fileTypeLabel', () => {
    it('should keep known MIME types', () => {
      expect(fileTypeLabel('application/pdf')).to.equal('application/pdf')
      expect(fileTypeLabel('image/png')).to.equal('image/png')
    })

    it('should normalize the casing of known MIME types', () => {
      expect(fileTypeLabel('Application/PDF')).to.equal('application/pdf')
    })

    it('should bucket unknown MIME types as "other"', () => {
      expect(fileTypeLabel('application/x-' + 'a'.repeat(64))).to.equal('other')
      expect(fileTypeLabel('')).to.equal('other')
      expect(fileTypeLabel(undefined)).to.equal('other')
    })
  })
})
