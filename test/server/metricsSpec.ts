/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as Prometheus from 'prom-client'
import { type Request, type Response } from 'express'

import { fileTypeLabel, observeFileUploadMetricsMiddleware } from '../../routes/metrics'

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

  describe('observeFileUploadMetricsMiddleware', () => {
    async function upload (mimetype: string, statusCode: number) {
      const req = { file: { mimetype } } as unknown as Request
      const res = { statusCode, finished: true } as unknown as Response
      await new Promise<void>(resolve => { observeFileUploadMetricsMiddleware()(req, res, () => { resolve() }) })
      await new Promise(resolve => setImmediate(resolve))
    }

    async function fileTypeLabels (metricName: string) {
      const metric = Prometheus.register.getSingleMetric(metricName)
      const { values } = await metric!.get()
      return values.map(({ labels }) => labels.file_type)
    }

    it('should collapse invented MIME types into "other" for successful uploads', async () => {
      await upload('application/pdf', 200)
      for (let i = 0; i < 50; i++) {
        await upload(`application/x-invented-ok-${i}`, 200)
      }
      const labels = await fileTypeLabels('file_uploads_count')
      expect(labels).to.include.members(['application/pdf', 'other'])
      expect(labels.filter(label => String(label).includes('invented'))).to.deep.equal([])
    })

    it('should collapse invented MIME types into "other" for failed uploads', async () => {
      for (let i = 0; i < 50; i++) {
        await upload(`application/x-invented-err-${i}`, 400)
      }
      const labels = await fileTypeLabels('file_upload_errors')
      expect(labels).to.include('other')
      expect(labels.filter(label => String(label).includes('invented'))).to.deep.equal([])
    })
  })
})
