/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as webhook from '../../lib/webhook'
import { type AddressInfo } from 'node:net'
import http from 'node:http'
import chai from 'chai'
import sinon from 'sinon'
import logger from '../../lib/logger'
const expect = chai.expect

describe('webhook', () => {
  const challenge = {
    key: 'key',
    name: 'name',
    difficulty: 1
  }

  describe('notify', () => {
    it('ignores errors where no webhook URL is provided via environment variable', async () => {
      try {
        await webhook.notify(challenge)
      } catch (error) {
        chai.assert.fail('webhook.notify should not throw an error when no webhook URL is provided')
      }
    })

    it('fails when supplied webhook is not a valid URL', async () => {
      try {
        await webhook.notify(challenge, 0, 0, 0, 'localhorst')
        chai.assert.fail('Expected error was not thrown')
      } catch (error) {
        expect((error as Error).message).to.equal('Failed to parse URL from localhorst')
      }
    })

    it('skips non-loopback webhooks that do not use HTTPS', async () => {
      const warn = sinon.stub(logger, 'warn')
      try {
        await webhook.notify(challenge, 0, 0, 0, 'http://webhook.invalid/collect')
        expect(warn.calledOnce).to.equal(true)
        expect(warn.firstCall.args[0]).to.contain('only HTTPS destinations are permitted')
      } finally {
        warn.restore()
      }
    })

    it('skips webhooks whose host is not in SOLUTIONS_WEBHOOK_ALLOWED_HOSTS', async () => {
      const server = http.createServer((req, res) => {
        res.statusCode = 200
        res.end('OK')
      })
      let requests = 0
      server.on('request', () => { requests++ })

      await new Promise<void>((resolve) => server.listen(0, resolve))
      const port = (server.address() as AddressInfo)?.port
      process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS = 'Approved.invalid:443'

      try {
        await webhook.notify(challenge, 0, 0, 0, `http://localhost:${port}`)
        expect(requests).to.equal(0)
      } finally {
        delete process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS
        server.close()
      }
    })

    it('notifies webhooks whose host is in SOLUTIONS_WEBHOOK_ALLOWED_HOSTS', async () => {
      const server = http.createServer((req, res) => {
        res.statusCode = 200
        res.end('OK')
      })
      let requests = 0
      server.on('request', () => { requests++ })

      await new Promise<void>((resolve) => server.listen(0, resolve))
      const port = (server.address() as AddressInfo)?.port
      process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS = 'LOCALHOST'

      try {
        await webhook.notify(challenge, 0, 0, 0, `http://localhost:${port}`)
        expect(requests).to.equal(1)
      } finally {
        delete process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS
        server.close()
      }
    })

    it('notifies webhooks whose IPv6 host is in SOLUTIONS_WEBHOOK_ALLOWED_HOSTS', async () => {
      const server = http.createServer((req, res) => {
        res.statusCode = 200
        res.end('OK')
      })
      let requests = 0
      server.on('request', () => { requests++ })

      await new Promise<void>((resolve) => server.listen(0, '::1', resolve))
      const port = (server.address() as AddressInfo)?.port
      process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS = '[::1]:443'

      try {
        await webhook.notify(challenge, 0, 0, 0, `http://[::1]:${port}`)
        expect(requests).to.equal(1)
      } finally {
        delete process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS
        server.close()
      }
    })

    it('submits POST with payload to existing URL', async () => {
      const server = http.createServer((req, res) => {
        res.statusCode = 200
        res.end('OK')
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))

      const port = (server.address() as AddressInfo)?.port
      const url = `http://localhost:${port}`

      try {
        await webhook.notify(challenge, 0, 0, 0, url)
      } finally {
        server.close()
      }
    })
  })
})
