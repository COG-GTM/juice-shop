/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as webhook from '../../lib/webhook'
import { type AddressInfo } from 'node:net'
import http from 'node:http'
import chai from 'chai'
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

    it('refuses plaintext HTTP webhooks on non-loopback hosts', async () => {
      try {
        await webhook.notify(challenge, 0, 0, 0, 'http://example.com/hook')
        chai.assert.fail('Expected error was not thrown')
      } catch (error) {
        expect((error as Error).message).to.equal('Refusing to send solution data to non-HTTPS webhook host example.com')
      }
    })

    it('refuses webhook hosts missing from the allowlist', async () => {
      process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS = 'hooks.example.com'
      try {
        await webhook.notify(challenge, 0, 0, 0, 'https://other.example.com/hook')
        chai.assert.fail('Expected error was not thrown')
      } catch (error) {
        expect((error as Error).message).to.equal('Webhook host other.example.com is not in SOLUTIONS_WEBHOOK_ALLOWED_HOSTS')
      } finally {
        delete process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS
      }
    })

    it('matches allowlist entries case-insensitively', async () => {
      const server = http.createServer((req, res) => {
        res.statusCode = 200
        res.end('OK')
      })

      await new Promise<void>((resolve) => server.listen(0, resolve))

      const port = (server.address() as AddressInfo)?.port
      process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS = 'LOCALHOST'

      try {
        await webhook.notify(challenge, 0, 0, 0, `http://localhost:${port}`)
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
