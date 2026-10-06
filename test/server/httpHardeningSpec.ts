/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { allowedCorsOrigins, cookieSecret, corsOptions, productionErrorHandler } from '../../lib/httpHardening'
const expect = chai.expect

const fakeResponse = (statusCode = 200) => {
  const res: any = { statusCode, headersSent: false, headers: {}, body: undefined }
  res.setHeader = (name: string, value: string) => { res.headers[name.toLowerCase()] = value }
  res.end = (body: string) => { res.body = body }
  return res
}

const fakeRequest = (accept: 'html' | 'json' = 'html'): any => ({ method: 'GET', path: '/rest/x', accepts: () => accept })

const resolveOrigin = async (allowed: string[], origin: string | undefined) => await new Promise((resolve) => {
  (corsOptions(allowed).origin as any)(origin, (_err: unknown, allow: unknown) => { resolve(allow) })
})

describe('httpHardening', () => {
  describe('productionErrorHandler', () => {
    it('answers 5xx errors with the generic status text instead of message and stack trace', () => {
      const res = fakeResponse()
      productionErrorHandler()(new Error('SQLITE_ERROR: near "union": syntax error'), fakeRequest(), res, () => {})
      expect(res.statusCode).to.equal(500)
      expect(res.body).to.equal('Internal Server Error')
      expect(res.body).not.to.contain('SQLITE_ERROR')
      expect(res.body).not.to.contain('at ')
    })

    it('answers JSON clients without a stack property', () => {
      const res = fakeResponse()
      productionErrorHandler()(new Error('Unexpected path: /rest/x'), fakeRequest('json'), res, () => {})
      expect(JSON.parse(res.body)).to.deep.equal({ error: { message: 'Internal Server Error' } })
      expect(res.headers['content-type']).to.contain('application/json')
    })

    it('keeps the escaped message but no stack trace for client errors', () => {
      const res = fakeResponse(403)
      productionErrorHandler()(new Error('Only <md> files are allowed!'), fakeRequest(), res, () => {})
      expect(res.statusCode).to.equal(403)
      expect(res.body).to.equal('Error: Only &#60;md&#62; files are allowed!')
    })

    it('uses the status carried by the error', () => {
      const res = fakeResponse()
      productionErrorHandler()(Object.assign(new Error('Payload too large'), { status: 413 }), fakeRequest(), res, () => {})
      expect(res.statusCode).to.equal(413)
    })

    it('logs the stack trace server-side', () => {
      const logged: string[] = []
      productionErrorHandler((message) => logged.push(message))(new Error('boom'), fakeRequest(), fakeResponse(), () => {})
      expect(logged[0]).to.contain('GET /rest/x failed with 500')
      expect(logged[0]).to.contain('Error: boom\n    at ')
    })

    it('delegates to the next handler once headers are sent', () => {
      const res = fakeResponse()
      res.headersSent = true
      const err = new Error('late')
      let forwarded: unknown
      productionErrorHandler()(err, fakeRequest(), res, (e?: unknown) => { forwarded = e })
      expect(forwarded).to.equal(err)
      expect(res.body).to.equal(undefined)
    })
  })

  describe('CORS', () => {
    it('defaults to the base URL origin and the Angular dev server', () => {
      expect(allowedCorsOrigins('http://localhost:3000/', undefined)).to.deep.equal(['http://localhost:3000', 'http://localhost:4200'])
    })

    it('reads origins from CORS_ALLOWED_ORIGINS and drops wildcards and invalid entries', () => {
      expect(allowedCorsOrigins('http://localhost:3000', ' https://shop.example ,*,null,not a url')).to.deep.equal(['https://shop.example'])
    })

    it('allows only listed origins', async () => {
      expect(await resolveOrigin(['http://localhost:3000'], 'http://localhost:3000')).to.equal(true)
      expect(await resolveOrigin(['http://localhost:3000'], 'https://attacker.example')).to.equal(false)
      expect(await resolveOrigin(['http://localhost:3000'], undefined)).to.equal(false)
    })
  })

  describe('cookieSecret', () => {
    it('uses COOKIE_PARSER_SECRET when configured', () => {
      expect(cookieSecret('from-env')).to.equal('from-env')
    })

    it('falls back to a random secret instead of a hardcoded one', () => {
      const secret = cookieSecret(undefined)
      expect(secret).to.match(/^[0-9a-f]{64}$/)
      expect(secret).not.to.equal('kekse')
      expect(cookieSecret('')).not.to.equal(secret)
    })
  })
})
