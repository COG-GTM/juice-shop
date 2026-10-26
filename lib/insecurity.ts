/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  revokedTokens: Record<string, number>
  sessionsValidAfter: Record<string, number>
  exemptTokens: Record<string, number>
  issuedTokens: Record<string, number>
  lastSweep: number
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
  remove: (token: string) => void
  revoke: (token?: string) => void
  revokeAllFor: (userId: number, exceptToken?: string) => void
  isRevoked: (token?: string) => boolean
  sweep: () => void
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const sessionTokenLifetimeInSeconds = 6 * 60 * 60
const sweepIntervalInSeconds = 60
const nowInSeconds = () => Math.floor(Date.now() / 1000)

export const isAuthorized = () => {
  const checkJwt = expressJwt(({ secret: publicKey }) as any)
  return (req: Request, res: Response, next: NextFunction) => {
    checkJwt(req, res, (err?: unknown) => {
      if (!err && authenticatedUsers.isRevoked(utils.jwtFrom(req))) {
        next(Object.assign(new Error('jwt revoked'), { name: 'UnauthorizedError', code: 'revoked_token', status: 401 }))
        return
      }
      next(err)
    })
  }
}
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
// exp is set explicitly because jsonwebtoken 0.4.0 ignores the expiresIn option
export const authorize = (user = {}) => {
  const exp = nowInSeconds() + sessionTokenLifetimeInSeconds
  const token = jwt.sign({ ...user, jti: crypto.randomUUID(), iat: nowInSeconds(), exp }, privateKey, { algorithm: 'RS256' })
  authenticatedUsers.sweep()
  if ((user as { data?: { id?: unknown } }).data?.id !== undefined) {
    authenticatedUsers.issuedTokens[token] = exp
  }
  return token
}
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
export const decode = (token: string) => { return jws.decode(token)?.payload }

const claimsOf = (token: string) => {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))
  } catch {
    return undefined
  }
}

const expiryOf = (token: string) => {
  const exp = claimsOf(token)?.exp
  return typeof exp === 'number' ? exp : undefined
}

const hasValidSignature = (token: string) => {
  try {
    return verify(token)
  } catch {
    return false
  }
}

export const isLiveSessionToken = (token?: string) => {
  if (!token) return false
  const exp = expiryOf(token)
  return exp !== undefined && exp > nowInSeconds() && !authenticatedUsers.isRevoked(token) && hasValidSignature(token)
}

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  revokedTokens: {},
  sessionsValidAfter: {},
  exemptTokens: {},
  issuedTokens: {},
  lastSweep: 0,
  put: function (token: string, user: ResponseWithUser) {
    this.sweep()
    if (!isLiveSessionToken(token)) return
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    if (!token) return undefined
    this.sweep()
    const key = utils.unquote(token)
    if (!Object.prototype.hasOwnProperty.call(this.tokenMap, key)) return undefined
    if (!isLiveSessionToken(key)) {
      this.remove(key)
      return undefined
    }
    return this.tokenMap[key]
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  },
  remove: function (token: string) {
    if (!Object.prototype.hasOwnProperty.call(this.tokenMap, token)) return
    const user = this.tokenMap[token]
    delete this.tokenMap[token]
    if (this.idMap[user.data?.id] === token) {
      delete this.idMap[user.data.id]
    }
  },
  revoke: function (token?: string) {
    if (!token) return
    const key = utils.unquote(token)
    const exp = expiryOf(key)
    if (exp !== undefined && exp > nowInSeconds() && hasValidSignature(key)) {
      this.revokedTokens[key] = Math.min(exp, nowInSeconds() + sessionTokenLifetimeInSeconds)
    }
    this.remove(key)
  },
  revokeAllFor: function (userId: number, exceptToken?: string) {
    const keep = exceptToken ? utils.unquote(exceptToken) : undefined
    this.sessionsValidAfter[userId] = nowInSeconds()
    for (const token of Object.keys(this.exemptTokens)) {
      if (claimsOf(token)?.data?.id === userId) delete this.exemptTokens[token]
    }
    const keepExp = keep ? expiryOf(keep) : undefined
    if (keep && keepExp !== undefined && keepExp > nowInSeconds() && hasValidSignature(keep)) {
      this.exemptTokens[keep] = keepExp
    }
    for (const [token, user] of Object.entries(this.tokenMap)) {
      if (user.data?.id === userId && token !== keep) {
        this.revoke(token)
      }
    }
    for (const token of Object.keys(this.issuedTokens)) {
      if (claimsOf(token)?.data?.id === userId && token !== keep) {
        this.revoke(token)
        delete this.issuedTokens[token]
      }
    }
  },
  isRevoked: function (token?: string) {
    if (!token) return false
    const key = utils.unquote(token)
    if (Object.prototype.hasOwnProperty.call(this.revokedTokens, key)) return true
    const claims = claimsOf(key)
    const validAfter = this.sessionsValidAfter[claims?.data?.id]
    if (validAfter === undefined || Object.prototype.hasOwnProperty.call(this.exemptTokens, key)) return false
    return typeof claims.iat !== 'number' || claims.iat < validAfter
  },
  sweep: function () {
    const now = nowInSeconds()
    if (now - this.lastSweep < sweepIntervalInSeconds) return
    this.lastSweep = now
    for (const token of Object.keys(this.tokenMap)) {
      const exp = expiryOf(token)
      if (exp === undefined || exp <= now) this.remove(token)
    }
    for (const [token, exp] of Object.entries(this.revokedTokens)) {
      if (exp <= now) delete this.revokedTokens[token]
    }
    for (const [token, exp] of Object.entries(this.exemptTokens)) {
      if (exp <= now) delete this.exemptTokens[token]
    }
    for (const [token, exp] of Object.entries(this.issuedTokens)) {
      if (exp <= now) delete this.issuedTokens[token]
    }
    for (const [userId, validAfter] of Object.entries(this.sessionsValidAfter)) {
      if (validAfter + sessionTokenLifetimeInSeconds <= now) delete this.sessionsValidAfter[userId]
    }
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

const activeClaimsFrom = (req: Request) => {
  const token = utils.jwtFrom(req)
  return !authenticatedUsers.isRevoked(token) && verify(token) && decode(token)
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = activeClaimsFrom(req)
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = activeClaimsFrom(req)
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = activeClaimsFrom(req)
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = authenticatedUsers.from(req)
    if (user === undefined) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    req.body.UserId = user.data.id
    next()
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null && isLiveSessionToken(token)) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
