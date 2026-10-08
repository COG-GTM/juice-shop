/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAuIue//RvKVw0rBDan1YUKHAok7/DIjuqMxwZlNkIjexo5zXw\r\n0V3H3ydmGisjRXv8wRh3dN2P8IHDXQ4qqNHNpmvlKL3tT7VfxIB2HVTphUmMdmxX\r\nuAaiwoo/wngsLDHDNj/LA3tQU4Z65jiu0zlZ8EKgJfJ2/1SnTqrj4RO9pKIUGEoi\r\nHuVCNCnuCwxbHSoQY90zZ05qZ96/IsvNhIuX8CyTfgltWzUZ5+te2FT8U5hOmuvq\r\n//yCRd03Itm1d2Wh+ih0JRwUGbSy4vk9DN8MZtLK4CFKtpo+f+y/zMdab8UMe+U7\r\nrCJAIvFXfUjQw0ziToEBtMktxzZuOKEi7gQEVwIDAQABAoIBAAP9wqbG5fySab7R\r\nVbK3TUcbaq7Y9kk9DYJLeK/ECq/r5zaEIr0BQ6H4G5I0HdaSRulaNE/+I4kDe9kw\r\nX3Ke280rBwRcwmj3g3NTH+4K3xeqro04UwrzQcpMhfJ++aplbSAB1mWXevZDfoPD\r\nwawzalZZUPAt9uFKagMejEBa7/GpvwcOrvOhqr48nR/njFFnQWCkcASOb1Jo/0HP\r\niHpnu8uLlm3AxIPhK3jyia26SBgEeFG0UL/4L94/RbW32uAztXfKmkzj7zgnYbXb\r\nPkt2F9zloSFmPnqvUbxr5UusyQW7tmDZswuqcD4l9TpEWiYYh3gwFfJQfCGtCR1v\r\n9Tcl7dkCgYEA+a+7uzFBjqPunOcQYwHYbB6V5oFfUfpHNjd4OjwxabGg97zZc1uu\r\np77rRmgpaE5zwq4Pygqosaszo9elaYCAUvDTiN0aLdhoZZODv87ZStbTHc4wUA/l\r\nl/Ov11b2iSKKRGy3ztgKK1SboxcU1vgZQBaMpHbDgc9gHVMqR/HnsjUCgYEAvTY3\r\ntNwd30n7NN8V5qsXV+0Zz7LiJkE/h0GWtgHpTD9zl3d/isS9EmDYB+saKc1XDqg4\r\njm4h4wU8Bg59HujPjOVpyAJI5XsFhsY87iRp7/tNTF1xIKD2Y8Sej+SpNbNlUEir\r\nnqXOVe/ttmGnvtVNSXHLcwYrzwzUjDI/XJv2bdsCgYATVr0fno0JU0Ej/fGS+Y2d\r\nsjDCDbsoSk5BsMIrIIZjPVLOXV4qRSud6nemmGK8pXbp2Tl32KOAP1ZcllNFfKJz\r\nyhtYOmfQrTZIx8gojwjddw4a/OFZEiIiRsmT0DSAIqC69AC4kJsZCBCV7S+8BrNN\r\n93ElO92grEMxgkOAFwhvEQKBgAevehfIkRYOxTtijFswO+SAZvn+xBzVraTqzxpZ\r\nfYZxVVqjqfSTBTMH5/56WDe2dYDM6G8wngPApK2CTSbCQhvw/Zj4LsnTc2gECVmK\r\n9RqgVIVzjjLLFvb6d45UtWLPBKB8Myxgg78N3dP4p32i4F7JVoA3kfP5C3EeYWB7\r\nnUjdAoGBAJcLUiMhzr3f0+wD3ohaa+9SymzxhCFRi3XXi8BksTRNXleN4VyZFdot\r\nBIYSfx1vQTah4gKJ48zQhnCgnilyanlRBG9+Y3LEUttO922jXcUR8Pp3JMnTce+8\r\nbVC8Jejrrgg7feMa9OUoPU8VuhgDaVyqVrW+3ZEhTT/ZN7MpJRBG\r\n-----END RSA PRIVATE KEY-----'

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
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
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

const jwtAlgorithms: jwt.Algorithm[] = ['RS256']

export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: jwtAlgorithms })
export const denyAll = () => expressjwt({ secret: crypto.randomBytes(32).toString('hex'), algorithms: ['HS256'] })
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => {
  if (!token) return false
  try {
    jwt.verify(token, publicKey, { algorithms: jwtAlgorithms })
    return true
  } catch {
    return false
  }
}
export const decode = (token: string): any => jwt.decode(token)

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
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
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

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
