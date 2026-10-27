/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { BlockList, isIP } from 'node:net'
import { type Request } from 'express'
import { rateLimit } from 'express-rate-limit'
import * as security from './insecurity'

export const maxFailedAttemptsPerAccount = 5

/* Number of reverse proxies in front of the server; only the X-Forwarded-For entries they appended are trusted */
export const trustedProxyHops = (value = process.env.JUICE_SHOP_TRUSTED_PROXY_HOPS) => {
  const hops = Number(value)
  return value !== undefined && Number.isInteger(hops) && hops > 0 ? hops : 0
}

const privateNetworks = new BlockList()
for (const [network, prefix] of [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['127.0.0.0', 8], ['169.254.0.0', 16]] as const) privateNetworks.addSubnet(network, prefix, 'ipv4')
for (const [network, prefix] of [['::1', 128], ['fc00::', 7], ['fe80::', 10]] as const) privateNetworks.addSubnet(network, prefix, 'ipv6')

/* Proxies must sit on a loopback or private network, so clients connecting directly from outside cannot claim to be one */
const isPrivateAddress = (address: string) => {
  const unmapped = address.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '')
  const family = isIP(unmapped)
  return family !== 0 && privateNetworks.check(unmapped, family === 4 ? 'ipv4' : 'ipv6')
}

/* Resolved independently of req.ip, which follows the client-controlled X-Forwarded-For header while 'trust proxy' is enabled */
export const clientKey = (req: Request, hops = trustedProxyHops()) => {
  const forwardedFor = req.headers['x-forwarded-for']
  const forwarded = (Array.isArray(forwardedFor) ? forwardedFor.join(',') : forwardedFor ?? '').split(',').map(address => address.trim()).filter(address => address !== '')
  const chain = [req.socket?.remoteAddress ?? 'unknown', ...forwarded.reverse()]
  let client = 0
  while (client < hops && client < chain.length - 1 && isPrivateAddress(chain[client])) client++
  return chain[client]
}

export const accountKey = (req: Request) => {
  const userId = security.verifySecondFactorToken(req.body?.tmpToken)?.userId
  return userId !== undefined && userId !== null && userId !== '' ? `2fa-user:${userId}` : undefined
}

export const perClient = () => rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator: (req: Request) => clientKey(req),
  validate: { trustProxy: false }
})

/* Locks second-factor verification for an account after a few failed codes, regardless of client address */
export const perAccount = () => rateLimit({
  windowMs: 15 * 60 * 1000,
  max: maxFailedAttemptsPerAccount,
  skipSuccessfulRequests: true,
  skip: (req: Request) => accountKey(req) === undefined,
  keyGenerator: (req: Request) => accountKey(req) as string,
  validate: { trustProxy: false }
})
