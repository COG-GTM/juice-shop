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

const familyOf = (address: string) => {
  const family = isIP(address)
  return family === 4 ? 'ipv4' : family === 6 ? 'ipv6' : undefined
}

/* Proxies may connect from loopback/private networks or from addresses listed in JUICE_SHOP_TRUSTED_PROXIES (comma-separated IPs or CIDRs), so other clients connecting directly cannot claim to be one */
export const trustedProxies = (value = process.env.JUICE_SHOP_TRUSTED_PROXIES) => {
  const trusted = new BlockList()
  for (const [network, prefix] of [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['127.0.0.0', 8], ['169.254.0.0', 16]] as const) trusted.addSubnet(network, prefix, 'ipv4')
  for (const [network, prefix] of [['::1', 128], ['fc00::', 7], ['fe80::', 10]] as const) trusted.addSubnet(network, prefix, 'ipv6')
  for (const entry of (value ?? '').split(',').map(entry => entry.trim()).filter(entry => entry !== '')) {
    const [network, prefix] = entry.split('/')
    const family = familyOf(network)
    const bits = prefix === undefined ? (family === 'ipv4' ? 32 : 128) : Number(prefix)
    if (family !== undefined && Number.isInteger(bits) && bits >= 0 && bits <= (family === 'ipv4' ? 32 : 128)) trusted.addSubnet(network, bits, family)
  }
  return trusted
}

const isTrustedProxy = (address: string, trusted: BlockList) => [address, address.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '')].some(candidate => {
  const family = familyOf(candidate)
  return family !== undefined && trusted.check(candidate, family)
})

/* Resolved independently of req.ip, which follows the client-controlled X-Forwarded-For header while 'trust proxy' is enabled */
export const clientKey = (req: Request, hops = trustedProxyHops(), trusted = trustedProxies()) => {
  const forwardedFor = req.headers['x-forwarded-for']
  const forwarded = (Array.isArray(forwardedFor) ? forwardedFor.join(',') : forwardedFor ?? '').split(',').map(address => address.trim()).filter(address => address !== '')
  const chain = [req.socket?.remoteAddress ?? 'unknown', ...forwarded.reverse()]
  let client = 0
  while (client < hops && client < chain.length - 1 && isTrustedProxy(chain[client], trusted)) client++
  return chain[client]
}

export const accountKey = (req: Request) => {
  const userId = security.verifySecondFactorToken(req.body?.tmpToken)?.userId
  return userId !== undefined && userId !== null && userId !== '' ? `2fa-user:${userId}` : undefined
}

export const perClient = (hops = trustedProxyHops(), trusted = trustedProxies()) => rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator: (req: Request) => clientKey(req, hops, trusted),
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
