/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const ALLOWED_PROTOCOLS = ['http:', 'https:']

function ipv4ToLong (ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0
}

function isDisallowedIPv4 (ip: string): boolean {
  const value = ipv4ToLong(ip)
  const inRange = (base: string, bits: number): boolean => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
    return (value & mask) === (ipv4ToLong(base) & mask)
  }
  return (
    inRange('0.0.0.0', 8) || // "this" network
    inRange('10.0.0.0', 8) || // private
    inRange('100.64.0.0', 10) || // carrier-grade NAT
    inRange('127.0.0.0', 8) || // loopback
    inRange('169.254.0.0', 16) || // link-local (incl. cloud metadata 169.254.169.254)
    inRange('172.16.0.0', 12) || // private
    inRange('192.0.0.0', 24) || // IETF protocol assignments
    inRange('192.168.0.0', 16) || // private
    inRange('198.18.0.0', 15) || // benchmarking
    inRange('224.0.0.0', 4) || // multicast
    inRange('240.0.0.0', 4) // reserved
  )
}

function isDisallowedIPv6 (ip: string): boolean {
  const addr = ip.toLowerCase().replace(/^\[|\]$/g, '')
  const mapped = addr.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (mapped) return isDisallowedIPv4(mapped[1])
  if (addr === '::' || addr === '::1') return true // unspecified / loopback
  return /^(f[cd]|fe[89ab])/.test(addr) // unique-local (fc00::/7) and link-local (fe80::/10)
}

function isDisallowedAddress (ip: string): boolean {
  if (net.isIPv4(ip)) return isDisallowedIPv4(ip)
  if (net.isIPv6(ip)) return isDisallowedIPv6(ip)
  return true
}

async function isUrlSafeForServerSideFetch (rawUrl: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return false
  }
  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) return false
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  try {
    if (net.isIP(hostname) !== 0) {
      return !isDisallowedAddress(hostname)
    }
    const addresses = await dns.lookup(hostname, { all: true })
    if (addresses.length === 0) return false
    return addresses.every(({ address }) => !isDisallowedAddress(address))
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        if (await isUrlSafeForServerSideFetch(url)) {
          try {
            const response = await fetch(url, { redirect: 'error' })
            if (!response.ok || !response.body) {
              throw new Error('url returned a non-OK status code or an empty body')
            }
            if (!(response.headers.get('content-type') ?? '').startsWith('image/')) {
              throw new Error('url did not return an image')
            }
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
            const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
            await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
            await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
          } catch (error) {
            try {
              await user?.update({ profileImage: url })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            } catch (error) {
              next(error)
              return
            }
          }
        } else {
          try {
            await user?.update({ profileImage: url })
            logger.warn('Blocked server-side fetch of disallowed profile image URL; using image link directly')
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
