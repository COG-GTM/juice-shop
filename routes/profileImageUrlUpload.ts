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
const MAX_REDIRECTS = 5

// Rejects loopback, private, link-local (incl. cloud metadata 169.254.169.254),
// CGNAT, unspecified, multicast and reserved IP ranges to prevent SSRF.
function isBlockedAddress (address: string): boolean {
  const type = net.isIP(address)
  if (type === 4) {
    const [a, b] = address.split('.').map(Number)
    if (a === 0) return true
    if (a === 10) return true
    if (a === 127) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 100 && b >= 64 && b <= 127) return true
    if (a >= 224) return true
    return false
  }
  if (type === 6) {
    const addr = address.toLowerCase()
    const mapped = addr.match(/^::ffff:(.+)$/)
    if (mapped) {
      const rest = mapped[1]
      if (rest.includes('.')) return isBlockedAddress(rest)
      const groups = rest.split(':')
      if (groups.length === 2) {
        const hi = parseInt(groups[0] || '0', 16)
        const lo = parseInt(groups[1] || '0', 16)
        return isBlockedAddress(`${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`)
      }
    }
    if (addr === '::' || addr === '::1') return true
    if (addr.startsWith('fe80')) return true
    if (addr.startsWith('fc') || addr.startsWith('fd')) return true
    return false
  }
  return true
}

export async function isUrlAllowed (rawUrl: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return false
  }
  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) return false
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(hostname) !== 0) {
    return !isBlockedAddress(hostname)
  }
  try {
    const records = await dns.lookup(hostname, { all: true })
    return records.length > 0 && records.every(({ address }) => !isBlockedAddress(address))
  } catch {
    return false
  }
}

// Follows redirects manually, re-validating every hop so a redirect cannot be
// used to reach an internal/metadata host after the initial check.
async function safeFetch (rawUrl: string): Promise<Awaited<ReturnType<typeof fetch>>> {
  let currentUrl = rawUrl
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    if (!(await isUrlAllowed(currentUrl))) {
      throw new Error('Requested URL is not allowed')
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if (response.status >= 300 && response.status < 400 && response.headers.has('location')) {
      currentUrl = new URL(response.headers.get('location') as string, currentUrl).toString()
      continue
    }
    return response
  }
  throw new Error('Too many redirects while resolving URL')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await safeFetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
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
