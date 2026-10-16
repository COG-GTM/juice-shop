/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns'
import http, { type IncomingMessage } from 'node:http'
import https from 'node:https'
import net, { type LookupFunction } from 'node:net'
import fileType from 'file-type'

const REQUEST_TIMEOUT = 10000
export const MAX_IMAGE_SIZE = 1000000

const ALLOWED_IMAGE_TYPES: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif'
}

const deniedRanges = new net.BlockList()
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as Array<[string, number]>) {
  deniedRanges.addSubnet(network, prefix, 'ipv4')
}
for (const [network, prefix] of [
  ['::', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 32], ['2001:db8::', 32],
  ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]
] as Array<[string, number]>) {
  deniedRanges.addSubnet(network, prefix, 'ipv6')
}

export function isDeniedAddress (address: string): boolean {
  const plainAddress = address.replace(/^\[|\]$/g, '').split('%')[0]
  const family = net.isIP(plainAddress)
  if (family === 0) return true
  return deniedRanges.check(plainAddress, family === 4 ? 'ipv4' : 'ipv6')
}

export const publicOnlyLookup: LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { family: options.family, hints: options.hints, all: true }, (error, addresses) => {
    if (error !== null) {
      callback(error, [])
      return
    }
    const denied = addresses.find(({ address }) => isDeniedAddress(address))
    if (denied !== undefined || addresses.length === 0) {
      callback(new Error(`${hostname} resolves to the non-public address ${denied?.address ?? 'none'}`), [])
      return
    }
    if (options.all === true) {
      callback(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

export function parseImageUrl (imageUrl: unknown): URL {
  let url: URL
  try {
    url = new URL(String(imageUrl))
  } catch {
    throw new Error('not a valid URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`unsupported protocol ${url.protocol}`)
  }
  if (url.username !== '' || url.password !== '') {
    throw new Error('URLs with credentials are not supported')
  }
  if (net.isIP(url.hostname.replace(/^\[|\]$/g, '')) !== 0 && isDeniedAddress(url.hostname)) {
    throw new Error(`${url.hostname} is a non-public address`)
  }
  return url
}

async function readLimited (response: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of response) {
    size += chunk.length
    if (size > MAX_IMAGE_SIZE) {
      response.destroy()
      throw new Error(`image exceeds ${MAX_IMAGE_SIZE} bytes`)
    }
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

/**
 * Downloads an image only from publicly routable http(s) hosts, without following redirects,
 * and only if both the Content-Type and the actual file signature are an allowed raster image.
 */
export async function fetchPublicImage (imageUrl: unknown): Promise<{ buffer: Buffer, extension: string }> {
  const url = parseImageUrl(imageUrl)
  const client = url.protocol === 'https:' ? https : http
  const response = await new Promise<IncomingMessage>((resolve, reject) => {
    const request = client.get(url, { lookup: publicOnlyLookup, timeout: REQUEST_TIMEOUT, headers: { accept: 'image/png,image/jpeg,image/gif' } }, resolve)
    request.on('timeout', () => request.destroy(new Error('url did not respond in time')))
    request.on('error', reject)
  })
  try {
    const remoteAddress = response.socket.remoteAddress
    if (remoteAddress === undefined || isDeniedAddress(remoteAddress)) {
      throw new Error(`connected to the non-public address ${remoteAddress ?? 'unknown'}`)
    }
    if (response.statusCode !== 200) {
      throw new Error(`url returned status code ${response.statusCode ?? 'unknown'}`)
    }
    const contentType = response.headers['content-type']?.split(';')[0].trim().toLowerCase() ?? ''
    if (ALLOWED_IMAGE_TYPES[contentType] === undefined) {
      throw new Error(`url returned unsupported content type "${contentType}"`)
    }
    if (Number(response.headers['content-length'] ?? 0) > MAX_IMAGE_SIZE) {
      throw new Error(`image exceeds ${MAX_IMAGE_SIZE} bytes`)
    }
    const buffer = await readLimited(response)
    const detected = await fileType.fromBuffer(buffer)
    const extension = detected !== undefined ? ALLOWED_IMAGE_TYPES[detected.mime] : undefined
    if (extension === undefined) {
      throw new Error('url content is not a supported image')
    }
    return { buffer, extension }
  } finally {
    response.destroy()
  }
}
