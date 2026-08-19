/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns'
import https from 'node:https'
import net, { type LookupFunction } from 'node:net'
import { type IncomingMessage } from 'node:http'

const REQUEST_TIMEOUT = 10000

const SUPPORTED_IMAGE_TYPES: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/svg+xml': 'svg',
  'image/gif': 'gif'
}

const DENIED_IPV4_BLOCKS: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local incl. cloud metadata
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4] // reserved incl. broadcast
]

function ipv4ToNumber (address: string): number {
  return address.split('.').reduce((number, octet) => (number << 8) + Number(octet), 0) >>> 0
}

function isDeniedIpv4Address (address: string): boolean {
  const number = ipv4ToNumber(address)
  return DENIED_IPV4_BLOCKS.some(([block, prefix]) => (number ^ ipv4ToNumber(block)) >>> (32 - prefix) === 0)
}

function ipv6ToBytes (address: string): number[] | undefined {
  const [head, tail] = address.split('::')
  const headGroups = head === '' ? [] : head.split(':')
  const tailGroups = tail === undefined || tail === '' ? [] : tail.split(':')
  const embeddedIpv4Groups = net.isIPv4([...headGroups, ...tailGroups].slice(-1)[0] ?? '') ? 1 : 0 // an embedded IPv4 address fills two groups
  const missingGroups = 8 - headGroups.length - tailGroups.length - embeddedIpv4Groups
  const groups = tail === undefined ? headGroups : [...headGroups, ...Array(missingGroups).fill('0'), ...tailGroups]

  const bytes: number[] = []
  for (const [index, group] of groups.entries()) {
    if (index === groups.length - 1 && net.isIPv4(group)) {
      bytes.push(...group.split('.').map(Number))
    } else {
      const value = Number.parseInt(group, 16)
      bytes.push(value >> 8, value & 0xff)
    }
  }
  return bytes.length === 16 ? bytes : undefined
}

function bytesToIpv4 (bytes: number[]): string {
  return bytes.join('.')
}

function isDeniedIpv6Address (address: string): boolean {
  const bytes = ipv6ToBytes(address)
  if (bytes === undefined) return true

  const isPrefixedWith = (prefix: number[]) => prefix.every((byte, index) => bytes[index] === byte)

  if (isPrefixedWith([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])) return isDeniedIpv4Address(bytesToIpv4(bytes.slice(12))) // IPv4-mapped
  if (isPrefixedWith([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])) return true // unspecified, loopback and IPv4-compatible
  if (isPrefixedWith([0x00, 0x64, 0xff, 0x9b])) return isDeniedIpv4Address(bytesToIpv4(bytes.slice(12))) // NAT64
  if (isPrefixedWith([0x20, 0x02])) return isDeniedIpv4Address(bytesToIpv4(bytes.slice(2, 6))) // 6to4
  if ((bytes[0] & 0xfe) === 0xfc) return true // unique local
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true // link-local
  if (bytes[0] === 0xff) return true // multicast
  return false
}

/** Denies loopback, private, link-local (incl. cloud metadata) and otherwise non-globally-routable addresses. */
export function isDeniedIpAddress (address: string): boolean {
  const [plainAddress] = address.split('%') // strip IPv6 zone index
  if (net.isIPv4(plainAddress)) return isDeniedIpv4Address(plainAddress)
  if (net.isIPv6(plainAddress)) return isDeniedIpv6Address(plainAddress)
  return true
}

/** DNS lookup that refuses to hand out any address the request must not connect to. */
export const safeLookup: LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { family: options.family, hints: options.hints, all: true }, (error, addresses) => {
    if (error !== null) {
      callback(error, [])
      return
    }
    const deniedAddress = addresses.find(({ address }) => isDeniedIpAddress(address))
    if (deniedAddress !== undefined) {
      callback(new Error(`${hostname} resolves to the non-public address ${deniedAddress.address}`), [])
      return
    }
    if (options.all === true) {
      callback(null, addresses)
    } else {
      callback(null, addresses[0].address, addresses[0].family)
    }
  })
}

export function parseExternalImageUrl (imageUrl: string): URL {
  let url: URL
  try {
    url = new URL(imageUrl)
  } catch {
    throw new Error(`"${imageUrl}" is not a valid URL`)
  }
  if (url.protocol !== 'https:') {
    throw new Error(`Only https URLs are accepted but got "${url.protocol}"`)
  }
  if (url.username !== '' || url.password !== '') {
    throw new Error('URLs with embedded credentials are not accepted')
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '') // IPv6 literals are bracketed and never passed through the DNS lookup
  if (net.isIP(hostname) !== 0 && isDeniedIpAddress(hostname)) {
    throw new Error(`${hostname} is a non-public address`)
  }
  return url
}

/**
 * Retrieves an image from a URL under user control without exposing internal infrastructure:
 * only https URLs are accepted, every resolved address must be globally routable, redirects are
 * not followed and the response has to be an actual image.
 */
export async function fetchExternalImage (imageUrl: string): Promise<{ stream: IncomingMessage, extension: string }> {
  const url = parseExternalImageUrl(imageUrl)
  return await new Promise<{ stream: IncomingMessage, extension: string }>((resolve, reject) => {
    const request = https.get(url, { lookup: safeLookup, timeout: REQUEST_TIMEOUT }, (response) => {
      const abort = (message: string) => {
        response.destroy()
        request.destroy()
        reject(new Error(message))
      }
      const remoteAddress = response.socket.remoteAddress
      if (remoteAddress === undefined || isDeniedIpAddress(remoteAddress)) {
        abort(`${url.hostname} connected to the non-public address ${remoteAddress ?? 'unknown'}`)
        return
      }
      if (response.statusCode !== 200) {
        abort(`url returned a non-OK status code (${response.statusCode ?? 'unknown'})`)
        return
      }
      const contentType = response.headers['content-type']?.split(';')[0].trim().toLowerCase()
      const extension = contentType !== undefined ? SUPPORTED_IMAGE_TYPES[contentType] : undefined
      if (extension === undefined) {
        abort(`url returned the unsupported content type "${contentType ?? 'none'}"`)
        return
      }
      resolve({ stream: response, extension })
    })
    request.on('timeout', () => {
      request.destroy(new Error('url did not respond in time'))
    })
    request.on('error', reject)
  })
}
