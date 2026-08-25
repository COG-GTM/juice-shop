/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import net from 'node:net'

const ALLOWED_PROTOCOLS = ['http:', 'https:']

function ipv4ToNumber (address: string): number | null {
  const octets = address.split('.')
  if (octets.length !== 4) {
    return null
  }
  let value = 0
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) {
      return null
    }
    const parsed = Number(octet)
    if (parsed > 255) {
      return null
    }
    value = value * 256 + parsed
  }
  return value
}

function isForbiddenIpv4 (address: string): boolean {
  const value = ipv4ToNumber(address)
  if (value === null) {
    return true
  }
  const blocks: Array<[string, number]> = [
    ['0.0.0.0', 8], // "this host on this network"
    ['10.0.0.0', 8], // private
    ['100.64.0.0', 10], // carrier-grade NAT
    ['127.0.0.0', 8], // loopback
    ['169.254.0.0', 16], // link-local, includes cloud metadata service
    ['172.16.0.0', 12], // private
    ['192.0.0.0', 24], // IETF protocol assignments
    ['192.0.2.0', 24], // documentation
    ['192.88.99.0', 24], // 6to4 relay anycast
    ['192.168.0.0', 16], // private
    ['198.18.0.0', 15], // benchmarking
    ['198.51.100.0', 24], // documentation
    ['203.0.113.0', 24], // documentation
    ['224.0.0.0', 4], // multicast
    ['240.0.0.0', 4] // reserved, includes broadcast
  ]
  return blocks.some(([network, prefix]) => {
    const base = ipv4ToNumber(network)
    if (base === null) {
      return false
    }
    const mask = prefix === 0 ? 0 : (-1 << (32 - prefix)) >>> 0
    return (value & mask) === (base & mask)
  })
}

function expandIpv6 (address: string): number[] | null {
  const [head, tail] = address.split('::')
  const parseGroups = (part: string) => part === '' ? [] : part.split(':')
  const headGroups = parseGroups(head ?? '')
  const tailGroups = tail === undefined ? [] : parseGroups(tail)
  const groups = tail === undefined
    ? headGroups
    : [...headGroups, ...Array(8 - headGroups.length - tailGroups.length).fill('0'), ...tailGroups]
  if (groups.length !== 8) {
    return null
  }
  const words: number[] = []
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      return null
    }
    words.push(Number.parseInt(group, 16))
  }
  return words
}

function isForbiddenIpv6 (address: string): boolean {
  const normalized = address.toLowerCase().split('%')[0]
  const embeddedIpv4 = normalized.match(/(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (embeddedIpv4 !== null) {
    // IPv4-mapped, IPv4-compatible and NAT64 addresses inherit the IPv4 restrictions
    return isForbiddenIpv4(embeddedIpv4[1])
  }
  const words = expandIpv6(normalized)
  if (words === null) {
    return true
  }
  if (words.every((word) => word === 0)) {
    return true // unspecified address ::
  }
  if (words.slice(0, 7).every((word) => word === 0) && words[7] === 1) {
    return true // loopback ::1
  }
  if ((words[0] & 0xfe00) === 0xfc00) {
    return true // unique local fc00::/7
  }
  if ((words[0] & 0xffc0) === 0xfe80) {
    return true // link-local fe80::/10
  }
  if ((words[0] & 0xff00) === 0xff00) {
    return true // multicast ff00::/8
  }
  if (words[0] === 0x2001 && words[1] === 0x0db8) {
    return true // documentation 2001:db8::/32
  }
  return false
}

export function isForbiddenAddress (address: string): boolean {
  const version = net.isIP(address)
  if (version === 4) {
    return isForbiddenIpv4(address)
  }
  if (version === 6) {
    return isForbiddenIpv6(address)
  }
  return true
}

/**
 * Parses a user-supplied URL that the server is about to fetch and rejects
 * anything that could be abused for server-side request forgery: non-HTTP(S)
 * schemes, embedded credentials and hosts that resolve to loopback, private,
 * link-local (including the cloud metadata service) or otherwise reserved
 * addresses.
 */
export async function assertSafeFetchUrl (candidate: string): Promise<URL> {
  const url = new URL(candidate)
  if (!ALLOWED_PROTOCOLS.includes(url.protocol)) {
    throw new Error(`url uses the unsupported protocol ${url.protocol}`)
  }
  if (url.username !== '' || url.password !== '') {
    throw new Error('url must not contain credentials')
  }
  const hostname = url.hostname.replace(/^\[/, '').replace(/\]$/, '')
  if (hostname === '') {
    throw new Error('url has no hostname')
  }
  if (net.isIP(hostname) !== 0) {
    if (isForbiddenAddress(hostname)) {
      throw new Error(`url points to the non-public address ${hostname}`)
    }
    return url
  }
  const records = await dns.lookup(hostname, { all: true, verbatim: true })
  if (records.length === 0) {
    throw new Error(`url hostname ${hostname} could not be resolved`)
  }
  for (const record of records) {
    if (isForbiddenAddress(record.address)) {
      throw new Error(`url hostname ${hostname} resolves to the non-public address ${record.address}`)
    }
  }
  return url
}
