/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { utils } from 'ethers'

export const SOLC_BINARIES_BASE_URL = 'https://binaries.soliditylang.org/bin/'

export interface SolcRelease {
  version: string
  file: string
  sha256: string
}

export const SOLC_RELEASES: readonly SolcRelease[] = [
  { version: '0.8.21', file: 'soljson-v0.8.21+commit.d9974bed.js', sha256: '45bea352b41d04039e19439962ddef1d3e10cf2bc9526feba39f2cc79e3c5a17' },
  { version: '0.8.9', file: 'soljson-v0.8.9+commit.e5eed63a.js', sha256: '5b25f987aae32a0275fdc6c1be36cc47cf126024a04dafd8e4be39a1d1d1422c' },
  { version: '0.7.6', file: 'soljson-v0.7.6+commit.7338295f.js', sha256: 'b94e69dfb056b3e26080f805ab43b668afbc0ac70bf124bfb7391ecfc0172ad2' },
  { version: '0.6.12', file: 'soljson-v0.6.12+commit.27d51765.js', sha256: '3e1956c550ca48e289044c7c0bd892403081b4b5e17e77ce707c815ce6c4228f' },
  { version: '0.5.17', file: 'soljson-v0.5.17+commit.d19bba13.js', sha256: 'dac1bc7560247d3e69bce9891f7eb2218a6a8d0106d9cdb4de8e03ede4546153' },
  { version: '0.4.26', file: 'soljson-v0.4.26+commit.4563c3fc.js', sha256: '357adb49bb74c9eabaa034db28f96b4105def2b052c7795db8e30ad9a34cc551' },
  { version: '0.3.6', file: 'soljson-v0.3.6+commit.3fc68da5.js', sha256: 'e6092a90398b8519fe2ad7c582074b806e365ebd55fc86d7d2d5c27513732373' },
  { version: '0.2.2', file: 'soljson-v0.2.2+commit.ef92f566.js', sha256: '04f5e3c386833a5a0e15e204dec859a2499c8d7da69b89544e475c25004c4602' },
  { version: '0.1.7', file: 'soljson-v0.1.7+commit.b4e666cc.js', sha256: '41a0cbd38f6fb957ed3748688078f6e6186d9a2e8b6706de9a63dbf65c62ffd3' }
]

export async function fetchVerifiedSolcBundle (release: SolcRelease): Promise<string> {
  const response = await fetch(SOLC_BINARIES_BASE_URL + release.file)
  if (!response.ok) {
    throw new Error(`Failed to download Solidity compiler ${release.version} (HTTP ${response.status})`)
  }
  const bytes = await response.arrayBuffer()
  const digest = utils.sha256(new Uint8Array(bytes)).slice(2)
  if (digest !== release.sha256) {
    throw new Error(`Integrity check failed for Solidity compiler ${release.version}`)
  }
  return URL.createObjectURL(new Blob([bytes], { type: 'text/javascript' }))
}
