/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { detectContainer, type ContainerProbe } from '../../lib/is-docker'
import isGitpod from '../../lib/is-gitpod'

import chai from 'chai'
const expect = chai.expect

function probe ({ env = {}, files = [], cgroup }: { env?: NodeJS.ProcessEnv, files?: string[], cgroup?: string } = {}): ContainerProbe {
  return {
    env,
    exists: (path) => files.includes(path),
    readFile: (path) => path === '/proc/self/cgroup' ? cgroup : undefined
  }
}

describe('isDocker', () => {
  it('is false on a host without any container markers', () => {
    expect(detectContainer(probe({ cgroup: '0::/user.slice/user-1000.slice/session-2.scope\n' }))).to.equal(false)
  })

  it('detects Docker Engine via /.dockerenv', () => {
    expect(detectContainer(probe({ files: ['/.dockerenv'] }))).to.equal(true)
  })

  it('detects Docker Engine via cgroup v1', () => {
    expect(detectContainer(probe({ cgroup: '12:pids:/docker/0123456789abcdef\n' }))).to.equal(true)
  })

  it('detects Podman via /run/.containerenv', () => {
    expect(detectContainer(probe({ files: ['/run/.containerenv'] }))).to.equal(true)
  })

  it('detects Podman/systemd style container env variable', () => {
    expect(detectContainer(probe({ env: { container: 'podman' } }))).to.equal(true)
  })

  it('detects Kubernetes pods running on containerd with cgroup v2', () => {
    expect(detectContainer(probe({ env: { KUBERNETES_SERVICE_HOST: '10.96.0.1' }, cgroup: '0::/\n' }))).to.equal(true)
  })

  it('detects containerd/CRI-O via cgroup v1 kubepods path', () => {
    expect(detectContainer(probe({ cgroup: '11:memory:/kubepods/besteffort/pod1234/cri-containerd-abcdef\n' }))).to.equal(true)
  })

  for (const value of ['true', 'TRUE', '1', 'yes']) {
    it(`honors explicit JUICE_SHOP_CONTAINER=${value} marker from the official image`, () => {
      expect(detectContainer(probe({ env: { JUICE_SHOP_CONTAINER: value }, cgroup: '0::/\n' }))).to.equal(true)
    })
  }

  for (const value of ['false', '0', '']) {
    it(`ignores JUICE_SHOP_CONTAINER=${JSON.stringify(value)}`, () => {
      expect(detectContainer(probe({ env: { JUICE_SHOP_CONTAINER: value }, cgroup: '0::/\n' }))).to.equal(false)
    })
  }
})

describe('isGitpod', () => {
  let original: string | undefined

  beforeEach(() => {
    original = process.env.GITPOD_WORKSPACE_ID
  })

  afterEach(() => {
    if (original === undefined) {
      delete process.env.GITPOD_WORKSPACE_ID
    } else {
      process.env.GITPOD_WORKSPACE_ID = original
    }
  })

  it('is false outside of Gitpod', () => {
    delete process.env.GITPOD_WORKSPACE_ID
    expect(isGitpod()).to.equal(false)
  })

  it('is true inside a Gitpod workspace', () => {
    process.env.GITPOD_WORKSPACE_ID = 'juiceshop-juiceshop-abc123'
    expect(isGitpod()).to.equal(true)
  })
})
