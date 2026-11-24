// based on https://github.com/sindresorhus/is-docker and https://github.com/sindresorhus/is-inside-container (MIT Licensed)
// inlined to avoid import problems in cypress

import fs from 'node:fs'

export interface ContainerProbe {
  env: NodeJS.ProcessEnv
  exists: (path: string) => boolean
  readFile: (path: string) => string | undefined
}

const defaultProbe: ContainerProbe = {
  env: process.env,
  exists: (path) => {
    try {
      fs.statSync(path)
      return true
    } catch {
      return false
    }
  },
  readFile: (path) => {
    try {
      return fs.readFileSync(path, 'utf8')
    } catch {
      return undefined
    }
  }
}

const truthyEnvValues = ['true', '1', 'yes']
const containerCGroupPattern = /docker|containerd|kubepods|libpod|crio|lxc/

export function detectContainer ({ env, exists, readFile }: ContainerProbe = defaultProbe) {
  return truthyEnvValues.includes(env.JUICE_SHOP_CONTAINER?.toLowerCase() ?? '') ||
    exists('/.dockerenv') ||
    exists('/run/.containerenv') ||
    containerCGroupPattern.test(readFile('/proc/self/cgroup') ?? '') ||
    Boolean(env.KUBERNETES_SERVICE_HOST) ||
    Boolean(env.container)
}

let isDockerCached: boolean | undefined

export default function isDocker () {
  isDockerCached ??= detectContainer()
  return isDockerCached
}
