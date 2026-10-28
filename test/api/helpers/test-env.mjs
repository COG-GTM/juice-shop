process.env.NODE_ENV = 'test'

const nodeConfig = JSON.parse(process.env.NODE_CONFIG ?? '{}')
nodeConfig.application = { ...nodeConfig.application, staticPrivilegedCredentials: true }
process.env.NODE_CONFIG = JSON.stringify(nodeConfig)
