process.env.NODE_ENV = 'test'

const nodeConfig = JSON.parse(process.env.NODE_CONFIG ?? '{}')
nodeConfig.application = { ...nodeConfig.application, staticSeedCredentials: true }
process.env.NODE_CONFIG = JSON.stringify(nodeConfig)
