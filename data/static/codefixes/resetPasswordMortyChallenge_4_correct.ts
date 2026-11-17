/* Rate limiting */
  const trustedProxies = config.get<string>('server.trustedProxies')
  if (trustedProxies) app.set('trust proxy', trustedProxies)
  app.use('/rest/user/reset-password', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100
  }))