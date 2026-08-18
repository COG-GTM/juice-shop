/* /ftp file download limited to explicitly published file types */
  app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
  app.use('/ftp/quarantine/:file', serveQuarantineFiles())

  app.use('/.well-known', express.static('.well-known'))

  /* /encryptionkeys file download restricted to administrators */
  app.use('/encryptionkeys/:file', security.isAuthorized(), security.isAdmin(), serveKeyFiles())

  /* /logs file download restricted to administrators */
  app.use('/support/logs', security.isAuthorized(), security.isAdmin())
  app.use('/support/logs/:file', serveLogFiles())

  /* Swagger documentation for B2B v2 endpoints */
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

  app.use(express.static(path.resolve('frontend/dist/frontend')))
  app.use(cookieParser('kekse'))