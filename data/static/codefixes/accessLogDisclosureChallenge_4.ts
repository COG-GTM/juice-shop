/* /ftp directory browsing and file download */
  app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))
  app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
  app.use('/ftp/quarantine/:file', serveQuarantineFiles())

  app.use('/.well-known', serveIndexMiddleware, serveIndex('.well-known', { icons: true, view: 'details' }))
  app.use('/.well-known', express.static('.well-known'))

  /* /encryptionkeys public key file download */
  app.use('/encryptionkeys', denyDirectoryListing())
  app.use('/encryptionkeys/:file', serveKeyFiles())

  /* /logs directory browsing */
  app.use('/support/logs/:file', serveLogFiles())

  /* Swagger documentation for B2B v2 endpoints */
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

  app.use(express.static(path.resolve('frontend/dist/frontend')))
  app.use(cookieParser('kekse'))