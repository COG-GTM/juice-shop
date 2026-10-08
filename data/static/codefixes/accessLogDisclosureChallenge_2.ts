/* /ftp file download (no directory listing, confidential files for admins only) */
  app.use('/ftp(?!/quarantine)/:file', servePublicFiles())
  app.use('/ftp/quarantine/:file', security.isAdmin(), serveQuarantineFiles())

  app.use('/.well-known', serveIndexMiddleware, serveIndex('.well-known', { icons: true, view: 'details' }))
  app.use('/.well-known', express.static('.well-known'))

  /* /encryptionkeys file download (admins only) */
  app.use('/encryptionkeys/:file', security.isAdmin(), serveKeyFiles())

  /* /logs directory browsing */
  app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true }))
  app.use('/support/logs/:file', serveLogFiles())

  /* Swagger documentation for B2B v2 endpoints */
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

  app.use(express.static(path.resolve('frontend/dist/frontend')))
  app.use(cookieParser('kekse'))