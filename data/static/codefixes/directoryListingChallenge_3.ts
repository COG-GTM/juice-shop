/* /ftp directory browsing */
  app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))

  app.use('/.well-known', serveIndexMiddleware, serveIndex('.well-known', { icons: true, view: 'details' }))
  app.use('/.well-known', express.static('.well-known'))

  /* /encryptionkeys file download (admins only) */
  app.use('/encryptionkeys/:file', security.isAdmin(), serveKeyFiles())

  /* /logs file download (no directory listing, admins only) */
  app.use('/support/logs', security.isAdmin())
  app.use('/support/logs/:file', serveLogFiles())

  /* Swagger documentation for B2B v2 endpoints */
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

  app.use(express.static(path.resolve('frontend/dist/frontend')))
  app.use(cookieParser('kekse'))