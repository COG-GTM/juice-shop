describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should not be possible to read local files via the layout parameter', () => {
      cy.window().then((win) => {
        cy.request({
          method: 'POST',
          url: '/dataerasure',
          form: true,
          body: { layout: '../package.json' },
          headers: { Cookie: `token=${win.localStorage.getItem('token')}` }
        }).then((response) => {
          expect(response.status).to.eq(200)
          expect(response.body).not.to.contain('"name": "juice-shop"')
          expect(response.body).not.to.contain('......')
        })
      })
    })
  })
})
