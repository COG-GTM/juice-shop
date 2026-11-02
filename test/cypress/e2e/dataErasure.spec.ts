describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('layout parameter', () => {
    it('should not allow local file read via the layout parameter', () => {
      cy.request({
        method: 'POST',
        url: '/dataerasure',
        form: true,
        headers: { Cookie: `token=${localStorage.getItem('token')}` },
        body: { layout: '../package.json' }
      }).then((response) => {
        expect(response.status).to.eq(200)
        expect(response.body).not.to.contain('"name": "juice-shop"')
      })
    })
  })
})
