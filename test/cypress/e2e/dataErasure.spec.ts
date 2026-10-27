describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should not be possible to read local files via the layout parameter', () => {
      cy.request({
        method: 'POST',
        url: '/dataerasure',
        form: true,
        body: { layout: '../package.json' }
      }).then((response) => {
        expect(response.status).to.eq(200)
        expect(response.body).not.to.contain('"name": "juice-shop"')
        expect(response.body).not.to.contain('......')
      })
      cy.request('/api/Challenges/?name=Local File Read').then((response) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(response.body.data[0].solved).to.be.false
      })
    })
  })
})
