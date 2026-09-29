describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('layout parameter', () => {
    it('should not allow local file read via the layout parameter', () => {
      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/dataerasure`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/x-www-form-urlencoded',
            Origin: `${Cypress.config('baseUrl')}/`,
            Cookie: `token=${localStorage.getItem('token')}`
          },
          body: 'layout=../package.json'
        })
        const text = await response.text()
        expect(response.status).to.equal(200)
        expect(text).to.contain('Sorry to see you leave!')
        expect(text).not.to.contain('"name": "juice-shop"')
        expect(text).not.to.contain('......')
      })
    })
  })
})
