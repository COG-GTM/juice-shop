describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should not be possible to read local files through the layout parameter', () => {
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
        const body = await response.text()
        expect(response.status).to.equal(200)
        expect(body).to.contain('Sorry to see you leave!')
        expect(body).not.to.contain('"name": "juice-shop"')
      })
    })
  })
})
