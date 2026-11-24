describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should not be possible to perform local file read attack using the browser', () => {
      cy.window().then(async () => {
        for (const params of ['layout=../package.json', 'settings[view options][layout]=package.json&settings[views]=.']) {
          const response = await fetch(`${Cypress.config('baseUrl')}/dataerasure`, {
            method: 'POST',
            cache: 'no-cache',
            headers: {
              'Content-type': 'application/x-www-form-urlencoded',
              Origin: `${Cypress.config('baseUrl')}/`,
              Cookie: `token=${localStorage.getItem('token')}`
            },
            body: params
          })
          const text = await response.text()
          expect(response.status).to.not.equal(200)
          expect(text).to.not.contain('"name": "juice-shop"')
        }
      })
    })
  })
})
