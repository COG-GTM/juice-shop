describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should not be possible to perform local file read attack using the browser', () => {
      cy.window().then(async () => {
        const params = 'layout=../package.json'

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
        expect(response.status).to.equal(500)
        expect(await response.text()).to.contain('File access not allowed')
      })
    })
  })
})
