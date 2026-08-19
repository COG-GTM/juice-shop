describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('layout parameter', () => {
    it('should not be possible to read local files through the layout parameter', () => {
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
        const body = await response.text()
        expect(response.status).to.equal(200)
        expect(body).to.not.contain('"devDependencies"')
        expect(body).to.contain('Your erasure request will be processed shortly')
      })
    })
  })
})
