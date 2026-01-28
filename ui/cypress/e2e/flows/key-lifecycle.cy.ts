/// <reference types="cypress" />

describe('Key Lifecycle Flow', () => {
  describe('Complete Key Lifecycle: Create → Use → Delete', () => {
    let createdKeyId: string

    afterEach(() => {
      // Cleanup in case test fails before deletion
      if (createdKeyId) {
        cy.loginViaApi()
        cy.deleteKeyViaApi(createdKeyId).then(() => {
          createdKeyId = ''
        })
      }
    })

    it('creates a key, uses it to sign, then deletes it', () => {
      cy.setupAuth()

      // Intercept APIs for waiting
      cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')
      cy.intercept('POST', '**/api/hsm/keys').as('createKey')

      // === STEP 1: Create a new key ===
      cy.visit('/keys')
      cy.wait('@getKeys')

      // Open create dialog
      cy.contains('button', /create key/i).click()
      cy.get('[role="dialog"]').should('be.visible')

      // Select Ed25519 algorithm
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('Ed25519').click()

      // Create the key
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()
      })

      // Wait for dialog to close
      cy.get('[role="dialog"]').should('not.exist')

      // Get the key ID from the API response
      cy.wait('@createKey').then((interception) => {
        createdKeyId = interception.response?.body?.key_id
        expect(createdKeyId).to.not.be.empty

        // Verify key appears in list (truncated)
        cy.contains(createdKeyId.substring(0, 8)).should('be.visible')

        // === STEP 2: Use the key to sign data ===
        cy.visit('/operations/sign')
        cy.wait('@getKeys')

        // Select the newly created key
        cy.get('button[role="combobox"]').first().click()
        cy.get('[role="option"]').contains(createdKeyId.substring(0, 8)).click()

        // Enter data to sign
        cy.get('textarea#data').clear().type('Test data for lifecycle test')

        // Sign the data
        cy.contains('button', /sign data/i).click()

        // Verify signature was created
        cy.contains(/signature result/i, { timeout: 10000 }).should('be.visible')

        // === STEP 3: Delete the key ===
        cy.visit(`/keys/${createdKeyId}`)

        // Click direct delete button in header
        cy.contains('button', /delete/i).click()

        // Confirm deletion
        cy.get('[role="dialog"]').should('be.visible')
        cy.get('[role="dialog"]').within(() => {
          cy.get('input#confirmation').type('DELETE')
          cy.contains('button', /delete key/i).click()
        })

        // Verify redirect to keys list
        cy.url().should('include', '/keys')
        cy.url().should('not.include', createdKeyId)

        // Mark as deleted so afterEach doesn't try again
        createdKeyId = ''
      })
    })
  })

  describe('Key Detail View and Back Navigation', () => {
    let testKeyId: string

    beforeEach(() => {
      cy.setupAuth()

      // Intercept the key detail API call
      cy.intercept('GET', '**/api/hsm/keys/*').as('getKey')
      cy.intercept('GET', '**/api/hsm/keys').as('getKeys')

      cy.createKeyViaApi({ algorithm: 'ED25519', purpose: 'SIGN' }).then((key) => {
        testKeyId = key.key_id
      })
    })

    afterEach(() => {
      if (testKeyId) {
        cy.deleteKeyViaApi(testKeyId)
      }
    })

    it('views key details and navigates back', () => {
      cy.visit(`/keys/${testKeyId}`)
      cy.wait('@getKey')

      // View key information
      cy.contains('Ed25519').should('be.visible')
      cy.contains(testKeyId.substring(0, 8)).should('be.visible')

      // Navigate back to list
      cy.get('a[href="/keys"]').first().click()
      cy.wait('@getKeys')

      // Should be back on list
      cy.url().should('include', '/keys')
      cy.url().should('not.include', testKeyId)

      // Key should still be in list (truncated)
      cy.get('button').find('svg.lucide-refresh-cw').parent().click()
      cy.wait('@getKeys')
      cy.contains(testKeyId.substring(0, 8)).should('be.visible')
    })
  })

  describe('Session Persistence Through Lifecycle', () => {
    let testKeyId: string

    afterEach(() => {
      if (testKeyId) {
        cy.loginViaApi()
        cy.deleteKeyViaApi(testKeyId)
      }
    })

    it('maintains auth through entire key lifecycle', () => {
      cy.setupAuth()

      // Intercept APIs
      cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')
      cy.intercept('POST', '**/api/hsm/keys').as('createKey')

      // Create key
      cy.visit('/keys')
      cy.wait('@getKeys')

      cy.contains('button', /create key/i).click()
      cy.get('[role="dialog"]').within(() => {
        cy.get('button[role="combobox"]').first().click()
      })
      cy.get('[role="option"]').contains('Ed25519').click()
      cy.get('[role="dialog"]').within(() => {
        cy.contains('button', /create/i).click()
      })

      cy.get('[role="dialog"]').should('not.exist')

      // Get key ID from API
      cy.wait('@createKey').then((interception) => {
        testKeyId = interception.response?.body?.key_id

        // Navigate to operations - should not redirect to login
        cy.visit('/operations')
        cy.url().should('include', '/operations')
        cy.url().should('not.include', '/login')

        // Navigate to key detail - should not redirect to login
        cy.visit(`/keys/${testKeyId}`)
        cy.url().should('include', testKeyId)
        cy.url().should('not.include', '/login')

        // Delete key
        cy.contains('button', /delete/i).click()

        cy.get('[role="dialog"]').within(() => {
          cy.get('input#confirmation').type('DELETE')
          cy.contains('button', /delete key/i).click()
        })

        cy.url().should('include', '/keys')
        cy.url().should('not.include', '/login')

        testKeyId = '' // Deleted
      })
    })
  })
})
