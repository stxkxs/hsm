/// <reference types="cypress" />

// ============================================================================
// Authentication Commands
// ============================================================================

/**
 * Login via API (fast, no UI interaction)
 */
Cypress.Commands.add('loginViaApi', (username?: string, password?: string) => {
  const user = username ?? Cypress.env('defaultUsername')
  const pass = password ?? Cypress.env('defaultPassword')
  const apiUrl = Cypress.env('apiUrl')

  cy.request({
    method: 'POST',
    url: `${apiUrl}/auth/dev-login`,
    body: { username: user, password: pass },
    failOnStatusCode: false,
  }).then((response) => {
    if (response.status === 200) {
      const { token, user: userData } = response.body
      window.localStorage.setItem('hsm_auth_token', token)
      window.localStorage.setItem('hsm_auth_user', JSON.stringify(userData))
    } else {
      throw new Error(`Login failed: ${response.status} - ${JSON.stringify(response.body)}`)
    }
  })
})

/**
 * Session-based authentication (cached across tests in same spec)
 */
Cypress.Commands.add('setupAuth', (username?: string, password?: string) => {
  const user = username ?? Cypress.env('defaultUsername')
  const pass = password ?? Cypress.env('defaultPassword')

  cy.session(
    [user, pass],
    () => {
      cy.loginViaApi(user, pass)
    },
    {
      validate() {
        cy.window().then((win) => {
          const token = win.localStorage.getItem('hsm_auth_token')
          expect(token).to.exist
        })
      },
    }
  )
})

/**
 * Logout - clear auth state
 */
Cypress.Commands.add('logout', () => {
  cy.window().then((win) => {
    win.localStorage.removeItem('hsm_auth_token')
    win.localStorage.removeItem('hsm_auth_user')
  })
})

// ============================================================================
// Key Management Commands
// ============================================================================

interface CreateKeyOptions {
  algorithm?: string
  purpose?: string
  namespace?: string
  labels?: Record<string, string>
}

/**
 * Create a key via API
 */
Cypress.Commands.add('createKeyViaApi', (options?: CreateKeyOptions) => {
  const apiUrl = Cypress.env('apiUrl')
  const {
    algorithm = 'ED25519',
    purpose = 'SIGN',
    namespace = 'default',
    labels = {},
  } = options ?? {}

  return cy.window().then((win) => {
    const token = win.localStorage.getItem('hsm_auth_token')

    return cy.request({
      method: 'POST',
      url: `${apiUrl}/keys`,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: { algorithm, purpose, namespace, labels },
    }).then((response) => {
      expect(response.status).to.eq(201)
      return response.body
    })
  })
})

/**
 * Delete a key via API
 */
Cypress.Commands.add('deleteKeyViaApi', (keyId: string) => {
  const apiUrl = Cypress.env('apiUrl')

  return cy.window().then((win) => {
    const token = win.localStorage.getItem('hsm_auth_token')

    return cy.request({
      method: 'DELETE',
      url: `${apiUrl}/keys/${keyId}`,
      headers: {
        Authorization: `Bearer ${token}`,
      },
      failOnStatusCode: false,
    })
  })
})

/**
 * Get all keys via API
 */
Cypress.Commands.add('getKeysViaApi', (namespace?: string) => {
  const apiUrl = Cypress.env('apiUrl')
  const url = namespace ? `${apiUrl}/keys?namespace=${namespace}` : `${apiUrl}/keys`

  return cy.window().then((win) => {
    const token = win.localStorage.getItem('hsm_auth_token')

    return cy.request({
      method: 'GET',
      url,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }).then((response) => {
      expect(response.status).to.eq(200)
      return response.body.keys
    })
  })
})

/**
 * Sign data via API
 */
Cypress.Commands.add('signViaApi', (keyId: string, data: string) => {
  const apiUrl = Cypress.env('apiUrl')

  return cy.window().then((win) => {
    const token = win.localStorage.getItem('hsm_auth_token')

    return cy.request({
      method: 'POST',
      url: `${apiUrl}/keys/${keyId}/sign`,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: { data },
    }).then((response) => {
      expect(response.status).to.eq(200)
      return response.body
    })
  })
})

// ============================================================================
// UI Helper Commands
// ============================================================================

/**
 * Open the Create Key dialog
 */
Cypress.Commands.add('openCreateKeyDialog', () => {
  cy.contains('button', /create key/i).click()
  cy.get('[role="dialog"]').should('be.visible')
})

/**
 * Select an algorithm in the Create Key dialog
 */
Cypress.Commands.add('selectAlgorithm', (algorithm: string) => {
  cy.get('[role="dialog"]').within(() => {
    cy.get('button[role="combobox"]').first().click()
  })
  cy.get('[role="option"]').contains(algorithm).click()
})

/**
 * Select a purpose in the Create Key dialog
 */
Cypress.Commands.add('selectPurpose', (purpose: string) => {
  cy.get('[role="dialog"]').within(() => {
    cy.get('button[role="combobox"]').eq(1).click()
  })
  cy.get('[role="option"]').contains(purpose).click()
})

/**
 * Wait for loading spinners to disappear
 */
Cypress.Commands.add('waitForLoading', () => {
  cy.get('[data-testid="loading"], [role="status"]', { timeout: 1000 })
    .should('not.exist')
    .then(() => {})
    .catch(() => {
      // No loading indicator found, that's fine
    })
  // Also wait for any skeleton loaders
  cy.get('.animate-pulse', { timeout: 1000 }).should('not.exist')
})

/**
 * Expect a toast notification
 */
Cypress.Commands.add('expectToast', (title: string, message?: string) => {
  cy.get('[role="alert"], [data-testid="toast"]', { timeout: 5000 })
    .should('be.visible')
    .and('contain.text', title)

  if (message) {
    cy.get('[role="alert"], [data-testid="toast"]').and('contain.text', message)
  }
})

/**
 * Navigate using sidebar
 */
Cypress.Commands.add('navigateVia', (menuItem: string) => {
  cy.get('nav, aside').contains('a', menuItem).click()
})

/**
 * Get data-testid element
 */
Cypress.Commands.add('getByTestId', (testId: string) => {
  return cy.get(`[data-testid="${testId}"]`)
})

// ============================================================================
// Utility Commands
// ============================================================================

/**
 * Clear all application state
 */
Cypress.Commands.add('clearAppState', () => {
  cy.clearLocalStorage()
  cy.clearCookies()
})

/**
 * Wait for API request to complete
 */
Cypress.Commands.add('waitForApi', (alias: string, timeout?: number) => {
  cy.wait(`@${alias}`, { timeout: timeout ?? 10000 })
})
