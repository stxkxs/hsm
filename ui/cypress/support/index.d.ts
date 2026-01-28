/// <reference types="cypress" />

interface CreateKeyOptions {
  algorithm?: string
  purpose?: string
  namespace?: string
  labels?: Record<string, string>
}

interface CreateKeyResponse {
  key_id: string
  algorithm: string
  purpose: string
  public_key?: string
  created_at: string
}

interface Key {
  key_id: string
  algorithm: string
  purpose: string
  namespace: string
  public_key?: string
  created_at: string
  last_used?: string
  labels: Record<string, string>
  active: boolean
}

interface SignResponse {
  signature: string
  key_id: string
  algorithm: string
}

declare namespace Cypress {
  interface Chainable {
    // ========================================================================
    // Authentication Commands
    // ========================================================================

    /**
     * Login via API (fast, no UI interaction)
     * @param username - Username (defaults to env.defaultUsername)
     * @param password - Password (defaults to env.defaultPassword)
     * @example cy.loginViaApi()
     * @example cy.loginViaApi('operator', 'dev')
     */
    loginViaApi(username?: string, password?: string): Chainable<void>

    /**
     * Session-based authentication (cached across tests in same spec)
     * @param username - Username (defaults to env.defaultUsername)
     * @param password - Password (defaults to env.defaultPassword)
     * @example cy.setupAuth()
     * @example cy.setupAuth('admin', 'dev')
     */
    setupAuth(username?: string, password?: string): Chainable<void>

    /**
     * Logout - clear auth state
     * @example cy.logout()
     */
    logout(): Chainable<void>

    // ========================================================================
    // Key Management Commands
    // ========================================================================

    /**
     * Create a key via API
     * @param options - Key creation options
     * @example cy.createKeyViaApi()
     * @example cy.createKeyViaApi({ algorithm: 'ECDSA_P256', purpose: 'SIGN' })
     */
    createKeyViaApi(options?: CreateKeyOptions): Chainable<CreateKeyResponse>

    /**
     * Delete a key via API
     * @param keyId - The key ID to delete
     * @example cy.deleteKeyViaApi('key-123')
     */
    deleteKeyViaApi(keyId: string): Chainable<Cypress.Response<unknown>>

    /**
     * Get all keys via API
     * @param namespace - Optional namespace filter
     * @example cy.getKeysViaApi()
     * @example cy.getKeysViaApi('production')
     */
    getKeysViaApi(namespace?: string): Chainable<Key[]>

    /**
     * Sign data via API
     * @param keyId - The key ID to sign with
     * @param data - The data to sign (base64 encoded)
     * @example cy.signViaApi('key-123', 'aGVsbG8=')
     */
    signViaApi(keyId: string, data: string): Chainable<SignResponse>

    // ========================================================================
    // UI Helper Commands
    // ========================================================================

    /**
     * Open the Create Key dialog
     * @example cy.openCreateKeyDialog()
     */
    openCreateKeyDialog(): Chainable<void>

    /**
     * Select an algorithm in the Create Key dialog
     * @param algorithm - Algorithm name (e.g., 'ED25519', 'ECDSA_P256')
     * @example cy.selectAlgorithm('ED25519')
     */
    selectAlgorithm(algorithm: string): Chainable<void>

    /**
     * Select a purpose in the Create Key dialog
     * @param purpose - Purpose (e.g., 'SIGN', 'ENCRYPT')
     * @example cy.selectPurpose('SIGN')
     */
    selectPurpose(purpose: string): Chainable<void>

    /**
     * Wait for loading spinners to disappear
     * @example cy.waitForLoading()
     */
    waitForLoading(): Chainable<void>

    /**
     * Expect a toast notification
     * @param title - Expected toast title
     * @param message - Optional expected message content
     * @example cy.expectToast('Success')
     * @example cy.expectToast('Key Created', 'Your key has been created')
     */
    expectToast(title: string, message?: string): Chainable<void>

    /**
     * Navigate using sidebar menu
     * @param menuItem - Menu item text to click
     * @example cy.navigateVia('Keys')
     */
    navigateVia(menuItem: string): Chainable<void>

    /**
     * Get element by data-testid attribute
     * @param testId - The data-testid value
     * @example cy.getByTestId('login-form')
     */
    getByTestId(testId: string): Chainable<JQuery<HTMLElement>>

    // ========================================================================
    // Utility Commands
    // ========================================================================

    /**
     * Clear all application state (localStorage, cookies)
     * @example cy.clearAppState()
     */
    clearAppState(): Chainable<void>

    /**
     * Wait for an API request to complete
     * @param alias - The intercept alias (without @)
     * @param timeout - Optional timeout in ms
     * @example cy.waitForApi('apiGet')
     */
    waitForApi(alias: string, timeout?: number): Chainable<void>
  }
}
