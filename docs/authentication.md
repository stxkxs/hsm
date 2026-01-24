# Authentication

HSM supports multiple authentication methods including social login, passwordless authentication, and account recovery.

## Social Login

Authenticate users via OAuth2/OIDC providers.

### Supported Providers

| Provider | Features |
|----------|----------|
| Google | email, profile, openid |
| Apple | email, name (sign in with apple) |
| GitHub | email, profile, orgs |
| Microsoft | email, profile, azure ad |
| Facebook | email, public_profile |
| Twitter | email, profile (oauth 2.0 + pkce) |
| Discord | email, identify |
| LinkedIn | email, profile |

### Configuration

```toml
[auth.social.google]
enabled = true
client_id = "your-client-id.apps.googleusercontent.com"
client_secret = "your-client-secret"
redirect_uri = "https://your-app.com/auth/callback/google"

[auth.social.github]
enabled = true
client_id = "your-github-client-id"
client_secret = "your-github-secret"
redirect_uri = "https://your-app.com/auth/callback/github"
# optional: restrict to specific orgs
allowed_orgs = ["your-org"]

[auth.social.apple]
enabled = true
client_id = "com.your-app.auth"
team_id = "your-team-id"
key_id = "your-key-id"
private_key_path = "/etc/hsm/apple-auth-key.p8"
redirect_uri = "https://your-app.com/auth/callback/apple"
```

### OAuth Flow

```
┌──────────┐     ┌─────────┐     ┌──────────┐     ┌──────────┐
│  Client  │     │   HSM   │     │ Provider │     │  Client  │
└────┬─────┘     └────┬────┘     └────┬─────┘     └────┬─────┘
     │                │               │                │
     │ GET /auth/social/google        │                │
     │───────────────►│               │                │
     │                │               │                │
     │ 302 redirect   │               │                │
     │◄───────────────│               │                │
     │                │               │                │
     │ authorize request              │                │
     │───────────────────────────────►│                │
     │                │               │                │
     │ user approves  │               │                │
     │◄───────────────────────────────│                │
     │                │               │                │
     │ callback with code             │                │
     │───────────────►│               │                │
     │                │ exchange code │                │
     │                │──────────────►│                │
     │                │               │                │
     │                │ tokens + user │                │
     │                │◄──────────────│                │
     │                │               │                │
     │ session token  │               │                │
     │◄───────────────│               │                │
     │                │               │                │
```

### API Endpoints

```bash
# initiate oauth flow
GET /auth/social/{provider}
# returns: redirect to provider

# handle callback
GET /auth/social/{provider}/callback?code=...&state=...
# returns: session token

# get user info from token
GET /auth/me
Authorization: Bearer {session_token}
```

### Example: React Integration

```typescript
// redirect to provider
const loginWithGoogle = () => {
  window.location.href = `${HSM_URL}/auth/social/google`;
};

// handle callback (in callback page)
useEffect(() => {
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token');
  if (token) {
    localStorage.setItem('hsm_token', token);
    navigate('/dashboard');
  }
}, []);
```

## Passwordless Authentication

No passwords required - authenticate via email, authenticator apps, or hardware keys.

### Magic Links

One-time login links sent via email.

```toml
[auth.passwordless.magic_link]
enabled = true
expiration_minutes = 15
rate_limit_per_hour = 5

[auth.email]
smtp_host = "smtp.sendgrid.net"
smtp_port = 587
smtp_user = "apikey"
smtp_password = "your-sendgrid-key"
from_address = "auth@your-app.com"
```

```bash
# request magic link
POST /auth/magic-link/send
{
  "email": "user@example.com"
}

# verify (from email link)
GET /auth/magic-link/verify?token=...
# returns: session token
```

### TOTP (Authenticator Apps)

Time-based one-time passwords (google authenticator, authy, etc.)

```toml
[auth.passwordless.totp]
enabled = true
issuer = "YourApp"
digits = 6
period_seconds = 30
algorithm = "sha1"  # sha1, sha256, sha512
```

```bash
# start registration
POST /auth/totp/register
{
  "user_id": "user-123"
}
# returns: { secret, qr_code_uri, backup_codes }

# verify code
POST /auth/totp/verify
{
  "user_id": "user-123",
  "code": "123456"
}
# returns: session token
```

### WebAuthn / Passkeys

FIDO2 hardware keys and platform authenticators.

```toml
[auth.passwordless.webauthn]
enabled = true
rp_id = "your-app.com"
rp_name = "Your App"
rp_origin = "https://your-app.com"
attestation = "none"  # none, indirect, direct
user_verification = "preferred"  # required, preferred, discouraged
```

```bash
# start registration
POST /auth/webauthn/register/start
{
  "user_id": "user-123",
  "user_name": "alice@example.com"
}
# returns: PublicKeyCredentialCreationOptions

# complete registration
POST /auth/webauthn/register/finish
{
  "user_id": "user-123",
  "credential": { /* from navigator.credentials.create() */ }
}

# start authentication
POST /auth/webauthn/authenticate/start
{
  "user_id": "user-123"
}
# returns: PublicKeyCredentialRequestOptions

# complete authentication
POST /auth/webauthn/authenticate/finish
{
  "user_id": "user-123",
  "credential": { /* from navigator.credentials.get() */ }
}
# returns: session token
```

### Example: WebAuthn Registration (JavaScript)

```javascript
// start registration
const options = await fetch('/auth/webauthn/register/start', {
  method: 'POST',
  body: JSON.stringify({ user_id: userId, user_name: email }),
}).then(r => r.json());

// create credential
const credential = await navigator.credentials.create({
  publicKey: {
    ...options,
    challenge: base64ToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64ToBuffer(options.user.id),
    },
  },
});

// finish registration
await fetch('/auth/webauthn/register/finish', {
  method: 'POST',
  body: JSON.stringify({
    user_id: userId,
    credential: {
      id: credential.id,
      rawId: bufferToBase64(credential.rawId),
      response: {
        clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
        attestationObject: bufferToBase64(credential.response.attestationObject),
      },
      type: credential.type,
    },
  }),
});
```

## Account Recovery

Multiple recovery methods for when users lose access.

### Email Recovery

```toml
[auth.recovery.email]
enabled = true
code_length = 8
expiration_minutes = 60
rate_limit_per_day = 3
```

```bash
# request recovery
POST /auth/recovery/email/initiate
{
  "email": "user@example.com"
}

# verify code (from email)
POST /auth/recovery/email/verify
{
  "email": "user@example.com",
  "code": "ABC12345"
}

# complete recovery (set new credentials)
POST /auth/recovery/complete
{
  "recovery_token": "...",
  "new_credential": { /* totp secret, webauthn, etc */ }
}
```

### SMS Recovery

```toml
[auth.recovery.sms]
enabled = true
code_length = 6
expiration_minutes = 10
rate_limit_per_day = 3

[auth.sms]
provider = "twilio"
account_sid = "your-account-sid"
auth_token = "your-auth-token"
from_number = "+15551234567"
```

### Backup Codes

Generated at registration, single-use.

```bash
# generate backup codes (during setup)
POST /auth/backup-codes/generate
{
  "user_id": "user-123"
}
# returns: { codes: ["XXXX-XXXX-XXXX", ...] }  # 12 codes

# use backup code
POST /auth/backup-codes/verify
{
  "user_id": "user-123",
  "code": "XXXX-XXXX-XXXX"
}
# returns: session token (code is now invalidated)

# check remaining codes
GET /auth/backup-codes/remaining?user_id=user-123
# returns: { remaining: 11 }
```

### Social Recovery

Require approval from trusted guardians.

```toml
[auth.recovery.social]
enabled = true
min_guardians = 3
required_approvals = 2
request_expiration_hours = 72
```

```bash
# add guardians (during setup)
POST /auth/guardians/add
{
  "user_id": "user-123",
  "guardian": {
    "name": "Alice",
    "email": "alice@example.com"
  }
}

# initiate recovery
POST /auth/recovery/social/initiate
{
  "user_id": "user-123"
}
# notifies all guardians

# guardian approves
POST /auth/recovery/social/approve
{
  "recovery_id": "...",
  "guardian_id": "...",
  "approval_code": "..."  # from email
}

# check status
GET /auth/recovery/social/status?recovery_id=...
# returns: { approvals: 2, required: 2, status: "approved" }

# complete when enough approvals
POST /auth/recovery/complete
{
  "recovery_token": "..."
}
```

### Time-Locked Recovery

Automatic recovery after a delay (allows user to cancel if compromised).

```toml
[auth.recovery.time_locked]
enabled = true
delay_hours = 72
notification_intervals_hours = [0, 24, 48, 71]
```

```bash
# initiate time-locked recovery
POST /auth/recovery/time-locked/initiate
{
  "user_id": "user-123"
}
# returns: { recovery_id, release_at: "2024-01-18T10:00:00Z" }

# cancel (if user regains access)
POST /auth/recovery/time-locked/cancel
{
  "recovery_id": "...",
  "cancellation_code": "..."  # from notification email
}

# complete after delay
POST /auth/recovery/complete
{
  "recovery_token": "..."
}
```

## Security Best Practices

### Rate Limiting

All auth endpoints are rate-limited by default:

| Endpoint | Limit |
|----------|-------|
| Magic link send | 5/hour per email |
| TOTP verify | 5/minute per user |
| Recovery initiate | 3/day per user |
| Password attempts | 5/minute per user |

### Audit Logging

All authentication events are logged:

```bash
GET /audit/events?type=auth&user_id=user-123
```

Events include:
- Login success/failure
- Recovery initiated/completed/cancelled
- Guardian added/removed
- Credential registered/revoked

### Session Management

```toml
[auth.session]
token_lifetime_hours = 24
refresh_enabled = true
refresh_lifetime_days = 30
max_sessions_per_user = 10
```

```bash
# list active sessions
GET /auth/sessions
Authorization: Bearer {token}

# revoke session
DELETE /auth/sessions/{session_id}

# revoke all sessions
DELETE /auth/sessions
```

### Multi-Factor Authentication

Require multiple factors for sensitive operations:

```toml
[auth.mfa]
required_for = ["key_export", "key_delete", "settings_change"]
```

```bash
# operation requiring MFA
POST /keys/{id}/export
Authorization: Bearer {token}
X-MFA-Code: 123456  # TOTP code
```
