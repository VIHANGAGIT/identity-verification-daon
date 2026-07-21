# WSO2 Identity Server — Daon TrustX Identity Provider (IDP) Connector

This connector integrates [Daon TrustX](https://www.daon.com/trustx/) into WSO2 Identity Server as a
standard **federated OIDC Identity Provider (IDP)**. A single Daon connection drives:

- **Self-registration** — provision a new user's profile from Daon-verified claims (first-time enrolment).
- **Invited-user registration** — validate a pre-populated profile against Daon-verified values (lock on mismatch).
- **Login verification** — as a login step, re-verify an already-enrolled user. A user not yet enrolled
  with Daon fails with an error (enrolment happens via a registration flow, not at login).
- **Password-recovery verification** — face re-verification of an already-enrolled user.

A single Daon **process definition (PD)** is configured on the connection and sent as `acr_values`
(`<ProcessDefinitionName:Version>`) across every flow. What differs per flow is the rest of the
request: first-time enrolment (self / invited registration) requests `verified_claims`, while login and
password recovery re-verify an already-enrolled user with a `login_hint` (the Daon `preferred_username`).
The verification state is stored as
a **federated identity association** (local user ↔ Daon subject) in IS's built-in association store — no
custom user claims and no separate Identity Verification Provider (IDVP) resource.

---

## Prerequisites

- WSO2 Identity Server 7.x
- Maven 3.6+
- JDK 21
- A Daon TrustX tenant with admin access

---

## Building

```bash
mvn clean install
```

Artifacts produced (two OSGi bundles — **no WAR**):

| Artifact | Location |
|---|---|
| Connector bundle | `components/org.wso2.carbon.identity.verification.daon.connector/target/org.wso2.carbon.identity.verification.daon.connector-*.jar` |
| Authenticator + executor bundle | `components/org.wso2.carbon.identity.verification.daon.authenticator/target/org.wso2.carbon.identity.verification.daon.authenticator-*.jar` |

The authenticator bundle depends on the connector bundle at runtime — deploy both.

---

## Deployment

### 1. Copy artifacts to WSO2 IS

```bash
IS_HOME=/path/to/wso2is

# OSGi bundles
cp components/org.wso2.carbon.identity.verification.daon.connector/target/\
org.wso2.carbon.identity.verification.daon.connector-*.jar \
$IS_HOME/repository/components/dropins/

cp components/org.wso2.carbon.identity.verification.daon.authenticator/target/\
org.wso2.carbon.identity.verification.daon.authenticator-*.jar \
$IS_HOME/repository/components/dropins/

# UI metadata — Daon TrustX connection (IDP) template
cp -r ui-metadata/daon-authenticator \
$IS_HOME/repository/resources/identity/extensions/connections/

# Daon logo
cp ui-metadata/assets/images/logos/daon.svg \
$IS_HOME/repository/deployment/server/webapps/console/resources/connections/assets/images/logos/
```

> The exact `connections` metadata path can vary by IS version — place `daon-authenticator` where your
> IS build reads connection templates.

### 2. No custom claims to register

Verification state is stored as a **federated identity association** (via the built-in
`FederatedAssociationManager`, in the `IDP_USER_ID` store) — the presence of an association with the
Daon IDP means "verified", and the association's federated user id holds the Daon `preferred_username`
used for `login_hint`. Nothing to register.

### 3. Restart WSO2 IS

```bash
$IS_HOME/bin/wso2server.sh restart
```

---

## Registering an OIDC Client in Daon TrustX

1. Log in to your Daon TrustX administration console.
2. Create a **Confidential** OIDC client.
3. Add the IS `/commonauth` endpoint (login) and your registration portal callback as allowed redirect
   URIs. The exact authorized redirect URI is shown on the connection's **Settings** tab after creation.
4. Enable the required scopes: `openid`, `profile`, `document`.
5. Note the **Client ID**, **Client Secret**, and the **authorization** and **token** endpoint URLs.
6. Note the **process definition** to use for identity verification.

---

## Configuring the Connection in WSO2 IS

### Step 1 — Create the Daon TrustX connection

1. Console → **Connections** → **New Connection** → **Daon TrustX**.
2. Fill in the create form:

| Field | Value |
|---|---|
| **Name** | e.g. `Daon TrustX` |
| **Client ID** / **Client Secret** | From the Daon OIDC client |
| **Authorization Endpoint URL** / **Token Endpoint URL** | Daon OIDC endpoints |
| **Scopes** | `openid profile document` |
| **Process Definition** | PD used across login, registration and recovery flows, `<Name:Version>` |

3. On the **Settings** tab, copy the **Authorized redirect URI** and register it on the Daon OIDC client.

### Step 2 — Map attributes

On the connection's **Attributes** tab, map Daon claim names to WSO2 local claims (these drive
provisioning and verification):

| WSO2 Local Claim | Daon Claim Name |
|---|---|
| `http://wso2.org/claims/givenname` | `given_name` |
| `http://wso2.org/claims/lastname` | `family_name` |
| `http://wso2.org/claims/dob` | `birthdate` |

Add mappings for any additional claims your Daon tenant returns. When Daon returns a combined
`family_name_and_given_name` field instead of split names, the executor splits it on `^`
(`<given>^<family>`).

### Step 3 — Add Daon to your flows

- **Self-registration**: add the Daon executor node to the registration flow. It requests
  `verified_claims`, provisions the profile from the verified claims, and records a federated
  association (⇒ verified).
- **Invited-user registration**: add the Daon executor node to the invited-user flow **before the
  set-password step**. When the invited user clicks the magic link / enters the OTP, they are redirected
  to Daon to verify the claims the admin defined. Every mapped claim the admin set on the
  user is compared against the Daon-verified values (read from the flow user, falling back to the user
  store by user id). **Only a successful match advances to set-password.** A mismatch re-prompts the Daon
  step; after `MAX_VERIFICATION_ATTEMPTS` (default 3, session-scoped) failures the account is locked. On
  success a federated association is recorded (⇒ verified).
- **Login**: add **Daon TrustX** to an application's Login Flow as a step **after** the user is
  identified (e.g. after username/password). The user must already be enrolled with Daon (have a Daon
  association); the step always re-verifies them with a `login_hint` (the Daon `preferred_username` from
  the association). A user with no Daon association is not enrolled and the login step **fails with an
  error** — enrolment happens via a registration flow.
- **Password recovery**: the Daon executor node re-verifies with a `login_hint`. A user with no Daon
  association fails with an error.

All flows send the same configured **Process Definition** as `acr_values`.

---

## Runtime Behaviour

```
      the same process definition is sent as acr_values in every flow
  ┌──────────────────────────┬───────────────────────────────────────────┐
  │ Flow                     │ Behaviour                                  │
  ├──────────────────────────┼───────────────────────────────────────────┤
  │ Self-registration        │ verified_claims → provision profile, assoc │
  │ Invited-user registration│ verified_claims → validate profile, assoc  │
  │ Login (enrolled)         │ login_hint (re-verify)                     │
  │ Login (not enrolled)     │ error — enrol via a registration flow first│
  │ Password recovery        │ login_hint (re-verify); error if not enrol │
  └──────────────────────────┴───────────────────────────────────────────┘
```

Profile attributes come from the ID token's `verifiedClaims.claims`; the verified state itself is a
federated association (local user ↔ Daon subject), not a user claim.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Redirect to Daon fails / missing endpoint | Authorization/token endpoint blank on the connection | Set the OIDC endpoint URLs on the **Settings** tab |
| `401` on token exchange | Wrong `Client ID` / `Client Secret` | Verify credentials match the Daon OIDC client |
| No `acr_values` sent | Process Definition not configured | Set the process definition on the connection |
| Login/recovery fails with "not enrolled with Daon" | User has no Daon association (never enrolled via registration, or `FederatedAssociationManager` unavailable) | Enrol the user through a Daon registration flow first; confirm Daon runs after user identification |
| Verified attributes not provisioned | Attribute mapping missing on the connection | Add the mapping on the **Attributes** tab |
| Names swapped | Daon emits `<family>^<given>` order | Adjust the split order in `DaonExecutor#populateNameClaims` |
| Redirect URI mismatch in Daon | Registered `redirect_uri` differs | Use the exact Authorized redirect URI from the **Settings** tab |
