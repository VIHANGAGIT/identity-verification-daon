# WSO2 Identity Server — Daon TrustX Identity Provider (IDP) Connector

This connector integrates [Daon TrustX](https://www.daon.com/trustx/) into WSO2 Identity Server as a
**federated OIDC connection**, using the custom `DaonAuthenticator` (login) and `DaonExecutor` (flow)
pair. It ships **two connection templates**, both of the same `DaonAuthenticator` type:

- **Daon Identity Verifier** (the *enrol* connection) — **self-contained**: holds its own
  OIDC client credentials, endpoints, scopes and the **enrol process definition**. Add it to
  registration and invited-user flows to enrol and verify users. It anchors the Daon **federated
  association** (verification state) under its own connection name.
- **Daon TrustX Authenticator** (the *login* connection) — **references** an Identity Verifier
  connection by resource id (`daon_idp_id`) and holds a **login process definition**. Add it to an
  application's login flow (re-verify an enrolled user) and to password-recovery. It resolves OIDC
  credentials/endpoints from, and shares the enrolment association of, the referenced Identity
  Verification connection — so **multiple login connections can share one enrolment**.

The flows:

- **Self-registration** — provision a new user's profile from Daon-verified claims (first-time enrolment).
- **Invited-user registration** — validate a pre-populated profile against Daon-verified values (lock on mismatch).
- **Login verification** — as a login step, re-verify an already-enrolled user. A user not yet enrolled
  with Daon fails with an error (enrolment happens via a registration flow, not at login).
- **Password-recovery verification** — face re-verification of an already-enrolled user.

A connection is *self-contained* (no `daon_idp_id`) or *referencing* (`daon_idp_id` set) — the runtime
branches on that to read OIDC config and the association key either from the connection's own props or
from the referenced Identity Verifier connection. The relevant **process definition** (enrol PD for
registration/invited-user, login PD for login/recovery) is sent as `acr_values`
(`<ProcessDefinitionName:Version>`); enrolment additionally requests `verified_claims`, while login and
password recovery re-verify with a `login_hint` (the Daon `preferred_username`). The verification state
is stored as a **federated identity association** (local user ↔ Daon subject) in IS's built-in
association store — no custom user claims and no separate Identity Verification Provider (IDVP) resource.

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

# UI metadata — both Daon TrustX connection templates
cp -r ui-metadata/daon-idv ui-metadata/daon-authenticator \
$IS_HOME/repository/resources/identity/extensions/connections/

# Daon logo
cp ui-metadata/assets/images/logos/daon.svg \
$IS_HOME/repository/deployment/server/webapps/console/resources/connections/assets/images/logos/
```

> The exact `connections` metadata path can vary by IS version — place `daon-idv` (Identity
> Verification / enrol) and `daon-authenticator` (login) where your IS build reads connection templates.

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
6. Note the **enrol process definition** (registration/invited-user) and the **login process
   definition** (login/recovery re-verification) to use.

---

## Configuring the Connection in WSO2 IS

### Step 1 — Create the Daon Identity Verifier (enrol) connection

1. Console → **Connections** → **New Connection** → **Daon Identity Verifier**.
2. Fill in the create form:

| Field | Value |
|---|---|
| **Name** | e.g. `Daon Identity Verifier` |
| **Client ID** / **Client Secret** | From the Daon OIDC client |
| **Authorization Endpoint URL** / **Token Endpoint URL** | Daon OIDC endpoints |
| **Scopes** | `openid profile document` |
| **Enrol Process Definition** | PD for registration/invited-user enrolment, `<Name:Version>` |

3. On the **Settings** tab, copy the **Authorized redirect URI** and register it on the Daon OIDC client.
4. Copy the connection's **resource ID** (shown in the connection details / console URL) — the login
   connection references it.

### Step 2 — Create the Daon TrustX Authenticator (login) connection

1. Console → **Connections** → **New Connection** → **Daon TrustX Authenticator**.
2. Fill in the create form:

| Field | Value |
|---|---|
| **Name** | e.g. `Daon TrustX Login` |
| **Daon Verifier ID** | Resource ID of the Identity Verifier connection from Step 1 |
| **Login Process Definition** | PD for login/recovery re-verification, `<Name:Version>` |

You can create several login connections (e.g. per application, with different login PDs) all
referencing the same Identity Verifier connection; they share one enrolment.

### Step 3 — Map attributes

On the **Identity Verifier** connection's **Attributes** tab, map Daon claim names to WSO2 local
claims (these drive provisioning and verification):

| WSO2 Local Claim | Daon Claim Name |
|---|---|
| `http://wso2.org/claims/givenname` | `given_name` |
| `http://wso2.org/claims/lastname` | `family_name` |
| `http://wso2.org/claims/dob` | `birthdate` |

Add mappings for any additional claims your Daon tenant returns. When Daon returns a combined
`family_name_and_given_name` field instead of split names, the executor splits it on `^`
(`<given>^<family>`).

### Step 4 — Add Daon to your flows

Add the **Identity Verifier** connection to enrolment flows and a **Authenticator** (login)
connection to login/recovery:

- **Self-registration**: add the **Daon Identity Verifier** connection's executor node to the
  registration flow. It requests `verified_claims`, provisions the profile from the verified claims, and
  records a federated association (⇒ verified). Sends the **enrol PD** as `acr_values`.
- **Invited-user registration**: add the **Daon Identity Verifier** connection's executor node
  to the invited-user flow **before the set-password step**. When the invited user clicks the magic link
  / enters the OTP, they are redirected to Daon to verify the claims the admin defined. Every mapped
  claim the admin set on the user is compared against the Daon-verified values (read from the flow user,
  falling back to the user store by user id). **Only a successful match advances to set-password.** A
  mismatch re-prompts the Daon step; after `MAX_VERIFICATION_ATTEMPTS` (default 3, session-scoped)
  failures the account is locked. On success a federated association is recorded (⇒ verified). Sends the
  **enrol PD**.
- **Login**: add a **Daon TrustX Authenticator** (login) connection to an application's Login Flow as a
  step **after** the user is identified (e.g. after username/password). The user must already be enrolled
  with Daon (have an association with the referenced Identity Verifier connection); the step
  re-verifies them with a `login_hint` (the Daon `preferred_username` from the association) and the
  **login PD**. A user with no Daon association is not enrolled and the login step **fails with an
  error** — enrolment happens via a registration flow.
- **Password recovery**: add a **Daon TrustX Authenticator** (login) connection; its executor node
  re-verifies with a `login_hint` and the **login PD**. A user with no Daon association fails with an
  error.

---

## Runtime Behaviour

```
   enrol PD (IdV connection) for enrolment; login PD (login connection) for login/recovery — as acr_values
  ┌──────────────────────────┬──────────────┬─────────────────────────────────────────────┐
  │ Flow                     │ PD sent      │ Behaviour                                    │
  ├──────────────────────────┼──────────────┼─────────────────────────────────────────────┤
  │ Self-registration        │ enrol PD     │ verified_claims → provision profile, assoc   │
  │ Invited-user registration│ enrol PD     │ verified_claims → validate profile, assoc    │
  │ Login (enrolled)         │ login PD     │ login_hint (re-verify)                       │
  │ Login (not enrolled)     │ —            │ error — enrol via a registration flow first  │
  │ Password recovery        │ login PD     │ login_hint (re-verify); error if not enrolled│
  └──────────────────────────┴──────────────┴─────────────────────────────────────────────┘
```

Profile attributes come from the ID token's `verifiedClaims.claims`; the verified state itself is a
federated association (local user ↔ Daon subject), not a user claim.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Redirect to Daon fails / missing endpoint | Authorization/token endpoint blank on the connection | Set the OIDC endpoint URLs on the **Settings** tab |
| `401` on token exchange | Wrong `Client ID` / `Client Secret` | Verify credentials match the Daon OIDC client |
| No `acr_values` sent | Process definition not configured | Set the enrol PD on the Identity Verifier connection (enrolment) or the login PD on the login connection (login/recovery) |
| Enrolment runs plain OIDC (no Daon verification) | An old stock-OIDC IdP connection was added to the enrolment flow | Use a **Daon Identity Verifier** connection — only a `DaonAuthenticator`-type connection binds `DaonExecutor` |
| Login "not enrolled" for a user enrolled elsewhere | Login connection's **Daon Verifier ID** points at a different Identity Verifier connection than the one used to enrol | Point all connections at the same Identity Verifier connection (they share its association) |
| Login/recovery fails with "not enrolled with Daon" | User has no Daon association (never enrolled via registration, or `FederatedAssociationManager` unavailable) | Enrol the user through a Daon registration flow first; confirm Daon runs after user identification |
| Verified attributes not provisioned | Attribute mapping missing on the connection | Add the mapping on the **Attributes** tab |
| Names swapped | Daon emits `<family>^<given>` order | Adjust the split order in `DaonExecutor#populateNameClaims` |
| Redirect URI mismatch in Daon | Registered `redirect_uri` differs | Use the exact Authorized redirect URI from the **Settings** tab |
