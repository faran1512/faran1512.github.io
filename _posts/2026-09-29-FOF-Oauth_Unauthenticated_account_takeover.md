---
title: CVE-2026-92161 - Trusting an Email You Never Verified | Account Takeover in FriendsOfFlarum OAuth (0-day)
date: 2026-09-29 14:38:00 +0500
categories: [Vulnerability Research]
tags: [exploit-development, vulnerability-research, account_takeover, broken_authentication, RCE, OAuth]     # TAG names should always be lowercase
author: faran1512
description: fof/oauth trusted Discord's unverified email and auto-linked it to any matching account, letting an attacker log in as any user.
---

**GHSA-g7vj-c29h-3h5m - CVSS 9.8 - affected `fof/oauth` ≤ 1.7.3, and 2.0.0-beta.1 – 2.0.0-beta.3**

# 1. What the vulnerability is

Flarum is a popular open-source forum. The FriendsOfFlarum **OAuth** extension lets a forum
offer "Sign in with…" buttons — Discord, GitHub, Google, and others. The idea is simple: the
user proves their identity to the third-party provider, the provider hands the forum back the
user's profile (including an email address), and the forum logs them in.

The critical detail is what the forum does with that email. Flarum core has a concept of a
**trusted email**: if an OAuth provider says "this user owns `alice@example.com`," the extension
can call `provideTrustedEmail()`, and Flarum will **automatically link the login to whatever
existing account already uses that email** — and log the visitor straight in as that account.

That is the correct behavior *only if the provider actually verified the address.* `fof/oauth`
did not check whether it had.

The extension treated the email returned by **Discord** as trusted without checking Discord's
`verified` flag. And Discord will hand out an **unverified** email in one specific situation: an
account that completed **phone-number verification** is allowed to skip email verification. So an
attacker could:

1. Create a Discord account, set its email to a **victim's** forum email, and verify the account
   with a **phone number** instead of the email.
2. Click "Sign in with Discord" on any Flarum forum that has Discord login enabled.
3. Get logged straight in **as the victim** — no password, no access to the victim's inbox.

Because the auto-link happens on email match, **any** account is a target, **including
administrators**. The only prerequisites are that the forum has Discord sign-in enabled and that
the attacker knows the victim's email address (or the email is unclaimed on the forum, allowing
pre-registration hijack).

---

# 2. Root cause analysis

## The misleadingly-named check

At the center of the bug is a method whose name suggests it verifies an email, but which only
checks that the string is non-empty:

```php
// src/Provider.php:76-81  (fof/oauth 1.7.3)
protected function verifyEmail(?string $email)
{
    if ($email === null || empty($email)) {
        throw new AuthenticationException('invalid_email');
    }
}
```

`verifyEmail()` does **not** consult any `verified` / `email_verified` flag from the provider. It
rejects an empty string and accepts everything else.

## The trust hand-off

The Discord provider fetches the resource owner, runs the email through that non-check, and then
declares the address **trusted** to Flarum core:

```php
// src/Providers/Discord.php:53-68  (fof/oauth 1.7.3)
public function suggestions(Registration $registration, $user, string $token)
{
    $this->verifyEmail($email = $user->getEmail());   // only checks non-empty — the flaw

    $hash = $user->getAvatarHash();
    $file = $hash ?
        "https://cdn.discordapp.com/avatars/{$user->getId()}/{$user->getAvatarHash()}.png"
        : 'https://cdn.discordapp.com/embed/avatars/0.png';

    $registration
        ->provideTrustedEmail($email)                 // <-- tells core "the provider verified this"
        ->suggestUsername($user->getUsername() ?: '')
        ->setPayload($user->toArray());

    $this->provideAvatar($registration, $file);
}
```

The Discord OAuth scopes requested are just `identify` and `email` (`options()` in the same file).
Discord's `/users/@me` response contains a `verified` field that says whether the email is
verified — but the provider only ever reads `$user->getEmail()` and **never consults `verified`**
before calling `provideTrustedEmail()`.

## The sink: core auto-links by email

Once an email is "trusted," Flarum core links it to any existing account with that address and
issues a logged-in session — the standard trusted-email flow:

```
Discord callback
  → provider suggestions()
    → verifyEmail()           (non-empty only)
    → provideTrustedEmail($email)
      → core ResponseFactory::make()
        → User::where('email', $email)->first()   // find the victim
        → makeLoggedInResponse()                  // log in AS the victim
```

The one and only control that would have stopped it, a check on the provider's `verified` flag, was missing.

## Why it was default-exploitable, and why GitHub was safe

- **Default-deny wasn't the safeguard here.** Discord sign-in is a common option,
  any forum that enabled it was exposed on a stock configuration.
- **The GitHub provider was *not* vulnerable** because its email lookup explicitly filters on `primary && verified` before trusting an
  address. That safe pattern simply wasn't applied to Discord (or generalized), which is what
  isolates the defect to the missing verified-check.

## The broader lesson

The root cause is a **trust-boundary** mistake, not a coding typo. `provideTrustedEmail()` carries
an implicit contract — "the provider verified the user owns this address" — and the Discord path
satisfied the method call without satisfying the contract. The fix is to
**never call `provideTrustedEmail()` unless the provider asserts the
email is verified.**

---

# 3. Proof of concept — steps

**Preconditions**
- A Flarum forum running `fof/oauth` ≤ 1.7.3 (or 2.0.0-beta.1–beta.3) with **Discord sign-in enabled**.
- A victim account on that forum using a known email, e.g. `victim@example.com`.

**Attacker steps**
1. **Register a Discord account** you control (a throwaway account is fine).
2. In Discord account settings, **set the account email to the victim's email** (`victim@example.com`).
   Discord will show it as unverified.
3. **Verify the Discord account with a phone number** instead of the email. This satisfies
   Discord's verification requirement while leaving the email `verified: false`.
   *(Sanity check: `GET https://discord.com/api/users/@me` with the account's token returns the
   victim's email with `"verified": false`.)*
4. On the target forum, click **"Sign in with Discord"** and complete Discord's consent screen
   for your attacker account.
5. Discord redirects back to the forum's OAuth callback. The extension reads your (unverified)
   email, passes its non-empty check, and calls `provideTrustedEmail("victim@example.com")`.
6. Flarum core matches that email to the victim's account and issues a **logged-in session**.
   **You are now authenticated as the victim** — including admin, if the victim is an admin.

---

# 4. Remediation

- **Update immediately** to `fof/oauth` **1.7.4** or **2.0.0-beta.4**.
- The fix makes the extension require the provider's verified flag before an email is trusted,
  closing the Discord path and the wider nOAuth class (so provider add-ons don't inherit the trap).
- **If you build an OAuth integration yourself:** only call an auto-linking "trusted email" API
  when the provider explicitly asserts the email is verified (`email_verified` / `verified: true`),
  and prefer linking on the provider's immutable subject identifier over the email where possible.

---

# 5. Timeline

- **Reported** privately to FriendsOfFlarum via coordinated disclosure.
- **Reproduced** end-to-end and **patched** by the maintainers in 1.7.4 / 2.0.0-beta.4.
- **Published** as GHSA-g7vj-c29h-3h5m (2026-08-10), later assigned **CVE-2026-92161**.

*Credit to the FriendsOfFlarum maintainers ([@imorland](https://github.com/imorland) and team)
for a fast, clean fix and a well-run disclosure process.*
