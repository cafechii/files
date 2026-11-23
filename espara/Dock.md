## Blind Stored XSS

### 

### Challenge Summary

A simple "sign up" web form asked for `id`, `name`, `email`, and `age`, then sent this data as JSON to a `/submit` endpoint using a POST request.

### Reading the Source Code

We looked at the page's JavaScript and noticed something odd:

javascript

```javascript
const data = {
    id: formData.get('id'),
    name: formData.get('name'),
    email: formData.get('email'),
    age: parseInt(formData.get('age'))
};
```

We also noticed the response was displayed using `innerHTML`:

```javascript
resultDiv.innerHTML = `... ${result.userInfo} ...`;
```

Using `innerHTML` instead of `textContent` means that if the server ever reflects back something we typed, any HTML/JavaScript inside it will actually run in the browser. This is a classic setup for **XSS (Cross-Site Scripting)**.



### First XSS Attempt Failed

We put a payload like `<script>alert(1)</script>` in the `name` field — but the server returned `name=''` (empty). This meant the payload was either filtered/stripped by the server, or something about the format wasn't accepted. It's worth noting as a mistake because it initially looked like the field was "safe," but it just needed a different payload format.

### Step 3: Trying a Different Payload

Instead of `<script>`, we tried an image-based payload:

html

```html
<img src=x onerror=alert(1)>
```

This one worked — the `onerror` event fired and the `alert(1)` popped up. This confirmed the XSS vulnerability was real; the server wasn't filtering all tags, just some (likely `<script>` specifically, or something about that exact format).

### Trying to Make a Simple GET URL for the PoC

We first thought we could just make a simple clickable link like:

```
https://TARGET/submit?id=admin&name=<img src=x onerror=alert(1)>&email=a@a.com&age=22
```

This **failed with "Method Not Allowed" (HTTP 405)**. The reason: the `/submit` endpoint only accepts `POST` requests with a JSON body — it does not accept `GET` requests at all. Visiting a URL in a browser always sends a GET request, so this approach could never work here. This was an important lesson: not every vulnerable endpoint can be triggered with a simple link — the HTTP method matters.

### PoC

Since the endpoint requires `POST` with `Content-Type: application/json`, a plain URL isn't enough. The correct PoC is an HTML page that automatically sends the POST request when opened:

html

```html
<!DOCTYPE html>
<html>
<body>
<script>
fetch('https://TARGET/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        id: 'admin',
        name: '<img src=x onerror=alert(document.domain)>',
        email: 'poc@test.com',
        age: 22
    })
});
</script>
</body>
</html>
```

If a victim (or an admin bot that reviews submissions) opens this page, it silently sends the malicious data to the server. If that data is later shown in an admin panel without proper escaping, the XSS payload executes in the admin's browser — this is the real impact of a **stored XSS**, much more dangerous than a self-XSS alert.
