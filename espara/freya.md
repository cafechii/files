## JSONP Callback Injection



The application provides a note editor where users can enter content and generate a shareable link.

When the user clicks the "Bind the rune" button, the application retrieves the editor's HTML content,

 encodes it using Base64, 

and places the encoded value in the `d` parameter of the generated URL:

`/n/?d=<Base64-encoded-content>`

When the generated link is opened, the application decodes the content and renders it inside the note page.

Testing revealed that the application does not properly sanitize certain HTML elements and attributes before rendering them. Additionally, the application exposes a same-origin JSONP endpoint (`/reactions.js`) that accepts a user-controlled callback parameter.

By embedding a reference to this endpoint in the note content, it was possible to trigger the specified callback when the generated note link was opened.



```url
https://a4b362ac61.0o8.ir/n/?d=PHNjcmlwdCBzcmM9Ii9yZWFjdGlvbnMuanM/Y2FsbGJhY2s9YWxlcnQmdmFsdWU9b3JpZ2luIj48L3NjcmlwdD4=
```

parameter d=

```javascript
<script src="/reactions.js?callback=alert&value=origin"></script>
```
