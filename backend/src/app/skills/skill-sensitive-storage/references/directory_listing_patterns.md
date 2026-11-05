# Directory Listing Detection Cheatsheet

## Apache Autoindex

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /ftp</title></head>
<body><h1>Index of /ftp</h1><table>
<tr><th align="left"><a href="?C=N;O=D">Name</a></th>...</tr>
<tr><td>[DIR]</td><td><a href="legal/">legal/</a></td>...</tr>
</table></body></html>
```

Keywords: `Index of /`, `Directory listing for /`, `[DIR]`, `<table>` rows linking siblings.

## nginx Autoindex

```html
<html>
<head><title>Index of /downloads/</title></head>
<body>
<h1>Index of /downloads/</h1><hr><pre><a href="../">../</a>
<a href="file1.pdf">file1.pdf</a>
</pre><hr></body></html>
```

Keywords: `<h1>`, `<pre>`, `href="../` in a `<pre>` block.

## JSON Directory Listings (SPA/Node APIs)

```json
{"files": ["legal.md", "acquisitions.md"], "total": 2}
{"data": [{"name":"purchase.zip","size":1024}], "status":"ok"}
```

Heuristic: JSON object at start + array key like `files`, `items`, `entries`, `data`, `documents`, each mapped to lists of objects/names.

## Express `serve-index` middleware

Similar to nginx autoindex but often styled:

```html
<h1>/downloads/</h1><ul><li><a href="file.pdf">file.pdf</a></li></ul>
```

## IIS Directory Browsing

```html
<table><tr><th>Filename</th>...<tr><td><a href="report.docx">report.docx</a></td></tr></table>
```

## Negative Signals (NOT a listing)

- Single-file HTML page with app markup (`<div id="root">`, bundler scripts)
- 404 JSON: `{"message":"Not Found"}` with 200 status (SPA wildcard)
- Login redirect `<meta http-equiv="refresh">` or full login form markup

## Sensitivity Keywords

| Category | Keywords |
|----------|----------|
| credentials | `api_key`, `apikey`, `token`, `secret`, `password`, `passwd`, `token_url` |
| personal | `gdpr`, `acquisition`, `invoice`, `salary`, `citizen`, `phone number` |
| config | `db_host`, `database`, `redis`, `smtp`, `rabbitmq`, `kubernetes` |
| contracts | `termination`, `legal`, `nda`, `purchase`, `acquisitions`, `premium` |

## False-Positive Traps

1. **SPA wildcard**: any random path returns the app shell HTML → looks like "directory visible". Distinguish by checking for `Index of` / autoindex keywords instead of app markup.
2. **Custom error pages**: NGINX 404 pages often have `href="../` — but not inside `<pre>`.
3. **Static asset 200**: minified `main.js` returns 200 — a normal bundle, not a listing or backup.
