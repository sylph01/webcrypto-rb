# Browser dev/test environment

WebCrypto's `crypto.subtle` only exists in a secure browser context, so anything
that touches it runs here on `ruby.wasm`. Pure-Ruby code (e.g. `Encoding`) can
still be exercised with native CRuby + `ruby -c` outside the browser.

## Serve

Serve the **repository root** (not this folder) so the pages can fetch
`../webcrypto.rb`, then open the pages under `/browser/`:

```sh
ruby -run -e httpd . -p 8000
```

`localhost` qualifies as a secure context, so WebCrypto is available.

- Scratchpad: <http://localhost:8000/browser/index.html>
- Test suite: <http://localhost:8000/browser/tests.html>

ruby.wasm is pinned to `@ruby/wasm-wasi@2.7.1` / `@ruby/3.4-wasm-wasi@2.7.1`
(loaded from jsDelivr). Treat version bumps as intentional — several documented
quirks are version-dependent.

## Scratchpad (`index.html`)

A textarea + **Run** (Ctrl/Cmd+Enter) + output `<pre>`. Top-level `.await` works
because the code runs through `vm.evalAsync` (which sets up the fiber). The VM is
exposed as `window.vm`, so you can also drive it from the DevTools console:

```js
await vm.evalAsync(`WebCrypto.digest("abc".b, algorithm: "SHA-256").bytes`)
```

## Tests (`tests.html` + `tests.rb`)

`tests.rb` is a small assertion suite (`Tests.test`/`assert`/`assert_raises`)
that returns its results as JSON; `tests.html` renders them to a table and sets:

- `#status` text to `RUNNING` → `PASS` / `FAIL` / `ERROR`
- `window.__testResults` to the parsed results array

Both are convenient anchors for a headless driver (Playwright/Puppeteer): load
the page, wait for `#status` to leave `RUNNING`, then assert it reads `PASS`.
Add a test by appending a `Tests.test("…") { … }` block to `tests.rb`.
