# Proxy Handler Refactoring Notes

## Task
Refactor `proxy.go` to reduce code duplication, simplify skill references, and fix
the Helm `repo add` hang issue with large (~600KB) response bodies.

## Key Findings

### 1. Duplicated TLS Config (lines ~620-655 and ~872-908)
`handleMITM()` and `HandleTransparentTLS()` both build identical `tls.Config` with:
- MinVersion TLS 1.0, MaxVersion TLS 1.3
- Explicit CurvePreferences (disabling post-quantum)
- All cipher suites including insecure ones
- HTTP/1.1 forced via NextProtos

**Fix**: Extract a `newMITMTLSConfig(getCertFunc)` helper that returns the shared config.

### 2. Duplicated TLS Request Handlers (lines ~700-810 and ~947-1073)
`handleMITMRequest()` and `handleTransparentTLSRequest()` are nearly identical.
Both do: authenticate -> check registry/package/host approval -> log -> capture
full logging -> set URL scheme/host -> inject creds -> RoundTrip -> log -> write response.

Differences:
- `handleTransparentTLSRequest` does its own authentication (skill may not be known yet)
- `handleMITMRequest` receives skill from the CONNECT phase
- URL host construction: MITM uses `targetAddr` (may include port), transparent uses `host + ":443"`

**Fix**: Merge into a single `handleTLSRequest(clientConn, req, host, targetAddr, skill, sourceIP, start)`.
For transparent mode, authenticate first then call the unified handler.

### 3. Duplicated Package Repo Handlers (lines ~1176-1308 and ~1312-1429)
`handlePackageRepoHTTPRequest()` (uses http.ResponseWriter) and
`handlePackageRepoTLSRequest()` (uses net.Conn) have identical approval logic.
Only the response writing mechanism differs.

**Fix**: Extract the approval/logging logic into a shared function that returns
an approval decision. Then have thin HTTP and TLS wrappers that handle the
response writing.

Alternatively, introduce a `responseWriter` interface/adapter that abstracts
over `http.ResponseWriter` vs `net.Conn` for writing error responses and
forwarding responses.

### 4. Duplicated Forwarding Logic
The "forward and write response" pattern repeats in multiple places:
- `handleHTTP`: RoundTrip -> copy headers -> WriteHeader -> io.Copy
- `handleMITMRequest`: RoundTrip -> resp.Write(conn)
- `handleTransparentTLSRequest`: RoundTrip -> resp.Write(conn)
- `handleRegistryTLSRequest`: RoundTrip -> resp.Write(conn)
- `handlePackageRepoHTTPRequest`: RoundTrip -> copy headers -> WriteHeader -> io.Copy
- `handlePackageRepoTLSRequest`: RoundTrip -> resp.Write(conn)

**Fix**: Create `forwardHTTP(w, req, transport)` and `forwardTLS(conn, req, transport)`
helpers.

### 5. Skill Simplification
The `getSkillID()` function and skill-based three-level approval could potentially
be simplified if skills are not actively used. However, the approval system
fundamentally uses the three-level pattern in multiple places (host, image, library).
The skill code itself is not very verbose. Investigation showed skills ARE still part
of the approval model (auth.SkillStore, pre-approved hosts), just not the primary
auth mechanism in practice.

**Conclusion**: The skill code is minimal enough to keep. The real duplication is in
the handler functions, not the approval logic.

### 6. Helm Hang Issue (CRITICAL BUG)
**Symptom**: `helm repo add` hangs when proxied, even though the full response
(~600KB) is visible in the proxy logs.

**Root cause analysis**: Looking at the Helm stack trace, Helm is stuck in
`io.Copy` reading the response body from a TLS connection. The proxy uses
`resp.Write(clientConn)` to send the response back through the MITM'd TLS
connection. `http.Response.Write()` writes the response in HTTP/1.1 format.

The issue is likely that `resp.Write()` may not properly signal the end of
the response body when `Content-Length` is not set or when `Transfer-Encoding:
chunked` is used. With large bodies, the client (Helm) keeps waiting for more
data because the connection isn't closed and no end-of-body signal was sent.

**Fix options**:
a) Ensure `Content-Length` is set in forwarded responses (read full body first,
   then write with explicit length). This works but buffers the full response.
b) After `resp.Write(conn)`, check if the response used chunked encoding and
   ensure the final chunk marker ("0\r\n\r\n") was written.
c) Use HTTP/1.0 semantics where body end = connection close (not ideal for
   keep-alive).
d) The real fix may be to ensure `resp.Write()` correctly handles the
   `Transfer-Encoding` from upstream. If upstream sends `Transfer-Encoding:
   chunked`, `resp.Write()` should re-chunk or set Content-Length.

Most likely fix: After reading the response body completely for forwarding,
set `resp.ContentLength` explicitly and remove `Transfer-Encoding` header,
so `resp.Write()` uses Content-Length framing instead of chunked.

## Proposed Refactoring Order
1. Extract shared TLS config helper
2. Unify `handleMITMRequest` and `handleTransparentTLSRequest`
3. Extract package repo approval logic
4. Extract forwarding helpers
5. Fix the Helm response body issue
6. Run tests, verify no regressions
