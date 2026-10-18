# CertGuard

Free SSL/TLS certificate checker: expiry, chain trust, hostname match, TLS version, A/B/C/F grade.

## Live service

- Web app and API: https://certguard.mike-tusa.workers.dev/
- Pricing: https://certguard.mike-tusa.workers.dev/
- Support: digitalpromohub.support@gmail.com

## Use it from an AI assistant (MCP)

CertGuard is a remote MCP server (Streamable HTTP) at `https://certguard.mike-tusa.workers.dev/mcp`. Tools: `check_certificate`.

Cursor and Windsurf accept this config:

```json
{
  "mcpServers": {
    "certguard": {
      "type": "http",
      "url": "https://certguard.mike-tusa.workers.dev/mcp"
    }
  }
}
```

Cline (MCP Servers > Remote Servers, or `cline_mcp_settings.json`) needs `"type": "streamableHttp"`:

```json
{
  "mcpServers": {
    "certguard": {
      "type": "streamableHttp",
      "url": "https://certguard.mike-tusa.workers.dev/mcp"
    }
  }
}
```

Claude Desktop: open Settings > Connectors, choose "Add custom connector" and paste `https://certguard.mike-tusa.workers.dev/mcp`. Or, for clients that only support local (stdio) servers, use the mcp-remote bridge: `npx mcp-remote https://certguard.mike-tusa.workers.dev/mcp`.

VS Code uses a `servers` key instead of `mcpServers`.

The `server.json` file is the [MCP Registry](https://registry.modelcontextprotocol.io) manifest for this server.

## Run your own copy

Requires Node.js 22+ and a Cloudflare account.

```bash
npm install
npx wrangler@4 dev      # local dev server
```

`wrangler.toml` is a template: create your own KV namespaces / D1 databases / rate-limit namespaces and replace the `<PLACEHOLDER>` values before `npx wrangler@4 deploy`. Any secrets the Worker reads go in `wrangler secret put` (or `.dev.vars` locally), never in the repo.

Optional Worker secrets (leave unset if you do not need them): `RAPIDAPI_PROXY_SECRET` (only needed if you sell the API through RapidAPI; it must match the X-RapidAPI-Proxy-Secret header RapidAPI adds).

## Third-party data

`src/roots.js` is generated from the Mozilla root store (via curl's cacert.pem), which Mozilla publishes under MPL-2.0 (https://mozilla.org/MPL/2.0/).

## License

MIT (c) Digital Promo Hub. See [LICENSE](LICENSE).
