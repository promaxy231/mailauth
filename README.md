# MailAuth

Free, privacy-first SPF / DKIM / DMARC checker.

**Independent product** — not affiliated with any other brand.

## What it does

- Instant analysis of SPF, DKIM and DMARC records
- Clear Pass / Warning / Fail status
- Overall authentication score
- Actionable recommendations with example records
- Runs 100% in the browser (Cloudflare DNS-over-HTTPS)
- No accounts, no tracking, no data storage

## Security & Privacy

- All DNS lookups happen client-side
- Domain input is strictly validated and escaped
- No backend that logs or stores checked domains
- No third-party analytics or trackers
- Clear privacy statement on the page

## Deploy (Cloudflare Pages — $0)

1. Push this repository to GitHub
2. Cloudflare Dashboard → Pages → Create project
3. Connect the repo
4. Build settings:
   - Framework preset: None
   - Build command: (empty)
   - Output directory: `public`
5. Deploy

You get a `*.pages.dev` URL immediately. Custom domains are free.

## Local testing

```bash
npx serve public
```

Or just open `public/index.html` in a browser.

## Roadmap (future)

- Custom DKIM selector input
- Better recursive SPF lookup counting
- Optional monitoring + alerts (paid)
- Bulk domain checking
- Shareable report links
- French / Arabic interface

## License

MIT
