# End-to-end test harness (optional)

Runs the real backend against local stand-ins for the Wazuh manager (:55000), Wazuh Indexer (:9200)
and OpenRouter (:4010), then drives the built frontend with Playwright. Nothing here touches a real Wazuh or OpenRouter.

```bash
cd e2e && openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj "/CN=127.0.0.1"
node mock-services.js &
cd ../backend && WAZUH_HOST=127.0.0.1 WAZUH_USERNAME=u WAZUH_PASSWORD=your-wazuh-password INDEXER_USERNAME=u INDEXER_PASSWORD=p \
  OPENROUTER_API_KEY=test-key-not-real OPENROUTER_BASE_URL=http://127.0.0.1:4010/api/v1 OPENROUTER_MODEL=test/model:free \
  AI_TIMEOUT_MS=3000 npx ts-node src/index.ts &
cd ../frontend && npm run build && npx vite preview --port 4173 --host 127.0.0.1 &
mkdir -p /tmp/shots && node ../e2e/e2e.js /tmp/shots    # needs: npm i -D playwright
```
