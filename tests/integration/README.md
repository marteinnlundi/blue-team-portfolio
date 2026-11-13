# Integration tests

These tests run the real tools together as subprocesses:

```text
eventgen  ->  logpipe  ->  sigma-lite | auth-anom | ioc-feed
```

They check that every scenario from [eventgen](../../tools/eventgen) produces
the alerts it should, that harmless traffic produces none, and that every alert
follows the [alert schema](../../docs/standards/alert_schema.md). They are what
keeps tools written in different languages in agreement.

```bash
pip install -r tools/sigma-lite/requirements-dev.txt
(cd tools/ioc-feed && npm ci && npm run build)    # optional: ioc-feed tests are skipped without it
python3 -m pytest tests/integration -v
```

logpipe is built automatically. Set `LOGPIPE_BIN` or `IOC_FEED_CLI` to test
existing builds instead.
