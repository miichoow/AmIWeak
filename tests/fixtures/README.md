# Captured range responses

Verbatim slices of live provider responses, used by `tests/checks/test_real_payloads.py`
to check the parsers against the real wire format rather than an invented one.

Both are ranges for `sha1("password")` = `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8`,
captured 2026-07-31. `hibp_range_5BAA6.txt` keeps four real rows and four padding
rows; the full response had 1978 rows of which 131 were padding.

To regenerate:

```bash
curl -H 'Add-Padding: true' https://api.pwnedpasswords.com/range/5BAA6
curl 'https://weakpass.com/api/v1/range/5baa61.txt?filter=hash&type=sha1'
```

If a provider changes its format, these tests fail before anything in production
starts quietly answering "safe".
