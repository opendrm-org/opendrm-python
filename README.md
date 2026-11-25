# opendrm (Python)

Sign playback tokens for an opendrm license server.

```python
from opendrm import playback_token

token = playback_token(
    secret=settings.OPENDRM_TOKEN_SECRET,   # same value as on the opendrm server
    user=request.user.id,
    title="ip-c3",                          # the title id used with `opendrm keys create`
    device=request.headers.get("X-Device-Id"),
    claims={"plan": "paid"},                # whatever your policies check
)
```

Return the token to your player, which sends it as `Authorization: Bearer <token>`
with each license request. Tokens last 60 seconds by default; mint a fresh one
for every play.

Standard library only. Python 3.9+.

## License

Apache-2.0. This SDK is not covered by the Business Source License that
applies to the [openDRM server](https://github.com/opendrm-org/opendrm); you can
embed it in any app.
