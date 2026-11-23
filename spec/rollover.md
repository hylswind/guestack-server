# Month rollover

> What happens at the month boundary, for the backend, the pages, and existing identity tokens.

**Status:** v1

> [!NOTE]
> Running the rollover is an operational task and is not part of this repository.

## Boundary

The boundary is 00:00:00 UTC on the 1st of the month. Each image serves exactly one `EPOCH_ID`, and there is no overlap or grace window.

The page loader picks each month's pages by **the visitor's own clock**. Next month's pages are published in advance and are served as soon as a visitor's clock enters that month. Nothing is switched by hand at the boundary.

- Next month's backend image is built first, because its PCRs go into next month's login page.
- Next month's backend runs on standby before the boundary. Its epoch gate refuses registrations until its month starts, because the gate checks the Telegram-signed `iat` and not the instance clock.
- Last month's backend refuses registrations from the first instant of the new month, even if it is still running. It is terminated afterwards.
- Identity tokens expire at `epoch_end` of the month they were issued in. RPs allow 60 s of clock leeway.

## Page behaviour

### Login page

Only the **login page** is tied to a month, and it is the only page that talks to the backend. Which login page a visitor gets depends on their clock. Whether registration succeeds depends on Telegram's clock. The login page handles the two disagreeing.

When the backend answers `epoch_not_active`, or the login page can already tell that its `EPOCH_ID` differs from the current UTC month on the device, it shows one message:

> This page does not match the current month. If this tab has been open since last month, reload it. Otherwise check that your device's date and time are correct.

Reloading fixes a stale tab but not a wrong clock, so the message names both. A login in flight across the boundary fails cleanly with that message.

### Sign page

The **sign page** has no month. It uses any stored identity token that has not expired, and deletes an identity token and its key only once the token has expired.

## Restart mid-month

A restart creates a new `S` and a new `boot`, so every guest ID changes for the rest of the month. Identity tokens issued before the restart stay valid until their `exp`. This is an accepted trade-off: `S` is never persisted, so it cannot survive a restart.
