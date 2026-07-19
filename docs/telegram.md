# Telegram Bot Setup and First Account

Telegram support is optional. When enabled, the bot controls the one GlobalProtect profile configured in the Web UI and broadcasts meaningful VPN action, state, phase, OTP, and reconnect events.

## Security model

- `TELEGRAM_OWNER_ID` is the trust root.
- Authorization uses immutable numeric Telegram user IDs, never usernames.
- The owner is always authorized and cannot be revoked.
- All VPN actions must originate from a private chat where the chat ID equals the sender's user ID.
- Groups, channels, pending users, denied users, and revoked users cannot control the VPN or receive VPN notifications.
- Bot tokens and OTP values are not stored in `config.json` and must not be written to logs.

## 1. Create the bot

1. Open a private chat with Telegram's official `@BotFather` account.
2. Send `/newbot`.
3. Choose a display name and a username ending in `bot`.
4. Copy the generated token into a private password manager. Treat it as a password.

Do not commit the token to Git, paste it into tickets, or include it in screenshots.

## 2. Obtain the owner's numeric Telegram ID

Use the numeric ID of the human account that will approve all other users. The value must be positive.

A first-party Bot API method is:

1. Before starting GlobalProtect Manager, send any private message to the new bot.
2. Export the token only in the current shell:

   ```bash
   read -s TELEGRAM_BOT_TOKEN
   export TELEGRAM_BOT_TOKEN
   ```

3. Read pending updates:

   ```bash
   curl -fsS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates"
   ```

4. Find `message.from.id` for your message. That integer is `TELEGRAM_OWNER_ID`.
5. Clear the temporary shell value after writing `.env`:

   ```bash
   unset TELEGRAM_BOT_TOKEN
   ```

Do not run `getUpdates` while GlobalProtect Manager is polling the same bot. The application owns polling after startup.

## 3. Configure Docker Compose

Copy the example environment file:

```bash
cp .env.example .env
chmod 600 .env
```

Set:

```dotenv
TELEGRAM_BOT_TOKEN=123456789:replace_with_real_token
TELEGRAM_OWNER_ID=123456789
TELEGRAM_ACCESS_PATH=/data/telegram-access.json
```

Both token and owner ID must be valid to enable the bot. Setting only one disables Telegram while leaving the Web UI and GlobalProtect service healthy.

Validate and start:

```bash
docker compose config
docker compose up -d --build
docker compose logs -f globalprotect-manager
```

The service removes any webhook without dropping pending updates, registers its commands, and starts long polling. It does not open a Telegram webhook port.

## 4. Initialize the owner account

1. Open a private chat with the bot from the account whose numeric ID matches `TELEGRAM_OWNER_ID`.
2. Send `/start`.
3. The bot displays the GlobalProtect menu immediately; the owner does not require an access-store record.
4. Verify `/status` and `/menu`.
5. Use `/access` to inspect access requests.

If `/start` does not show a menu:

- confirm you are using a private chat
- confirm the sender ID exactly matches `TELEGRAM_OWNER_ID`
- inspect `docker compose logs globalprotect-manager`
- confirm the access JSON is valid and the bot was not disabled during startup

## 5. Approve the first additional account

On the additional user's Telegram account:

1. Open a private chat with the bot.
2. Send `/start`.
3. The user receives a pending message and cannot see or invoke VPN actions.

On the owner account:

1. Open the request card sent by the bot, or send `/access`.
2. Select the user by numeric ID.
3. Choose **Approve** or **Deny**.
4. The decision is persisted before the user is notified.

After approval, the user can send `/menu`, `/status`, `/connect`, and `/disconnect`. Repeating `/start` while pending does not create a duplicate request. A denied user remains denied until the owner changes the decision.

To remove access, use `/access` and revoke the approved user. Revocation immediately cancels that user's pending OTP prompt. Old buttons and OTP replies are rejected after revocation.

## Commands

| Command | Who | Purpose |
|---|---|---|
| `/start` | Anyone in a private chat | Initialize owner, request access, or show existing status |
| `/menu` | Owner or approved user | Show state-aware VPN actions |
| `/status` | Owner or approved user | Show current GlobalProtect state and phase |
| `/connect` | Owner or approved user | Connect the configured profile |
| `/disconnect` | Owner or approved user | Disconnect the active connection |
| `/access` | Owner only | Review and manage access records |

Unknown text does not trigger VPN actions. Non-command text is consumed only when it is a valid reply to an active OTP prompt.

## OTP behavior

### No saved TOTP seed

1. Select **Connect**.
2. The bot sends a ForceReply prompt for the initial OTP.
3. Reply to that exact prompt within 120 seconds.
4. The prompt and OTP message are deleted after the reply is claimed.
5. If GlobalProtect requests another OTP, use the **Enter OTP** button and reply to the new prompt.

Expired, repeated, unrelated, group-chat, unauthorized, denied, or revoked replies do not invoke the controller.

### Saved TOTP seed

When the profile contains a saved TOTP seed, **Connect** starts without asking for the initial OTP. The VPN manager generates codes when the server prompts. Persisted auto-reconnect behavior is retained.

Configure or clear the TOTP seed only through the Web UI. Never send the TOTP seed itself to the bot.

## Notifications

Each meaningful GlobalProtect event is attempted once for:

- the owner
- every approved user at dequeue time

Pending, denied, and revoked users are excluded. If delivery to one account fails—for example, that account blocked the bot—delivery continues to the remaining recipients and does not alter the VPN state.

Messages include lifecycle information such as state, action, phase, OTP prompt, reconnect attempt, interface, or sanitized errors. Raw process logs, passwords, OTP values, TOTP seeds, cookies, and authorization headers are excluded.

## Access store

Default path:

```text
/data/telegram-access.json
```

Shape:

```json
{
  "users": [
    {
      "user_id": 234567890,
      "chat_id": 234567890,
      "username": "example",
      "display_name": "Example User",
      "status": "approved",
      "requested_at": "2026-07-19T10:00:00Z",
      "decided_at": "2026-07-19T10:01:00Z"
    }
  ]
}
```

Do not manually add the owner. The loader rejects the entire file when it contains malformed JSON, invalid IDs, group chat IDs, duplicate users, unknown statuses, an owner record, or inconsistent timestamps. A corrupt store disables the bot instead of granting default access; the Web UI remains available.

Prefer managing records through `/access`. Before manual repair, stop the service and back up the file:

```bash
docker compose stop globalprotect-manager
docker run --rm \
  -v globalprotect-manager-data:/data:ro \
  -v "$PWD":/backup \
  alpine:3.20 cp /data/telegram-access.json /backup/telegram-access.json.bak
docker compose start globalprotect-manager
```

## Rotate the bot token

1. Revoke or regenerate the token with `@BotFather`.
2. Update `TELEGRAM_BOT_TOKEN` in `.env`.
3. Recreate the container:

   ```bash
   docker compose up -d --force-recreate
   ```

4. Confirm `/status` from the owner account.

Access decisions persist because they are stored in the Docker volume, not in the bot token.
