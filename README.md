# OpenAI Auth Gateway

Node.js gateway that keeps OpenAI API keys on the server. It supports Realtime
client secrets, scenario generation, and WorldEdit formula generation.

## Minecraft shape endpoint

Set these deployment environment variables:

- `OPENAI_API_KEY` (or `OPENAI_API_KEY_1` through `OPENAI_API_KEY_10`)
- `MINECRAFT_MOD_TOKEN` — a separate random token used only by the Minecraft mod

Request:

```http
POST /generate-shape
Authorization: Bearer <MINECRAFT_MOD_TOKEN>
Content-Type: application/json

{"prompt":"A hollow heart 30 blocks wide"}
```

The response contains `expression`, `material`, and `description`. The OpenAI
API key is never returned by this endpoint.

Generate a token with `openssl rand -hex 32` and store it only in the deployment
environment and the local Minecraft configuration file.
