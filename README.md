# OpenAI Auth Gateway

Node.js gateway that keeps OpenAI API keys on the server. It supports Realtime
client secrets, proxied text chat, scenario generation, and WorldEdit formula generation.

## Text chat endpoint

`POST /chat` accepts `project`, `messages`, `temperature`, `max_tokens`, and
`stream`. The model and output limits are controlled by the gateway, permanent
OpenAI API keys never leave the server, and both JSON and SSE streaming responses
retain the Chat Completions response format expected by existing clients.

## Audio transcription endpoint

`POST /transcribe` accepts a multipart `audio` file of up to 15 MB and an
optional `project` field. The gateway sends it to `gpt-4o-mini-transcribe` and
returns `{ "text": "..." }` without exposing a permanent OpenAI API key.

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
