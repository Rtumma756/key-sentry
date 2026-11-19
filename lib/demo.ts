// Demo sample: pre-written code with planted FAKE keys (TESTFAKE markers)
// plus decoys that must NOT be flagged. One click shows the full flow.
// All values are fake — never real credentials.

export const DEMO_CODE = `# app.py — sample service config (ALL keys below are FAKE test values)
import os

OPENAI_API_KEY = "sk-proj-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
ANTHROPIC_API_KEY = "sk-ant-api03-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
GEMINI_API_KEY = "AIzaTESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b"
GROQ_API_KEY = "gsk_TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
OPENROUTER_API_KEY = "sk-or-v1-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
DEEPSEEK_API_KEY = "sk-abcdef0123456789abcdef0123456789"
XAI_API_KEY = "xai-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
PERPLEXITY_API_KEY = "pplx-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
HF_TOKEN = "hf_TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
REPLICATE_API_TOKEN = "r8_TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

# .env — same keys, different file (the Anthropic key is duplicated on
# purpose: the scanner must report it once, not twice)
OPENAI_API_KEY="sk-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
MISTRAL_API_KEY="Kj8sDf2hG7mNq4wErTyUiOpAsDfGhJk"
TOGETHER_API_KEY="9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"
COHERE_API_KEY="Ab3dEf9Gh2JkLmNoPqRsTuVwXyZ1234567890abcd"
CUSTOM_API_KEY="Zx9qW8eR7tY6uI5oP4aS3dF2gH1jK0lM9nB8"
ANTHROPIC_API_KEY="sk-ant-api03-TESTFAKEa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"

# .mcp.json — one more OpenAI key, different value from the one above
{"mcpServers":{"openai-tools":{"command":"npx","env":{"OPENAI_API_KEY":"sk-proj-TESTFAKEmcp1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"}}}}

# Decoys — these must NOT be flagged:
request_id = "550e8400-e29b-41d4-a716-446655440000"
checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
api_key = "your-api-key-here"
password = "changeme"
openai_api_key = "sk-test-1234567890abcdef"
`;

// Expected demo outcome (mirrors the CLI prototype's fixture scorecard):
// 16 unique findings from 17 planted keys (1 duplicate collapsed),
// 0 findings from the decoy lines.
export const DEMO_EXPECTED_FINDINGS = 16;
