# app/recognizers.py
from presidio_analyzer import PatternRecognizer, Pattern
from typing import List


def get_custom_recognizers() -> List[PatternRecognizer]:
    recognizers = []

    # Shared context terms that boost detection confidence when found within 5 tokens of a pattern
    secret_context = [
        "secret", "token", "api_key", "apikey", "password", "passwd", "pwd",
        "config", "env", "access_key", "auth", "bearer", "credential", "private"
    ]

    # -------------------------------------------------------------------------
    # 1. CLOUD & AI CREDENTIALS
    # -------------------------------------------------------------------------

    # AWS Access Key ID (AKIA / ASIA / ABIA / ACIA followed by 16 hex/alphanumeric characters)
    aws_pattern = Pattern(
        name="aws_access_key_regex",
        regex=r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
        score=0.85
    )
    recognizers.append(PatternRecognizer(
        supported_entity="AWS_ACCESS_KEY",
        patterns=[aws_pattern],
        context=secret_context + ["aws", "amazon", "iam", "bucket", "s3"]
    ))

    # AI Provider API Keys (OpenAI, Anthropic, Google Gemini AIza)
    ai_key_pattern = Pattern(
        name="ai_api_key_regex",
        regex=r"\b(?:sk-(?:proj-|svcacct-|admin-|none-|org-)?[a-zA-Z0-9_-]{32,}|sk-ant-api03-[a-zA-Z0-9_-]{93}AA|AIza[0-9A-Za-z-_]{35})\b",
        score=0.90
    )
    recognizers.append(PatternRecognizer(
        supported_entity="AI_API_KEY",
        patterns=[ai_key_pattern],
        context=secret_context + ["openai", "anthropic", "claude", "gemini", "gpt", "llm"]
    ))

    # Version Control Tokens (GitHub PAT, GitLab PAT)
    vcs_token_pattern = Pattern(
        name="vcs_token_regex",
        regex=r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,255}|glpat-[A-Za-z0-9\-]{20,})\b",
        score=0.90
    )
    recognizers.append(PatternRecognizer(
        supported_entity="VCS_ACCESS_TOKEN",
        patterns=[vcs_token_pattern],
        context=secret_context + ["github", "gitlab", "repo", "git", "commit", "clone"]
    ))

    # Slack Tokens & Webhooks
    slack_pattern = Pattern(
        name="slack_token_regex",
        regex=r"\b(?:xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)\b",
        score=0.85
    )
    recognizers.append(PatternRecognizer(
        supported_entity="SLACK_CREDENTIAL",
        patterns=[slack_pattern],
        context=secret_context + ["slack", "bot", "channel", "webhook", "chat"]
    ))

    # -------------------------------------------------------------------------
    # 2. INFRASTRUCTURE & AUTHENTICATION SECRETS
    # -------------------------------------------------------------------------

    # Private SSH / RSA / EC Keys
    private_key_pattern = Pattern(
        name="private_key_regex",
        regex=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        score=0.95
    )
    recognizers.append(PatternRecognizer(
        supported_entity="PRIVATE_ENCRYPTION_KEY",
        patterns=[private_key_pattern],
        context=["ssh", "rsa", "cert", "key", "ssl", "tls", "pem"]
    ))

    # JSON Web Tokens (JWT)
    jwt_pattern = Pattern(
        name="jwt_regex",
        regex=r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",
        score=0.65  # Base score lower; relies heavily on context words to hit 0.85+
    )
    recognizers.append(PatternRecognizer(
        supported_entity="JWT_TOKEN",
        patterns=[jwt_pattern],
        context=secret_context + ["jwt", "session", "bearer", "header", "payload", "auth"]
    ))

    # Database Connection Strings (Postgres, MongoDB, MySQL, Redis URIs)
    db_uri_pattern = Pattern(
        name="db_connection_string_regex",
        regex=r"\b(?:mongodb(?:\+srv)?|postgresql|postgres|mysql|redis):\/\/(?:[^:@\s]+:[^:@\s]+@)?[^:@\s]+(?::\d+)?\/(?:[^\s?]+)?\b",
        score=0.85
    )
    recognizers.append(PatternRecognizer(
        supported_entity="DATABASE_CONNECTION_STRING",
        patterns=[db_uri_pattern],
        context=secret_context + ["db", "database", "sql", "mongo", "redis", "uri", "url", "connect", "host"]
    ))

    # -------------------------------------------------------------------------
    # 3. LLM PROMPT INJECTIONS
    # -------------------------------------------------------------------------

    # Prompt Injection: System Override Attempts
    override_pattern = Pattern(
        name="system_override_regex",
        regex=r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|prompts|rules)\b",
        score=0.85
    )
    recognizers.append(PatternRecognizer(
        supported_entity="PROMPT_INJECTION_OVERRIDE",
        patterns=[override_pattern],
        context=["system", "override", "instruction", "prompt", "rules", "bypass"]
    ))

    # Prompt Injection: Jailbreak / Roleplay (DAN mode)
    jailbreak_pattern = Pattern(
        name="jailbreak_roleplay_regex",
        regex=r"\b(?:you are now|act as|enable)\s+(?:DAN|developer mode|unfiltered mode|jailbreak)\b",
        score=0.85
    )
    recognizers.append(PatternRecognizer(
        supported_entity="PROMPT_INJECTION_JAILBREAK",
        patterns=[jailbreak_pattern],
        context=["roleplay", "dan", "mode", "unfiltered", "restriction", "capable"]
    ))

    return recognizers