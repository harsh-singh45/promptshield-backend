# app/recognizers.py
from presidio_analyzer import PatternRecognizer, Pattern


def get_custom_recognizers():
    recognizers = []

    # 1. Prompt Injection: System Override Attempts
    override_pattern = Pattern(
        name="system_override_regex",
        regex=r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|prompts|rules)\b",
        score=0.85
    )
    override_recognizer = PatternRecognizer(
        supported_entity="PROMPT_INJECTION_OVERRIDE",
        patterns=[override_pattern],
        context=["system", "override", "instruction", "prompt", "rules", "bypass"]
    )
    recognizers.append(override_recognizer)

    # 2. Prompt Injection: Jailbreak / Roleplay (DAN mode)
    jailbreak_pattern = Pattern(
        name="jailbreak_roleplay_regex",
        regex=r"\b(?:you are now|act as|enable)\s+(?:DAN|developer mode|unfiltered mode|jailbreak)\b",
        score=0.85
    )
    jailbreak_recognizer = PatternRecognizer(
        supported_entity="PROMPT_INJECTION_JAILBREAK",
        patterns=[jailbreak_pattern],
        context=["roleplay", "dan", "mode", "unfiltered", "restriction", "capable"]
    )
    recognizers.append(jailbreak_recognizer)

    return recognizers