# app/scanner.py
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.recognizers import get_custom_recognizers
from app.schemas import DetectedEntity


class PresidioScanner:
    def __init__(self):
        # 1. Initialize Registry and load default NLP recognizers (Emails, Names, Credit Cards, etc.)
        self.registry = RecognizerRegistry()
        self.registry.load_predefined_recognizers()

        # 2. Inject our custom LLM security recognizers
        for recognizer in get_custom_recognizers():
            self.registry.add_recognizer(recognizer)

        # 3. Build engines
        self.analyzer = AnalyzerEngine(registry=self.registry)
        self.anonymizer = AnonymizerEngine()

    def analyze_and_sanitize(self, text: str, language: str = "en", threshold: float = 0.60, mode: str = "replace"):
        if not text or not text.strip():
            return [], text

        # Step 1: Run NLP analysis
        results = self.analyzer.analyze(
            text=text,
            language=language,
            score_threshold=threshold
        )

        # Sort results by start index descending to match our frontend logic
        results.sort(key=lambda x: x.start, reverse=True)

        threats = []
        for r in results:
            threats.append(DetectedEntity(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=round(r.score, 2),
                snippet=text[r.start:r.end]
            ))

        # Step 2: Configure Anonymization Operators based on mode
        operators = {}
        for t in threats:
            if mode == "mask":
                # Masks characters with asterisk, e.g., ****1234
                operators[t.entity_type] = OperatorConfig("mask",
                                                          {"chars_to_mask": 12, "masking_char": "*", "from_end": False})
            elif mode == "redact":
                # Removes text entirely
                operators[t.entity_type] = OperatorConfig("redact", {})
            else:
                # Default: Replaces with tag like [EMAIL_ADDRESS] or [PROMPT_INJECTION_OVERRIDE]
                operators[t.entity_type] = OperatorConfig("replace", {"new_value": f"[{t.entity_type}]"})

        # Step 3: Perform text mutation
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )

        # Reverse threats array back to chronological reading order (left-to-right)
        return threats[::-1], anonymized_result.text


# Create a singleton instance to be imported by endpoints
scanner_engine = PresidioScanner()