# app/scanner.py
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.config import settings
from app.recognizers import get_custom_recognizers
from app.schemas import DetectedEntity


class PresidioScanner:
    def __init__(self):
        # 1. Configure and build the spaCy NLP engine FIRST
        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": settings.DEFAULT_SPACY_MODEL}],
        }
        nlp_provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
        self.nlp_engine = nlp_provider.create_engine()

        # 2. Initialize Registry and bind the NLP engine directly to the predefined recognizers
        self.registry = RecognizerRegistry()
        self.registry.load_predefined_recognizers(
            languages=["en"],
            nlp_engine=self.nlp_engine
        )

        # 3. Inject our custom Prompt Injection recognizers
        for recognizer in get_custom_recognizers():
            self.registry.add_recognizer(recognizer)

        # 4. Pass BOTH the bound registry and the nlp_engine into AnalyzerEngine
        self.analyzer = AnalyzerEngine(
            registry=self.registry,
            nlp_engine=self.nlp_engine
        )
        self.anonymizer = AnonymizerEngine()

    def analyze_and_sanitize(self, text: str, language: str = "en", threshold: float = 0.60, mode: str = "replace"):
        if not text or not text.strip():
            return [], text

        # 5. Normalize language code (e.g., converts 'en-US', 'en_US', 'English' -> 'en')
        clean_lang = language.lower().split("-")[0].split("_")[0]
        if clean_lang != "en":
            clean_lang = "en"  # Fallback to default supported language to prevent 500 errors

        # Step 1: Run NLP analysis with the normalized language code
        results = self.analyzer.analyze(
            text=text,
            language=clean_lang,
            score_threshold=threshold
        )

        # Sort results by start index descending to match frontend replacement logic
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
                operators[t.entity_type] = OperatorConfig("mask",
                                                          {"chars_to_mask": 12, "masking_char": "*", "from_end": False})
            elif mode == "redact":
                operators[t.entity_type] = OperatorConfig("redact", {})
            else:
                operators[t.entity_type] = OperatorConfig("replace", {"new_value": f"[{t.entity_type}]"})

        # Step 3: Perform text mutation
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )

        # Reverse threats array back to chronological reading order (left-to-right)
        return threats[::-1], anonymized_result.text


# Create singleton instance
scanner_engine = PresidioScanner()