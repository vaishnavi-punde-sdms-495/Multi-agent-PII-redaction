import os
import logging
import spacy
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
from presidio_analyzer.predefined_recognizers import (
    EmailRecognizer, 
    PhoneRecognizer, 
    SpacyRecognizer,
    DateRecognizer
)

# Force small model
os.environ['PRESIDIO_ANALYZER_DEFAULT_MODEL'] = 'en_core_web_sm'

logger = logging.getLogger(__name__)

class FastPresidioAgent:
    """Fast Presidio agent with ONLY necessary recognizers."""
    
    def __init__(self):
        self.analyzer = None
        self.nlp = None
        
        try:
            # Load spaCy model
            self.nlp = spacy.load('en_core_web_sm')
            logger.info("✅ spaCy loaded")
            
            # Create custom registry with ONLY necessary recognizers
            registry = RecognizerRegistry()
            
            # ONLY these recognizers - no UK/US/European
            registry.add_recognizer(SpacyRecognizer())  # For names (PERSON)
            registry.add_recognizer(EmailRecognizer())  # For emails
            registry.add_recognizer(PhoneRecognizer())  # For phones
            registry.add_recognizer(DateRecognizer())   # For DOB
            
            # Indian PII patterns (custom)
            patterns = [
                ('AADHAAR', r'\b\d{4}\s?\d{4}\s?\d{4}\b|\b\d{12}\b'),
                ('PAN', r'\b[A-Z]{5}\d{4}[A-Z]\b'),
            ]
            for entity, pattern in patterns:
                recognizer = PatternRecognizer(
                    supported_entity=entity,
                    patterns=[Pattern(name=entity, regex=pattern, score=0.85)]
                )
                registry.add_recognizer(recognizer)
                logger.info(f"✅ Added {entity} recognizer")
            
            # Create analyzer with custom registry
            self.analyzer = AnalyzerEngine(registry=registry)
            logger.info("✅ Presidio ready (only necessary recognizers)")
            
        except Exception as e:
            logger.error(f"❌ Presidio init failed: {e}")
            self.analyzer = None
    
    def detect(self, text):
        """Detect PII using Presidio."""
        if not self.analyzer or not text:
            return []
        try:
            return self.analyzer.analyze(text=text, language='en')
        except Exception as e:
            logger.error(f"❌ Detection failed: {e}")
            return []

# Singleton instance
_presidio = None

def get_presidio():
    global _presidio
    if _presidio is None:
        _presidio = FastPresidioAgent()
    return _presidio
