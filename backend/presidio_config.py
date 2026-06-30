#presidio_config.py
import os
import spacy

# Force Presidio to use the small model
os.environ['PRESIDIO_ANALYZER_DEFAULT_MODEL'] = 'en_core_web_sm'

# Pre-load the model to ensure it's available
try:
    nlp = spacy.load('en_core_web_sm')
    print("✅ en_core_web_sm loaded successfully")
except:
    print("⚠️ Downloading en_core_web_sm...")
    spacy.cli.download('en_core_web_sm')
    nlp = spacy.load('en_core_web_sm')
