#regex_patterns.py
PATTERNS = {
    "name": r'\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b',
    "aadhaar": r'\b\d{12}\b|\b\d{4}\s?\d{4}\s?\d{4}\b',
    "pan": r'\b[A-Z]{5}\d{4}[A-Z]\b',
    "phone": r'\b[6-9]\d{9}\b',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    "dob": r'\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b'
}
