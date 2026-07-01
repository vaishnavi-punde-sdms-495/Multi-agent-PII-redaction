# utils/regex_patterns.py
# Pure data module — no imports from this project, no circular dependencies.

PATTERNS = {
    'aadhaar':         r'\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b',
    'pan':             r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
    'phone':           r'(?<!\d)(?:\+91[\s\-]?)?[6-9]\d{9}(?!\d)',
    'email':           r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    'dob':             r'\b(?:\d{1,2}[\-/\.]\d{1,2}[\-/\.]\d{2,4}|\d{4}[\-/\.]\d{1,2}[\-/\.]\d{1,2})\b',
    'voter_id':        r'\b[A-Z]{3}[0-9]{7}\b',
    'passport':        r'\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b',
    'driving_license': r'\b[A-Z]{2}[\s\-]?\d{2}[\s\-]?\d{4}[\s\-]?\d{7}\b',
    'gst':             r'\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b',
    'account_number':  r'\b\d{9,18}\b',
    'ifsc':            r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
    'pincode':         r'\b[1-9][0-9]{5}\b',
}