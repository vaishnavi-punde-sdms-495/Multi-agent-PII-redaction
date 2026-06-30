import re
import logging

logger = logging.getLogger(__name__)

class ContextRules:
    """Indian PII context rules for validation."""
    
    @staticmethod
    def get_entity_type(entity_type):
        """Map Presidio entity types to our PII types."""
        mapping = {
            'PERSON': 'name',
            'AADHAAR': 'aadhaar',
            'PAN': 'pan',
            'PHONE_NUMBER': 'phone',
            'EMAIL_ADDRESS': 'email',
            'DATE_TIME': 'dob',
            'DATE': 'dob'
        }
        return mapping.get(entity_type, entity_type.lower())
    
    # ============ INDIAN PII VALIDATION ============
    
    @staticmethod
    def is_valid_aadhaar(text):
        """Validate Aadhaar number (12 digits)."""
        digits = re.sub(r'\s', '', text)
        # Strip a leading '+' if it survived the whitespace-only strip above
        # (e.g. "+919175238190" -> "919175238190")
        digits = digits.lstrip('+')
        if len(digits) != 12 or not digits.isdigit():
            return False
        # Check for common fake patterns
        if digits in ['000000000000', '111111111111', '222222222222', 
                      '333333333333', '444444444444', '555555555555',
                      '666666666666', '777777777777', '888888888888', 
                      '999999999999', '123456789012']:
            return False
        # Disambiguate from an Indian mobile number written with its country
        # code and no separator (e.g. "+91 9175238190" -> raw digits
        # "919175238190", which is also a syntactically valid 12-digit
        # string). Aadhaar numbers are never printed with a country-code
        # prefix, so "91" + a valid 10-digit mobile shape (starts 6-9) is
        # almost certainly a phone number, not an Aadhaar — reject it here
        # so it doesn't get double-detected as both.
        if digits.startswith('91') and digits[2] in '6789':
            return False
        return True
    
    @staticmethod
    def is_valid_pan(text):
        """Validate PAN number (ABCDE1234F)."""
        text = text.upper().strip()
        if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', text):
            return False
        # Check for common fake PANs
        fake_pans = ['AAAAA1111A', 'BBBBB2222B', 'CCCCC3333C']
        if text in fake_pans:
            return False
        return True
    
    @staticmethod
    def is_valid_phone(text):
        """Validate Indian phone number (10 digits, starts with 6-9).
        Normalizes common prefixes (+91 / 91 / 0) before checking length,
        otherwise valid numbers written with a country code get rejected."""
        digits = re.sub(r'\D', '', text)

        if len(digits) == 12 and digits.startswith('91'):
            digits = digits[2:]
        elif len(digits) == 13 and digits.startswith('091'):
            digits = digits[3:]
        elif len(digits) == 11 and digits.startswith('0'):
            digits = digits[1:]

        if len(digits) != 10 or not digits.isdigit():
            return False
        if digits[0] not in '6789':
            return False
        # Check for common fake patterns
        if digits in ['0000000000', '1111111111', '2222222222', 
                      '3333333333', '4444444444', '5555555555',
                      '6666666666', '7777777777', '8888888888', 
                      '9999999999', '1234567890']:
            return False
        return True
    
    @staticmethod
    def is_valid_email(text):
        """Validate email address."""
        if '@' not in text or '.' not in text:
            return False
        # Check for common fake emails
        fake_emails = ['example@example.com', 'test@test.com', 
                       'test@domain.com', 'user@example.com']
        if text.lower() in fake_emails:
            return False
        return True
    
    @staticmethod
    def is_valid_dob(text):
        """Validate date of birth (DD/MM/YYYY or similar)."""
        # Check format
        if not re.match(r'\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}', text):
            return False
        return True
    
    # ============ CONTEXT RULES FOR INDIAN IDs ============
    
    @staticmethod
    def is_valid_indian_id(text, context_text=""):
        """
        Validate if text is a valid Indian ID based on context.
        Checks for Aadhaar, PAN, Voter ID, Passport, etc.
        """
        text = text.strip()
        
        # Aadhaar: 12 digits or 4-4-4 format
        if re.match(r'^\d{12}$', text) or re.match(r'^\d{4}\s?\d{4}\s?\d{4}$', text):
            return True
        
        # PAN: 5 letters, 4 digits, 1 letter
        if re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', text.upper()):
            return True
        
        # Voter ID: 3 letters + 7 digits (EPIC number)
        if re.match(r'^[A-Z]{3}[0-9]{7}$', text.upper()):
            # Check for common patterns
            if text.upper().startswith(('AAA', 'BBB', 'CCC')):
                return False
            return True
        
        # Passport: 1 letter + 7 digits or 8 characters
        if re.match(r'^[A-Z][0-9]{7}$', text.upper()) or re.match(r'^[A-Z]{2}[0-9]{6}$', text.upper()):
            # Check for common fake patterns
            if text.upper().startswith(('P', 'Z')):
                return True
            return True
        
        # Driving License: 2 letters + 2 digits + 11 digits
        if re.match(r'^[A-Z]{2}[0-9]{2}\s?[0-9]{11}$', text.upper()):
            # Check for common fake patterns
            if text.upper().startswith(('AA', 'BB', 'CC')):
                return False
            return True
        
        # GSTIN: 2 digits + 5 letters + 4 digits + 1 letter + 1 digit + 1 letter + 1 digit
        if re.match(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[0-9]{1}[A-Z]{1}[0-9]{1}$', text.upper()):
            return True
        
        return False
    
    @staticmethod
    def get_context_type(text, context_text=""):
        """
        Determine the type of Indian ID based on patterns.
        """
        text = text.strip().upper()
        
        # Aadhaar
        if re.match(r'^\d{12}$', text) or re.match(r'^\d{4}\s?\d{4}\s?\d{4}$', text):
            return 'aadhaar'
        
        # PAN
        if re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', text):
            return 'pan'
        
        # Voter ID
        if re.match(r'^[A-Z]{3}[0-9]{7}$', text):
            return 'voter_id'
        
        # Passport
        if re.match(r'^[A-Z][0-9]{7}$', text):
            return 'passport'
        
        # Driving License
        if re.match(r'^[A-Z]{2}[0-9]{2}\s?[0-9]{11}$', text):
            return 'driving_license'
        
        # GST
        if re.match(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[0-9]{1}[A-Z]{1}[0-9]{1}$', text):
            return 'gst'
        
        return None
    
    # ============ FALSE POSITIVE DETECTION ============
    
    @staticmethod
    def is_false_positive_name(text):
        """Check if it's a false positive name."""
        false_positives = {
            'django', 'flask', 'react', 'angular', 'vue', 'node', 'nodejs',
            'python', 'java', 'kotlin', 'swift', 'ruby', 'rails', 'golang',
            'jupyter', 'claude', 'gemini', 'copilot', 'chatgpt', 'openai',
            'tensorflow', 'pytorch', 'keras', 'sklearn', 'pandas', 'numpy',
            'docker', 'kubernetes', 'jenkins', 'ansible', 'terraform',
            'github', 'gitlab', 'bitbucket', 'jira', 'confluence',
            'aws', 'azure', 'linux', 'ubuntu', 'windows', 'macos',
            'fastapi', 'express', 'spring', 'laravel', 'wordpress',
            'excel', 'powerpoint', 'photoshop', 'figma', 'canva',
            'visa', 'mastercard', 'amex', 'paypal', 'google', 'apple',
            'microsoft', 'amazon', 'meta', 'twitter', 'facebook', 'instagram',
            'whatsapp', 'telegram', 'signal', 'wechat', 'line',
            # Common resume/document section headers and field labels —
            # frequently mislabeled as "name" by vision detection on resumes/forms
            'education', 'experience', 'skills', 'projects', 'summary',
            'objective', 'profile', 'contact', 'references', 'certifications',
            'languages', 'achievements', 'awards', 'publications', 'interests',
            'hobbies', 'declaration', 'signature', 'address', 'curriculum vitae',
            'resume', 'personal details', 'work experience', 'professional summary',
            'career objective', 'technical skills', 'soft skills', 'key skills',
            'employment history', 'academic background', 'extracurricular',
            'volunteer experience', 'internship', 'internships', 'training',
            'workshops', 'leadership', 'strengths', 'father name', "father's name",
            'mother name', "mother's name", 'date of birth', 'gender', 'nationality',
            'marital status', 'blood group', 'department', 'designation', 'company'
        }
        text_lower = text.lower().strip()
        if text_lower in false_positives:
            return True
        if len(text_lower) <= 2:
            return True
        if text.isupper() and len(text) <= 5:
            return True
        # Check for common fake names
        fake_names = ['test', 'demo', 'sample', 'user', 'admin', 'guest']
        if text_lower in fake_names:
            return True
        # Structural checks: a real person's name is short (typically 2-4 words),
        # has no digits/punctuation, and isn't a long descriptive phrase.
        if any(ch.isdigit() for ch in text):
            return True
        word_count = len(text.split())
        if word_count == 0 or word_count > 4:
            return True
        if any(p in text for p in (':', '@', '/', '|', '-', '_', '(', ')')):
            return True
        # Single-word "names" are almost always section headers/labels in
        # document context (real names on IDs/resumes are virtually always
        # first+last, i.e. 2+ words)
        if word_count == 1:
            return True

        # Heuristics above only catch malformed shapes (punctuation, length) —
        # they let through plausible-looking-but-wrong phrases like "Active
        # Bankruptcy" or "None Tax ID" that happen to be capitalized 2-3 word
        # strings. Use the spaCy NER model (already loaded for Presidio
        # elsewhere in this project) as a secondary signal — but only to
        # reject when it confidently tags the text as something OTHER than a
        # person (org, location, law, event, etc). Do NOT require a positive
        # PERSON tag to accept: spaCy's NER relies on sentence context, and a
        # bare isolated 2-3 word string (no surrounding sentence) very often
        # gets no entity tag at all even for genuine real names — requiring
        # PERSON confirmation here was rejecting valid names.
        NON_PERSON_LABELS = {'ORG', 'GPE', 'LOC', 'LAW', 'EVENT', 'FAC',
                              'PRODUCT', 'WORK_OF_ART', 'NORP', 'MONEY',
                              'PERCENT', 'DATE', 'TIME', 'CARDINAL', 'ORDINAL'}
        try:
            from agents.presidio_fast import get_presidio
            presidio = get_presidio()
            if presidio.nlp:
                doc = presidio.nlp(text)
                if any(ent.label_ in NON_PERSON_LABELS for ent in doc.ents):
                    return True
        except Exception as e:
            logger.warning(f"spaCy entity check unavailable, falling back to heuristics only: {e}")

        # Content check: real human names never contain common English
        # stopwords or document/legal/financial vocabulary. Scout sometimes
        # pattern-matches on "capitalized phrase" rather than "is this a
        # person" (e.g. "Active Bankruptcy", "Unauthorized Access") — these
        # pass the structural checks above but fail here.
        non_name_words = {
            'a', 'an', 'the', 'or', 'and', 'is', 'are', 'was', 'were', 'be',
            'of', 'to', 'in', 'on', 'at', 'by', 'for', 'with', 'as', 'this',
            'that', 'none', 'prior', 'active', 'inactive', 'status', 'tax',
            'id', 'ein', 'ssn', 'individual', 'filer', 'joint', 'addresses',
            'address', 'account', 'accounts', 'balance', 'total', 'amount',
            'date', 'dates', 'number', 'numbers', 'code', 'section', 'page',
            'document', 'report', 'statement', 'unauthorized', 'access',
            'distribution', 'strictly', 'prohibited', 'confidential',
            'bankruptcy', 'filing', 'filed', 'court', 'case', 'docket',
            'reference', 'summary', 'details', 'information', 'history',
            'record', 'records', 'type', 'category', 'description', 'notes',
            'comments', 'remarks', 'pending', 'approved', 'rejected',
            'verified', 'unverified', 'expired', 'valid', 'invalid',
            'current', 'previous', 'next', 'first', 'last', 'middle',
            'name', 'names', 'title', 'titled', 'subject', 'regarding',
            'pursuant', 'hereby', 'herein', 'thereof', 'whereas'
        }
        words_lower = [re.sub(r'[^a-z]', '', w.lower()) for w in text.split()]
        if any(w in non_name_words for w in words_lower if w):
            return True
        return False
    
    @staticmethod
    def is_fake_id(text):
        """Check if an ID is fake/common test value."""
        text = text.strip().upper()
        fake_ids = [
            '000000000000', '111111111111', '222222222222', '333333333333',
            '444444444444', '555555555555', '666666666666', '777777777777',
            '888888888888', '999999999999', '123456789012',
            'AAAAA1111A', 'BBBBB2222B', 'CCCCC3333C',
            'AAA0000000', 'BBB0000000', 'CCC0000000'
        ]
        if text in fake_ids:
            return True
        return False
