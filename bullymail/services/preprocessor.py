import re
import string

# Built-in English stop words fallback in case NLTK corpus is not downloaded
DEFAULT_STOP_WORDS = {
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', "you're", "you've",
    'he', 'him', 'his', 'himself', 'she', "she's", 'her', 'hers', 'its', 'itself',
    'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which', 'who', 'whom',
    'this', 'that', 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been',
    'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a', 'an',
    'the', 'and', 'but', 'if', 'or', 'because', 'as', 'until', 'while', 'of', 'at',
    'by', 'for', 'with', 'about', 'against', 'between', 'into', 'through', 'during',
    'before', 'after', 'above', 'below', 'to', 'from', 'up', 'down', 'in', 'out', 'on',
    'off', 'over', 'under', 'again', 'further', 'then', 'once', 'here', 'there', 'when',
    'where', 'why', 'how', 'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other',
    'some', 'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too',
    'very', 's', 't', 'can', 'will', 'just', 'don', "don't", 'should', "should've", 'now'
}

CONTRACTIONS = {
    "you're": "you are", "i'm": "i am", "he's": "he is", "she's": "she is",
    "it's": "it is", "that's": "that is", "what's": "what is", "where's": "where is",
    "there's": "there is", "who's": "who is", "can't": "cannot", "won't": "will not",
    "don't": "do not", "doesn't": "does not", "didn't": "did not", "isn't": "is not",
    "aren't": "are not", "wasn't": "was not", "weren't": "were not", "haven't": "have not",
    "hasn't": "has not", "hadn't": "had not", "wouldn't": "would not", "shouldn't": "should not",
    "couldn't": "could not", "mustn't": "must not", "let's": "let us", "you'll": "you will",
    "i'll": "i will", "he'll": "he will", "she'll": "she will", "they'll": "they will",
    "we'll": "we will", "you've": "you have", "i've": "i have", "we've": "we have",
    "they've": "they have", "you'd": "you would", "i'd": "i would"
}

LEETSPEAK_MAP = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's'
}

class TextPreprocessor:
    """Text Normalization & NLP Preprocessing Pipeline with Adversarial Awareness"""
    
    def __init__(self):
        try:
            import nltk
            from nltk.corpus import stopwords
            self.stop_words = set(stopwords.words('english'))
        except Exception:
            self.stop_words = DEFAULT_STOP_WORDS

    def expand_contractions(self, text):
        """Expands English contractions in text."""
        if not text:
            return ""
        pattern = re.compile(r'\b(' + '|'.join(re.escape(k) for k in CONTRACTIONS.keys()) + r')\b', re.IGNORECASE)
        def replace(match):
            key = match.group(0).lower()
            return CONTRACTIONS.get(key, match.group(0))
        return pattern.sub(replace, text)

    def normalize_adversarial_text(self, text):
        """
        Normalizes adversarial text variations (spaced letters, punctuation-separated
        letters, leetspeak substitutions) for internal detection and ML vectorization.
        Avoids globally stripping punctuation from non-obfuscated text.
        """
        if not text or not isinstance(text, str):
            return ""
            
        # 1. Expand contractions
        norm = self.expand_contractions(text)
        
        # 2. Lowercase
        norm = norm.lower()
        
        # 3. Collapse sequences of single characters separated by dots, dashes, underscores, etc.
        # e.g. "i.d.i.o.t" -> "idiot", "p-a-t-h-e-t-i-c" -> "pathetic"
        def _collapse_punct_spaced(match):
            return match.group(0).replace('.', '').replace('-', '').replace('_', '').replace('*', '').replace('/', '')
            
        norm = re.sub(r'\b(?:[a-z0-9][.\-_*\/~]){2,}[a-z0-9]\b', _collapse_punct_spaced, norm)
        
        # 4. Collapse spaced single-letter words (sequence of 3 or more single letters separated by space)
        # e.g. "i d i o t" -> "idiot", "m o r o n" -> "moron", "u s e l e s s" -> "useless"
        def _collapse_spaced_letters(match):
            return match.group(0).replace(' ', '')
            
        norm = re.sub(r'\b(?:[a-z]\s+){2,}[a-z]\b', _collapse_spaced_letters, norm)
        
        # 5. Targeted Leetspeak / Alphanumeric obfuscation
        # For tokens containing a mix of letters and digits/symbols (e.g. idi0t, l0ser, us3l3ss, 5tupid, 1diot, dumb4ss)
        def _decode_leetspeak_token(match):
            token = match.group(0)
            has_letters = any(c.isalpha() for c in token)
            has_leet_chars = any(c in LEETSPEAK_MAP for c in token)
            if has_letters and has_leet_chars:
                for k, v in LEETSPEAK_MAP.items():
                    token = token.replace(k, v)
            return token
            
        norm = re.sub(r'\b[a-z0-9@$]{3,}\b', _decode_leetspeak_token, norm)
        
        # 6. Normalize elongated characters (3+ repetitions -> 1)
        # e.g. "idiiioooot" -> "idiot", "looooser" -> "loser", "stuuuupid" -> "stupid"
        norm = re.sub(r'([a-z])\1{2,}', r'\1', norm)
        
        return norm

    def clean_text(self, text, remove_stopwords=True, min_length=2):
        """Cleans, normalizes, and removes stopwords from email text for feature extraction."""
        if not isinstance(text, str) or not text.strip():
            return ""
            
        # 1. Apply adversarial normalization (collapses spaced letters, decodes leetspeak, expands contractions)
        text = self.normalize_adversarial_text(text)
        
        # 2. Remove email headers, URLs, and noisy markup
        text = re.sub(r'http\S+|www\.\S+', ' ', text)
        text = re.sub(r'\S+@\S+', ' ', text)
        
        # 3. Remove special characters and digits while keeping spaces
        text = re.sub(r'[^a-z\s]', ' ', text)
        
        # 4. Tokenize
        tokens = text.split()
        
        # 5. Stopwords filter
        if remove_stopwords:
            tokens = [t for t in tokens if t not in self.stop_words and len(t) >= min_length]
        else:
            tokens = [t for t in tokens if len(t) >= min_length]
            
        return ' '.join(tokens)

    def extract_ngrams(self, text, n=2):
        """Extracts n-grams from text."""
        words = text.split()
        if len(words) < n:
            return []
        return [' '.join(words[i:i+n]) for i in range(len(words)-n+1)]
