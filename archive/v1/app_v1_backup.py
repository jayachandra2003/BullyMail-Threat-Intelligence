# BULLEMAIL V1 BACKUP - Preserved exact original working file as fallback.
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
import mysql.connector
import pandas as pd
import numpy as np
import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report
import joblib
import os
from datetime import datetime
import secrets
import imaplib
import email
from email.header import decode_header
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import openpyxl
from io import BytesIO
import time
import random
from faker import Faker
import ssl

# Download NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

# Initialize Faker for generating realistic data
fake = Faker()

# Configuration
class Config:
    DB_CONFIG = {
        'host': os.environ.get('DB_HOST', 'localhost'),
        'user': os.environ.get('DB_USER', 'root'),
        'password': os.environ.get('DB_PASSWORD', ''),
        'database': os.environ.get('DB_NAME', 'bullymail_db')
    }
    
    MODEL_PATH = 'saved_models'
    DATASET_PATH = 'datasets'

# Create directories
os.makedirs(Config.MODEL_PATH, exist_ok=True)
os.makedirs(Config.DATASET_PATH, exist_ok=True)

# Enhanced bullying phrases with academic context
BULLYING_PHRASES = [
    "you're worthless", "nobody likes you", "you should quit", "you're stupid",
    "can't do anything right", "useless student", "hopeless case", "waste of space",
    "you'll never succeed", "pathetic attempt", "embarrassing work", "complete failure",
    "don't belong here", "dumb idea", "ridiculous question", "everyone hates you",
    "you're a joke", "worthless contribution", "mental midget", "academic fraud",
    "incompetent fool", "should drop out", "stupid question", "waste of time",
    "failure student", "not cut out for", "terrible work", "awful performance",
    "disappointing effort", "below standards", "inadequate research", "poor quality",
    "your research is flawed", "methodology is incompetent", "analysis is worthless",
    "can't understand basics", "fundamentally wrong approach", "academically weak",
    "intellectually deficient", "conceptually bankrupt", "theoretically unsound",
    "empirically invalid", "statistically insignificant", "methodologically unsound",
    "as your advisor I'm disappointed", "you'll never get a recommendation",
    "your career is over", "no one will hire you", "reputation is ruined",
    "academic suicide", "professional embarrassment", "colleague laughing stock",
    "surprised you got this far", "expected better from you", "others are progressing faster",
    "not meeting potential", "consistent underperformance", "becoming a concern",
    "department is worried", "faculty has concerns", "standards are slipping"
]

NON_BULLYING_PHRASES = [
    "great work", "well done", "excellent job", "good effort", "nice progress",
    "impressive work", "keep trying", "you can do it", "proud of you", "excellent question",
    "valuable contribution", "smart approach", "creative solution", "helpful comment",
    "constructive feedback", "meaningful input", "important perspective", "useful insight",
    "outstanding performance", "remarkable progress", "exceptional quality", "brilliant idea",
    "innovative approach", "thorough research", "comprehensive analysis", "excellent points",
    "well articulated", "thoughtful response", "insightful comments", "professional work",
    "showing strong potential", "demonstrates good understanding", "clear improvement",
    "developing nicely", "mastering concepts", "grasping complex ideas", "analytical skills growing",
    "research potential evident", "academic promise shown", "intellectual curiosity appreciated",
    "consider exploring further", "potential for expansion", "opportunity for depth",
    "suggest additional reading", "recommend further analysis", "build upon this foundation",
    "develop this concept", "expand your methodology", "strengthen your argument",
    "looking forward to your progress", "excited to see development", "confident in your abilities",
    "trust your judgment", "value your perspective", "appreciate your dedication",
    "respect your approach", "admire your persistence", "commend your efforts"
]

NEUTRAL_PHRASES = [
    "meeting scheduled for", "deadline approaching for", "submission required by",
    "office hours at", "department announcement", "course materials posted",
    "assignment due", "exam schedule", "grade posted", "feedback available",
    "recommendation letter", "transcript request", "scholarship application",
    "research proposal", "thesis defense", "dissertation committee",
    "conference presentation", "journal submission", "publication opportunity"
]

class EmailIntegration:
    def __init__(self):
        self.config = {
            'imap_server': 'imap.gmail.com',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'email': '',
            'password': ''
        }
    
    def configure_email(self, email_address, app_password):
        self.config['email'] = email_address
        self.config['password'] = app_password
        return True
    
    def test_connection(self):
        try:
            server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'])
            server.starttls()
            server.login(self.config['email'], self.config['password'])
            server.quit()
            mail = imaplib.IMAP4_SSL(self.config['imap_server'])
            mail.login(self.config['email'], self.config['password'])
            mail.logout()
            return True, "Email configuration successful"
        except Exception as e:
            return False, f"Email configuration failed: {str(e)}"
    
    def connect_imap(self):
        try:
            mail = imaplib.IMAP4_SSL(self.config['imap_server'])
            mail.login(self.config['email'], self.config['password'])
            return mail
        except Exception as e:
            print(f"IMAP connection error: {e}")
            return None
    
    def fetch_emails(self, mailbox='INBOX', limit=5):
        if not self.config['email'] or not self.config['password']:
            return []
        mail = self.connect_imap()
        if not mail:
            return []
        try:
            mail.select(mailbox)
            result, data = mail.search(None, 'ALL')
            if result != 'OK':
                return []
            email_ids = data[0].split()
            emails = []
            for i, email_id in enumerate(email_ids[-limit:]):
                if i >= limit:
                    break
                try:
                    result, msg_data = mail.fetch(email_id, '(RFC822)')
                    if result == 'OK':
                        email_body = self.parse_email(msg_data[0][1])
                        if email_body['body']:
                            emails.append({
                                'id': email_id.decode(),
                                'subject': email_body['subject'],
                                'from': email_body['from'],
                                'body': email_body['body'],
                                'date': email_body['date']
                            })
                except Exception as e:
                    print(f"Error processing email {email_id}: {e}")
                    continue
            mail.close()
            mail.logout()
            return emails
        except Exception as e:
            print(f"Error fetching emails: {e}")
            try:
                mail.logout()
            except:
                pass
            return []
    
    def parse_email(self, raw_email):
        try:
            msg = email.message_from_bytes(raw_email)
            subject = ""
            subject_header = msg["Subject"]
            if subject_header:
                decoded_parts = decode_header(subject_header)
                for part, encoding in decoded_parts:
                    if isinstance(part, bytes):
                        subject += part.decode(encoding or 'utf-8', errors='ignore')
                    else:
                        subject += str(part)
            else:
                subject = "No Subject"
            
            from_header = msg.get("From", "Unknown Sender")
            date_header = msg.get("Date", "Unknown Date")
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = payload.decode('utf-8', errors='ignore')
                                break
                        except:
                            try:
                                body = part.get_payload(decode=False)
                                break
                            except:
                                continue
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                    else:
                        body = msg.get_payload(decode=False)
                except:
                    body = msg.get_payload(decode=False)
            
            if body:
                body = ' '.join(body.splitlines())
                body = body.strip()
            
            return {'subject': subject, 'from': from_header, 'body': body or 'No content', 'date': date_header}
        except Exception as e:
            print(f"Error parsing email: {e}")
            return {'subject': 'Error', 'from': 'Error', 'body': 'Error parsing email', 'date': 'Error'}
    
    def send_email(self, to_email, subject, body):
        if not self.config['email'] or not self.config['password']:
            return False, "Email not configured"
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            context = ssl.create_default_context()
            server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'])
            server.starttls(context=context)
            server.login(self.config['email'], self.config['password'])
            text = msg.as_string()
            server.sendmail(self.config['email'], to_email, text)
            server.quit()
            return True, "Email sent successfully"
        except Exception as e:
            return False, f"Failed to send email: {str(e)}"
    
    def get_email_config_instructions(self):
        return {
            'gmail_instructions': [
                "1. Enable 2-Factor Authentication in your Google Account",
                "2. Go to Google Account Settings -> Security -> 2-Step Verification",
                "3. Generate an App Password (Select 'Mail')",
                "4. Use the app password in configuration"
            ],
            'outlook_instructions': [
                "1. Ensure app password or secure access is configured"
            ]
        }

class EmailDatasetGenerator:
    def __init__(self):
        self.fake = Faker()
        self.university_domains = [
            "@harvard.edu", "@stanford.edu", "@mit.edu", "@berkeley.edu",
            "@oxford.ac.uk", "@cambridge.ac.uk", "@yale.edu", "@princeton.edu"
        ]
        self.academic_roles = ["Professor", "Associate Professor", "Assistant Professor", "Lecturer", "Advisor"]
        self.course_codes = ["CS101", "MATH201", "PHYS301", "BIO401", "CHEM202"]
        
    def generate_bullying_email(self):
        templates = [
            "I've reviewed your {assignment} and I must say this is completely unacceptable. {bullying_phrase} Your work demonstrates a fundamental lack of understanding.",
            "Regarding your recent {submission}, the quality is far below what we expect from students. {bullying_phrase} Reconsider your position in this program.",
            "Your performance in {course} has been consistently disappointing. {bullying_phrase}"
        ]
        template = random.choice(templates)
        bullying_phrase = random.choice(BULLYING_PHRASES)
        return template.format(
            assignment="assignment", submission="research submission",
            course=random.choice(self.course_codes), bullying_phrase=bullying_phrase
        )
    
    def generate_non_bullying_email(self):
        templates = [
            "I wanted to commend you on your excellent work on the {assignment}. {positive_phrase} Keep it up.",
            "Thank you for your submission. {positive_phrase} Great progress.",
            "Your progress in {course} has been impressive. {positive_phrase}"
        ]
        template = random.choice(templates)
        positive_phrase = random.choice(NON_BULLYING_PHRASES)
        return template.format(
            assignment="assignment", course=random.choice(self.course_codes), positive_phrase=positive_phrase
        )
    
    def generate_neutral_email(self):
        templates = [
            "This is a reminder that the deadline for {course} assignment is approaching.",
            "Department announcement: meeting scheduled for tomorrow.",
            "Office hours for {course} have been updated."
        ]
        return random.choice(templates).format(course=random.choice(self.course_codes))
    
    def generate_sender_info(self, is_bullying=False):
        role = random.choice(self.academic_roles)
        first_name = self.fake.first_name()
        last_name = self.fake.last_name()
        domain = random.choice(self.university_domains)
        return {'name': f"{role} {first_name} {last_name}", 'email': f"{first_name.lower()}.{last_name.lower()}{domain}"}

class EmailAnalyzer:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=2000, stop_words='english', ngram_range=(1, 2))
        self.model = None
        self.model_type = None
        self.model_metrics = {}
        self.stop_words = set(stopwords.words('english'))
        self.dataset_generator = EmailDatasetGenerator()
        
    def preprocess_text(self, text):
        if not isinstance(text, str):
            return ""
        text = text.lower()
        text = re.sub(r'[^a-zA-Z\s]', '', text)
        text = ' '.join(text.split())
        tokens = word_tokenize(text)
        tokens = [t for t in tokens if t not in self.stop_words and len(t) > 2]
        return ' '.join(tokens)
    
    def rule_based_check(self, text):
        if not isinstance(text, str):
            return [], 0
        text_lower = text.lower()
        bullying_matches = [phrase for phrase in BULLYING_PHRASES if phrase in text_lower]
        bullying_score = len(bullying_matches) / len(BULLYING_PHRASES) if BULLYING_PHRASES else 0
        return bullying_matches, bullying_score
    
    def generate_large_dataset(self, num_samples=1000):
        emails, labels, senders, subjects, timestamps = [], [], [], [], []
        b_count = int(num_samples * 0.4)
        nb_count = int(num_samples * 0.4)
        n_count = num_samples - b_count - nb_count
        for _ in range(b_count):
            emails.append(self.dataset_generator.generate_bullying_email())
            labels.append(1)
            senders.append(self.dataset_generator.generate_sender_info(True)['name'])
            subjects.append("Academic Notice")
            timestamps.append(fake.date_time_between(start_date='-1y', end_date='now'))
        for _ in range(nb_count):
            emails.append(self.dataset_generator.generate_non_bullying_email())
            labels.append(0)
            senders.append(self.dataset_generator.generate_sender_info(False)['name'])
            subjects.append("Course Feedback")
            timestamps.append(fake.date_time_between(start_date='-1y', end_date='now'))
        for _ in range(n_count):
            emails.append(self.dataset_generator.generate_neutral_email())
            labels.append(0)
            senders.append(self.dataset_generator.generate_sender_info(False)['name'])
            subjects.append("Department Reminder")
            timestamps.append(fake.date_time_between(start_date='-1y', end_date='now'))
        return emails, labels, senders, subjects, timestamps
    
    def save_large_dataset_to_excel(self, num_samples=1000, filename='large_email_dataset.xlsx'):
        emails, labels, senders, subjects, timestamps = self.generate_large_dataset(num_samples)
        df = pd.DataFrame({
            'email_id': range(1, len(emails) + 1), 'timestamp': timestamps,
            'sender': senders, 'subject': subjects, 'email_content': emails, 'label': labels
        })
        filepath = os.path.join(Config.DATASET_PATH, filename)
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Email Dataset', index=False)
        return {
            'filepath': filepath, 'total_samples': len(emails),
            'bullying_samples': sum(labels), 'non_bullying_samples': len(labels) - sum(labels),
            'file_size': f"{os.path.getsize(filepath) / (1024*1024):.2f} MB"
        }
    
    def train_model(self, model_type='logistic', save_model=True, training_samples=1000):
        emails, labels, _, _, _ = self.generate_large_dataset(training_samples)
        processed = [self.preprocess_text(e) for e in emails]
        X_train, X_test, y_train, y_test = train_test_split(processed, labels, test_size=0.3, random_state=42)
        X_train_tfidf = self.vectorizer.fit_transform(X_train)
        X_test_tfidf = self.vectorizer.transform(X_test)
        if model_type == 'svm':
            self.model = SVC(kernel='linear', probability=True, random_state=42)
            self.model_type = 'SVM'
        else:
            self.model = LogisticRegression(random_state=42, max_iter=1000)
            self.model_type = 'Logistic Regression'
        self.model.fit(X_train_tfidf, y_train)
        y_pred = self.model.predict(X_test_tfidf)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        self.model_metrics = {
            'precision': round(precision, 3), 'recall': round(recall, 3), 'f1_score': round(f1, 3),
            'model_type': self.model_type, 'training_samples': len(X_train),
            'test_samples': len(X_test), 'accuracy': round((y_pred == y_test).mean(), 3)
        }
        if save_model:
            self.save_model()
        return self.model_metrics
    
    def save_model(self):
        if self.model is None:
            return False
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = os.path.join(Config.MODEL_PATH, f"{self.model_type}_{timestamp}.joblib")
        vec_path = os.path.join(Config.MODEL_PATH, f"vectorizer_{timestamp}.joblib")
        joblib.dump(self.model, model_path)
        joblib.dump(self.vectorizer, vec_path)
        joblib.dump(self.model, os.path.join(Config.MODEL_PATH, 'latest_model.joblib'))
        joblib.dump(self.vectorizer, os.path.join(Config.MODEL_PATH, 'latest_vectorizer.joblib'))
        return True
    
    def load_model(self, model_type='latest'):
        try:
            m_path = os.path.join(Config.MODEL_PATH, 'latest_model.joblib')
            v_path = os.path.join(Config.MODEL_PATH, 'latest_vectorizer.joblib')
            if os.path.exists(m_path) and os.path.exists(v_path):
                self.model = joblib.load(m_path)
                self.vectorizer = joblib.load(v_path)
                self.model_type = 'Latest'
                return True
        except Exception as e:
            print(f"Error loading model: {e}")
        return False
    
    def predict_bullying(self, email_text):
        if self.model is None and not self.load_model():
            return {"error": "Model not trained."}
        rule_matches, rule_score = self.rule_based_check(email_text)
        processed_text = self.preprocess_text(email_text)
        text_tfidf = self.vectorizer.transform([processed_text])
        ml_prediction = self.model.predict(text_tfidf)[0]
        ml_probability = self.model.predict_proba(text_tfidf)[0][1]
        combined_score = (rule_score * 0.4) + (ml_probability * 0.6)
        return {
            'is_bullying': bool(combined_score > 0.5), 'confidence': round(combined_score, 3),
            'rule_based_matches': rule_matches, 'rule_based_score': round(rule_score, 3),
            'ml_prediction': bool(ml_prediction), 'ml_confidence': round(ml_probability, 3),
            'model_used': self.model_type, 'combined_score': round(combined_score, 3)
        }

analyzer = EmailAnalyzer()
email_integration = EmailIntegration()

def get_db_connection():
    try:
        return mysql.connector.connect(**Config.DB_CONFIG)
    except Exception as e:
        print(f"Database error: {e}")
        return None

def init_database():
    try:
        conn = get_db_connection()
        if not conn:
            return False
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL, role VARCHAR(20) DEFAULT 'moderator',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        default_admin_pass = os.environ.get('ADMIN_PASSWORD', 'legacy_admin_placeholder')
        cursor.execute("INSERT IGNORE INTO users (username, password, role) VALUES (%s, %s, %s)", ('admin', default_admin_pass, 'admin'))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        expected_pass = os.environ.get('ADMIN_PASSWORD', 'legacy_admin_placeholder')
        if request.form['username'] == 'admin' and request.form['password'] == expected_pass:
            session['user_id'] = 1
            session['username'] = 'admin'
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
