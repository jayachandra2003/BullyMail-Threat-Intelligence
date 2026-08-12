import os
import random
import pandas as pd
from datetime import datetime
from faker import Faker
from flask import Blueprint, request, jsonify, session, send_file
from werkzeug.utils import secure_filename
from ..config import Config
from ..database.connection import fetch_all, execute_query
from ..services.bullying_detector import BULLYING_PHRASES
from ..services.preprocessor import TextPreprocessor

datasets_bp = Blueprint('datasets', __name__)
fake = Faker()
preprocessor = TextPreprocessor()

# -----------------------------------------------------------------------------
# 1. EXPANDED DIVERSE SYNTHETIC GENERATION TEMPLATES (25+ PER CLASS)
# -----------------------------------------------------------------------------

BULLYING_TEMPLATES = [
    # Direct Insult & Degradation
    "You are an absolute {phrase} and everyone in {course} is aware of it.",
    "Stop sending these ridiculous emails, you {phrase}. We do not care.",
    "Everyone in our {course} study group agrees that you are a {phrase}.",
    "You are a pathetic excuse for a student in {course}. Stop embarrassing yourself.",
    "You are completely moronic. Delete your {item} before you ruin the whole project.",
    
    # Academic Invalidation & Humiliation
    "I reviewed your {item} and it is completely unacceptable. {phrase} Your work is a total disaster.",
    "Regarding your recent {item}, the quality is far below department standards. {phrase} You should reconsider your academic path.",
    "Your performance in {course} is a complete embarrassment. {phrase} Other students are far ahead.",
    "Your {item} submission is utterly worthless. {phrase} You demonstrate zero understanding of {course}.",
    "Stop embarrassing yourself in {course} with this pathetic {item}. It is complete garbage.",
    "Your attempt at the {item} was so pathetic that even first-year students could do better.",
    "You cannot do anything right in {course}. Your {item} is an absolute joke.",
    "Everyone knows you are too stupid to pass {course}. Just quit already.",
    "You are a clueless fraud pretending to understand {course}. Delete your {item} immediately.",
    
    # Peer Harassment & Social Exclusion
    "Nobody on our {course} team wants to work with you because you are completely useless.",
    "Why are you even enrolled in {course}? You should drop out and stop wasting faculty time.",
    "Get lost from this project. Your contribution to the {item} was worthless and everyone hates working with you.",
    "You do not belong in this department. Give up on {course} before you fail completely.",
    "Your presence in the {course} research group is deeply resented because you are completely useless.",
    "Nobody wants you in {course}. Why do you keep showing up to lab sessions?",
    
    # Hostile Silencing, Intimidation & Threats
    "Shut your mouth during {course} seminars. Nobody wants to hear your idiotic opinions.",
    "If you dare show up to the {course} {item} presentation, I will make sure you suffer.",
    "Watch your back after class today. You will pay for ruining our {item} grade.",
    "I will make sure you are dismissed from the {course} lab if you ever speak up again.",
    "You better watch out. I will destroy your reputation across the entire department.",
    "I am going to make sure the review committee rejects your {item} and kicks you out."
]

CLEAN_NEUTRAL_TEMPLATES = [
    # Academic Logistics & Announcements
    "Department Announcement: The upcoming seminar on {course} research will take place in Hall B.",
    "Reminder: The submission deadline for the {course} {item} is scheduled for next Monday at 5 PM.",
    "Office hours for {course} have been updated. Please consult the course syllabus for details.",
    "Course registration for the Spring semester will open next week for all {course} students.",
    "The lecture slides and supplementary reading for {course} have been posted on the portal.",
    "Campus IT will perform scheduled server maintenance tonight; access to {course} materials will pause.",
    "The library has added new reference textbooks for {course} on reserve at the circulation desk.",
    "A review session for the upcoming {course} midterm will be held this Wednesday at 4 PM.",
    "The deadline for adding or dropping {course} without penalty is the end of this week.",
    "Guest lecture: Dr. Smith will present recent advances in {course} during tomorrow's class.",
    
    # Assignment Instructions & Lab Protocols
    "Please ensure your {item} for {course} includes unit test results and references in IEEE format.",
    "Lab safety protocols for {course} must be reviewed prior to beginning the {item} experiment.",
    "All project source code for {course} must be committed to the department version control system.",
    "The dataset for the upcoming {course} {item} is now available in the shared repository.",
    "Please submit your team preferences for the {course} capstone milestone before Friday.",
    "Please return all hardware kits borrowed for the {course} {item} to the department office.",
    "Please verify that your student ID is listed on the cover sheet of your {course} {item}.",
    "The grading rubric for the {course} {item} has been uploaded to the course website.",
    "Graduate teaching assistants for {course} will hold extra office hours in Room 302.",
    "We will conduct a code walkthrough and Q&A session during the next {course} laboratory.",
    
    # Constructive Technical Feedback & Admin Policy
    "Your {item} submission is incomplete and does not satisfy the criteria for section 3. Please revise.",
    "The algorithm in Section 2 of your {item} exhibits quadratic time complexity. Consider optimizing.",
    "Your attendance in {course} is below the 75% threshold. Please schedule a meeting with your advisor.",
    "Please review Chapter 4 of the {course} textbook before attempting the {item} exercises.",
    "The midterm exam for {course} has been graded and results are visible in the student dashboard."
]

COMMENDATION_POSITIVE_TEMPLATES = [
    # Praise, Recognition & Encouragement
    "I wanted to commend you on your excellent work on the {item}. Your analysis in {course} was thorough.",
    "Congratulations on your outstanding performance on the {course} {item}. Keep up the high standard.",
    "Thank you for submitting your {item}. The methodology looks solid and shows great promise for {course}.",
    "Great progress on the {item}. Looking forward to discussing the next steps during {course} office hours.",
    "Your recent performance in {course} has been outstanding. Keep up the dedication and curiosity.",
    "Your presentation on the {item} was well structured and demonstrated clear technical mastery.",
    "The faculty committee was very impressed with your {item} submission for {course}.",
    "Excellent work optimizing the algorithms in your {item}. Your solution is elegant and efficient.",
    "Thank you for your active participation and valuable contributions during {course} discussions.",
    "Your {item} draft is one of the strongest in the cohort this semester. Outstanding effort.",
    "I appreciate your leadership and collaboration in guiding your team through the {course} project.",
    "The thoroughness of your literature review in the {item} reflects impressive academic rigor.",
    "Congratulations on achieving full marks on the {course} practical examination.",
    "Your insights during today's {course} seminar added great depth to the discussion.",
    "We are pleased to inform you that your {item} has been nominated for the department research award.",
    "Thank you for mentoring fellow students during the {course} laboratory sessions.",
    "Your code documentation and test coverage on the {item} are exemplary. Great craftsmanship.",
    "The revisions you made to the {item} addressed all reviewer comments effectively.",
    "Your proactive communication and timely delivery on the {course} milestone are much appreciated.",
    "Fantastic presentation today. You explained complex {course} concepts with exceptional clarity.",
    "Your analytical rigor in evaluating the experimental data for {course} is commendable.",
    "We are excited to see your research on the {item} progressing toward publication.",
    "Thank you for volunteering to organize the student workshop for {course}.",
    "Your continuous improvement and resilience throughout {course} have been truly inspiring.",
    "Well done on completing the {course} capstone milestone ahead of schedule."
]

COURSES = [
    "CS101", "MATH201", "PHYS301", "BIO401", "ENG102", "ECON301",
    "SOC101", "CHEM201", "DATA301", "STAT202", "ROBOT401", "NEURO501"
]

ITEMS = [
    "assignment", "research paper", "thesis chapter", "proposal", "lab report",
    "project milestone", "codebase", "case study", "capstone draft", "technical essay",
    "seminar presentation", "literature review"
]

def generate_synthetic_samples(num_samples=2000):
    """
    Generates diverse, deduplicated synthetic academic email samples across 25+ templates per class.
    Applies exact and normalized duplicate suppression to guarantee high lexical diversity.
    """
    emails = []
    labels = []
    
    seen_exact = set()
    seen_normalized = set()
    duplicates_removed = 0
    
    bullying_target = int(num_samples * 0.4)
    positive_target = int(num_samples * 0.3)
    neutral_target = num_samples - bullying_target - positive_target
    
    # 1. Bullying Generation with Deduplication
    b_count = 0
    max_attempts = bullying_target * 5
    attempts = 0
    while b_count < bullying_target and attempts < max_attempts:
        attempts += 1
        tmpl = random.choice(BULLYING_TEMPLATES)
        txt = tmpl.format(
            item=random.choice(ITEMS),
            phrase=random.choice(BULLYING_PHRASES),
            course=random.choice(COURSES)
        )
        exact_key = txt.strip().lower()
        norm_key = preprocessor.clean_text(txt)
        
        if exact_key in seen_exact or (norm_key and norm_key in seen_normalized):
            duplicates_removed += 1
            continue
            
        seen_exact.add(exact_key)
        if norm_key:
            seen_normalized.add(norm_key)
        emails.append(txt)
        labels.append(1)
        b_count += 1
        
    # 2. Commendation / Positive Generation with Deduplication
    p_count = 0
    max_attempts = positive_target * 5
    attempts = 0
    while p_count < positive_target and attempts < max_attempts:
        attempts += 1
        tmpl = random.choice(COMMENDATION_POSITIVE_TEMPLATES)
        txt = tmpl.format(
            item=random.choice(ITEMS),
            course=random.choice(COURSES)
        )
        exact_key = txt.strip().lower()
        norm_key = preprocessor.clean_text(txt)
        
        if exact_key in seen_exact or (norm_key and norm_key in seen_normalized):
            duplicates_removed += 1
            continue
            
        seen_exact.add(exact_key)
        if norm_key:
            seen_normalized.add(norm_key)
        emails.append(txt)
        labels.append(0)
        p_count += 1
        
    # 3. Clean / Neutral Generation with Deduplication
    n_count = 0
    max_attempts = neutral_target * 5
    attempts = 0
    while n_count < neutral_target and attempts < max_attempts:
        attempts += 1
        tmpl = random.choice(CLEAN_NEUTRAL_TEMPLATES)
        txt = tmpl.format(
            item=random.choice(ITEMS),
            course=random.choice(COURSES)
        )
        exact_key = txt.strip().lower()
        norm_key = preprocessor.clean_text(txt)
        
        if exact_key in seen_exact or (norm_key and norm_key in seen_normalized):
            duplicates_removed += 1
            continue
            
        seen_exact.add(exact_key)
        if norm_key:
            seen_normalized.add(norm_key)
        emails.append(txt)
        labels.append(0)
        n_count += 1
        
    telemetry = {
        'requested_rows': num_samples,
        'generated_candidates': len(emails) + duplicates_removed,
        'unique_rows': len(emails),
        'duplicates_removed': duplicates_removed,
        'final_rows': len(emails),
        'bullying_samples': sum(labels),
        'non_bullying_samples': len(labels) - sum(labels)
    }
    
    return emails, labels, telemetry

@datasets_bp.route('/api/generate-dataset', methods=['POST'])
@datasets_bp.route('/api/generate-large-dataset', methods=['POST'])
def generate_dataset_route():
    """Generates diverse, deduplicated synthetic multi-sheet Excel datasets."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.get_json() or {}
    try:
        num_samples = min(max(int(data.get('num_samples', 2000)), 10), 25000)
    except (ValueError, TypeError):
        num_samples = 2000
        
    filename = 'large_email_dataset.xlsx' if num_samples >= 5000 else 'email_dataset.xlsx'
    
    try:
        emails, labels, telemetry = generate_synthetic_samples(num_samples)
        
        df = pd.DataFrame({
            'email_id': range(1, len(emails) + 1),
            'timestamp': [fake.date_time_between(start_date='-1y', end_date='now') for _ in range(len(emails))],
            'sender': [fake.name() for _ in range(len(emails))],
            'subject': ['Academic Communication' for _ in range(len(emails))],
            'email_content': emails,
            'label': labels,
            'label_description': ['Bullying' if l == 1 else 'Not Bullying' for l in labels]
        })
        
        filepath = os.path.join(Config.DATASET_PATH, filename)
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Email Dataset', index=False)
            
        file_size_mb = f"{os.path.getsize(filepath) / (1024 * 1024):.2f} MB"
        b_samples = sum(labels)
        nb_samples = len(labels) - b_samples
        
        # Save to DB
        execute_query('''
            INSERT INTO dataset_history (filename, total_samples, bullying_samples, non_bullying_samples, file_size)
            VALUES (%s, %s, %s, %s, %s)
        ''', (filename, len(emails), b_samples, nb_samples, file_size_mb))
        
        dataset_info = {
            'filename': filename,
            'total_samples': len(emails),
            'bullying_samples': b_samples,
            'non_bullying_samples': nb_samples,
            'file_size': file_size_mb,
            'duplicates_removed': telemetry['duplicates_removed'],
            'diversity_templates_per_class': '25+'
        }
        
        return jsonify({
            'success': True,
            'message': f"Dataset with {len(emails)} unique samples generated successfully.",
            'dataset_info': dataset_info
        })
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to generate synthetic dataset.'}), 500

@datasets_bp.route('/api/download-dataset/<filename>')
def download_dataset(filename):
    """Safely serves generated datasets for download with path traversal defense."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    safe_fn = secure_filename(filename)
    filepath = os.path.abspath(os.path.join(Config.DATASET_PATH, safe_fn))
    dataset_dir = os.path.abspath(Config.DATASET_PATH)
    
    # Path traversal check
    if not filepath.startswith(dataset_dir) or not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'File not found'}), 404
        
    return send_file(filepath, as_attachment=True, download_name=safe_fn)

@datasets_bp.route('/api/available-datasets')
def available_datasets():
    """Lists all available dataset files."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    datasets = []
    try:
        if os.path.exists(Config.DATASET_PATH):
            for fn in os.listdir(Config.DATASET_PATH):
                if fn.endswith(('.xlsx', '.csv')):
                    fp = os.path.join(Config.DATASET_PATH, fn)
                    size_mb = f"{os.path.getsize(fp) / (1024*1024):.2f} MB"
                    ctime = datetime.fromtimestamp(os.path.getctime(fp))
                    datasets.append({
                        'filename': fn,
                        'file_size': size_mb,
                        'created_at': ctime.strftime('%Y-%m-%d %H:%M:%S'),
                        'download_url': f"/api/download-dataset/{fn}"
                    })
        return jsonify({'success': True, 'datasets': datasets})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to list available datasets.'}), 500

@datasets_bp.route('/api/dataset-history')
def dataset_history():
    """Fetches generation log history."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    try:
        history = fetch_all("SELECT * FROM dataset_history ORDER BY created_at DESC LIMIT 10")
        return jsonify({'success': True, 'history': history})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to retrieve dataset generation logs.'}), 500
