@echo off
title BullyMail - Install Dependencies

cd /d "%~dp0"

if not exist venv (
    echo.
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate

echo.
echo ============================================
echo Installing BullyMail V2 Dependencies...
echo ============================================
echo.

pip install -r requirements.txt

echo.
echo ============================================
echo Downloading Required NLTK Corpora...
echo ============================================
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"

echo.
echo Dependencies installed successfully.
pause