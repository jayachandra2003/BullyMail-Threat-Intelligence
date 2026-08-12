import pytest
import io
from bullymail.services.image_forensics import ImageForensicsEngine

def test_image_forensics_safe():
    engine = ImageForensicsEngine()
    try:
        from PIL import Image
        img = Image.new('RGB', (100, 100), color='blue')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        
        res = engine.analyze_image(img_bytes.getvalue(), filename="chart.png")
        assert res['risk_level'] == 'LOW'
        assert 'Low Manipulation Risk' in res['manipulation_verdict']
    except ImportError:
        pass
