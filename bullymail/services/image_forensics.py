import os
import io

class ImageForensicsEngine:
    """Safe Passive Image Forensics & Integrity Analysis Engine"""
    
    # Software identifiers commonly found in edited/tampered image metadata
    EDITING_SOFTWARE_KEYWORDS = [
        'adobe', 'photoshop', 'gimp', 'paint.net', 'lightroom', 'canva',
        'pixelmator', 'coreldraw', 'affinity', 'snapseed', 'facetune'
    ]

    def analyze_image(self, image_path_or_bytes, filename=""):
        """Performs passive forensics on an image (EXIF, metadata, dimensions, compression artifacts)."""
        findings = []
        threat_score = 0.0
        exif_data = {}
        dimensions = (0, 0)
        image_format = 'Unknown'
        
        try:
            from PIL import Image, ExifTags
            
            if isinstance(image_path_or_bytes, str) and os.path.exists(image_path_or_bytes):
                filename = filename or os.path.basename(image_path_or_bytes)
                img = Image.open(image_path_or_bytes)
            elif isinstance(image_path_or_bytes, bytes):
                filename = filename or "image_attachment"
                img = Image.open(io.BytesIO(image_path_or_bytes))
            else:
                return {
                    'filename': filename,
                    'risk_level': 'LOW',
                    'manipulation_verdict': 'Not an Image / Unreadable',
                    'findings': ['Could not decode image bytes']
                }

            dimensions = img.size
            image_format = img.format or 'Unknown'
            
            # 1. EXIF Metadata Inspection
            raw_exif = getattr(img, '_getexif', lambda: None)()
            if raw_exif:
                for tag_id, value in raw_exif.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    # Convert bytes to string if needed
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    exif_data[str(tag)] = str(value)
                    
            # 2. Check for Editing Software Signatures
            software_tag = exif_data.get('Software', '').lower()
            artist_tag = exif_data.get('Artist', '').lower()
            img_description = exif_data.get('ImageDescription', '').lower()
            
            matched_software = []
            for kw in self.EDITING_SOFTWARE_KEYWORDS:
                if kw in software_tag or kw in artist_tag or kw in img_description:
                    matched_software.append(kw)
                    
            if matched_software:
                findings.append(f"Image metadata indicates editing/processing software signature ({', '.join(matched_software)})")
                threat_score += 0.35

            # 3. Check for Stripped Metadata vs Original Camera EXIF
            has_camera_tags = any(k in exif_data for k in ['Make', 'Model', 'DateTimeOriginal', 'FocalLength', 'ISOSpeedRatings'])
            if not exif_data and image_format in ('JPEG', 'JPG'):
                findings.append("Standard EXIF metadata has been completely stripped (common in sanitized web or edited media)")
                threat_score += 0.15
            elif has_camera_tags:
                findings.append(f"Contains authentic camera metadata: {exif_data.get('Make', '')} {exif_data.get('Model', '')}")

            # 4. Error Level Analysis (ELA) / Compression Inconsistency Check (Simulation)
            if img.mode in ('RGB', 'RGBA') and image_format in ('JPEG', 'JPG'):
                # Check for uneven pixel variance across quadrants
                try:
                    gray = img.convert('L')
                    w, h = gray.size
                    if w > 20 and h > 20:
                        q1 = gray.crop((0, 0, w//2, h//2)).getextrema()
                        q2 = gray.crop((w//2, 0, w, h//2)).getextrema()
                        q3 = gray.crop((0, h//2, w//2, h)).getextrema()
                        q4 = gray.crop((w//2, h//2, w, h)).getextrema()
                        
                        ranges = [q[1] - q[0] for q in [q1, q2, q3, q4]]
                        diff = max(ranges) - min(ranges)
                        if diff > 180:
                            findings.append("Noticeable compression and dynamic range variance across regions (possible localized editing/splicing)")
                            threat_score += 0.30
                except Exception:
                    pass

        except Exception as e:
            findings.append(f"Image forensic inspection encountered note: {str(e)}")

        # Manipulation Classification (Objective Terminology)
        if threat_score >= 0.60:
            risk_level = 'HIGH'
            manipulation_verdict = 'High Manipulation Risk'
        elif threat_score >= 0.30:
            risk_level = 'MEDIUM'
            manipulation_verdict = 'Potentially Manipulated / Edited'
        else:
            risk_level = 'LOW'
            manipulation_verdict = 'Low Manipulation Risk'

        if not findings:
            findings.append("No abnormal metadata or compression anomalies detected.")

        return {
            'filename': filename,
            'format': image_format,
            'dimensions': f"{dimensions[0]}x{dimensions[1]}",
            'risk_level': risk_level,
            'manipulation_verdict': manipulation_verdict,
            'threat_score': round(min(threat_score, 1.0), 3),
            'findings': findings
        }

    def analyze_images(self, image_list):
        """Analyzes a collection of images."""
        results = []
        for item in image_list:
            if isinstance(item, str):
                res = self.analyze_image(item)
            elif isinstance(item, dict):
                res = self.analyze_image(item.get('content', b''), item.get('filename', ''))
            else:
                continue
            results.append(res)
            
        high_risk_count = sum(1 for r in results if r['risk_level'] == 'HIGH')
        medium_risk_count = sum(1 for r in results if r['risk_level'] == 'MEDIUM')
        
        if high_risk_count > 0:
            overall_risk = 'HIGH'
        elif medium_risk_count > 0:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
            
        return {
            'total_images': len(results),
            'high_risk_count': high_risk_count,
            'medium_risk_count': medium_risk_count,
            'risk_level': overall_risk,
            'images': results
        }
