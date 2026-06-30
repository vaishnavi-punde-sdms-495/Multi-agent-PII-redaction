#!/usr/bin/env python3
"""
Create a realistic resume image for PII testing
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_resume_image(filename, img_size=(1200, 800)):
    """Create a realistic resume with PII."""
    img = Image.new('RGB', img_size, color='white')
    draw = ImageDraw.Draw(img)
    
    # Try to use a nice font
    try:
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-Regular.ttf"
        ]
        font = None
        for path in font_paths:
            if os.path.exists(path):
                font = ImageFont.truetype(path, 28)
                break
        if font is None:
            font = ImageFont.load_default()
    except:
        font = ImageFont.load_default()
    
    try:
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
    except:
        font_small = ImageFont.load_default()
    
    try:
        font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
    except:
        font_title = ImageFont.load_default()
    
    # Resume content with PII
    y = 40
    
    # Header
    draw.text((50, y), "RESUME", fill='black', font=font_title)
    y += 50
    
    # Personal Information (PII)
    draw.text((50, y), "Personal Information", fill='black', font=font)
    y += 35
    
    lines = [
        ("Name:", "Rahul Kumar Sharma"),
        ("Date of Birth:", "15/01/1990"),
        ("Email:", "rahul.sharma@email.com"),
        ("Phone:", "+91 98765 43210"),
        ("Aadhaar:", "1234 5678 9012"),
        ("PAN:", "ABCDE1234F"),
        ("Address:", "123, MG Road, Pune, Maharashtra 411001")
    ]
    
    for label, value in lines:
        draw.text((70, y), label, fill='black', font=font_small)
        draw.text((250, y), value, fill='black', font=font_small)
        y += 30
    
    y += 20
    
    # Education
    draw.text((50, y), "Education", fill='black', font=font)
    y += 35
    education = [
        ("B.Tech in Computer Science", "IIT Bombay, 2012-2016"),
        ("M.Tech in AI", "IIT Delhi, 2016-2018")
    ]
    for degree, uni in education:
        draw.text((70, y), degree, fill='black', font=font_small)
        y += 25
        draw.text((90, y), uni, fill='black', font=font_small)
        y += 30
    
    # Experience
    draw.text((50, y), "Work Experience", fill='black', font=font)
    y += 35
    experience = [
        ("Senior Software Engineer", "Google, 2018-2021"),
        ("AI Research Scientist", "Microsoft, 2021-Present")
    ]
    for role, company in experience:
        draw.text((70, y), role, fill='black', font=font_small)
        y += 25
        draw.text((90, y), company, fill='black', font=font_small)
        y += 30
    
    # Skills
    draw.text((50, y), "Skills", fill='black', font=font)
    y += 35
    draw.text((70, y), "Python, Java, C++, Machine Learning, Deep Learning", fill='black', font=font_small)
    y += 30
    
    # Certifications (with additional PII)
    draw.text((50, y), "Certifications", fill='black', font=font)
    y += 35
    draw.text((70, y), "Certified Python Developer - Certificate ID: PY-2020-12345", fill='black', font=font_small)
    
    # Save image
    img.save(filename)
    print(f"✅ Created: {filename}")
    print(f"   Size: {img_size[0]}x{img_size[1]}")
    print("")
    print("PII included in this resume:")
    print("  - Name: Rahul Kumar Sharma")
    print("  - DOB: 15/01/1990")
    print("  - Email: rahul.sharma@email.com")
    print("  - Phone: +91 98765 43210")
    print("  - Aadhaar: 1234 5678 9012")
    print("  - PAN: ABCDE1234F")
    print("  - Address: 123, MG Road, Pune")
    print("  - Certificate ID: PY-2020-12345")

# Create the resume
os.makedirs('test', exist_ok=True)
create_resume_image('test/resume_pii.jpg')

print("\n✅ Resume test image created: test/resume_pii.jpg")
print("\nUpload and test:")
print("curl -X POST http://localhost:8000/api/upload -F \"file=@test/resume_pii.jpg\" -H \"Content-Type: multipart/form-data\"")
