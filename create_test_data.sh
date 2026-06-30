#!/bin/bash

echo "Creating test images with clear, easy-to-detect PII..."

# Create test folder
mkdir -p test

# 1. Simple PII document (clear text, easy to detect)
python3 << 'PY'
from PIL import Image, ImageDraw, ImageFont
import os

def create_test_image(filename, text_lines, img_size=(1200, 600)):
    img = Image.new('RGB', img_size, color='white')
    draw = ImageDraw.Draw(img)
    
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
    except:
        font = ImageFont.load_default()
    
    y = 50
    for text in text_lines:
        draw.text((50, y), text, fill='black', font=font)
        y += 50
    
    img.save(f'test/{filename}')
    print(f"✅ Created: test/{filename}")

# SIMPLE TEST IMAGE - Clear, easy to detect
create_test_image('simple_test.jpg', [
    "Name: Rahul Kumar",
    "DOB: 15/01/1990",
    "Aadhaar: 123456789012",
    "PAN: ABCDE1234F",
    "Phone: 9876543210",
    "Email: rahul.kumar@email.com"
])

# ID CARD with clear text
create_test_image('id_card_clear.jpg', [
    "DRIVING LICENSE",
    "",
    "Name: Amit Patel",
    "DOB: 20/05/1988",
    "License: DL-1234567890",
    "Aadhaar: 567890123456",
    "PAN: KLMNO7890P",
    "Phone: 9876543210",
    "Email: amit.patel@gmail.com"
])

# Simple text with PII
create_test_image('clear_pii.jpg', [
    "EMPLOYEE DETAILS",
    "",
    "Name: Priya Sharma",
    "DOB: 25/12/1985",
    "Aadhaar: 987654321098",
    "PAN: FGHIJ5432K",
    "Phone: 8765432109",
    "Email: priya.sharma@company.com"
])

print("\n✅ Test images created!")
print("Files:")
for f in os.listdir('test'):
    print(f"  - test/{f}")
PY

echo ""
echo "Test images ready!"
echo "Upload: test/simple_test.jpg"
