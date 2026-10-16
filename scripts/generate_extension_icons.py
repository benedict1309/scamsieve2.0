# File: scripts/generate_extension_icons.py
import os
from PIL import Image, ImageDraw, ImageFont

os.makedirs("extension/icons", exist_ok=True)

sizes = [16, 48, 128]

for size in sizes:
    img = Image.new("RGBA", (size, size), (218, 37, 28, 255))  # PTIT Red (#DA251C)
    draw = ImageDraw.Draw(img)
    
    # Vẽ vòng tròn hoặc bo góc
    margin = max(1, size // 10)
    draw.rounded_rectangle(
        [(margin, margin), (size - margin, size - margin)],
        radius=max(2, size // 6),
        outline=(255, 255, 255, 255),
        width=max(1, size // 16)
    )
    
    # Vẽ chữ "P" ở giữa
    try:
        font_size = int(size * 0.6)
        font = ImageFont.truetype("arial.ttf", font_size)
    except Exception:
        font = ImageFont.load_default()
        
    text = "P"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (size - text_width) // 2
    y = (size - text_height) // 2 - max(1, size // 16)
    
    draw.text((x, y), text, fill=(255, 255, 255, 255), font=font)
    img.save(f"extension/icons/icon{size}.png")
    print(f"Generated extension/icons/icon{size}.png")

