# Arachnida 🕷️🦂

A cybersecurity project for web scraping and image metadata analysis.

## Overview

This project contains two programs:

1. **Spider** - A web image scraper that extracts images from websites recursively
2. **Scorpion** - An image metadata parser that displays EXIF and other metadata

## Installation

```bash
# Clone/navigate to the repository
cd arachnida

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Spider 🕷️

The Spider program extracts all images from a website, optionally crawling recursively.

### Usage

```bash
python spider.py [-r] [-l LEVEL] [-p PATH] URL
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-r, --recursive` | Recursively download images | Disabled |
| `-l N, --level N` | Maximum recursion depth | 5 |
| `-p PATH, --path PATH` | Download directory | `./data/` |

### Supported Image Formats

- JPEG (`.jpg`, `.jpeg`)
- PNG (`.png`)
- GIF (`.gif`)
- BMP (`.bmp`)

### Examples

```bash
# Download images from a single page
python spider.py https://example.com

# Recursively download with default depth (5)
python spider.py -r https://example.com

# Recursive download with max depth of 3
python spider.py -r -l 3 https://example.com

# Save to custom directory
python spider.py -r -p ./images/ https://example.com

# Combine all options
python spider.py -r -l 2 -p ./downloads/ https://example.com
```

## Scorpion 🦂

The Scorpion program analyzes image files and displays their metadata.

### Usage

```bash
python scorpion.py [OPTIONS] FILE1 [FILE2 ...]
```

### Options

| Option | Description |
|--------|-------------|
| `-m TAG VALUE, --modify TAG VALUE` | Modify a metadata tag (JPEG only) |
| `-d, --delete` | Delete all EXIF metadata (JPEG only) |

### Displayed Information

- **Basic File Info**: Name, path, size, dates
- **Image Properties**: Format, dimensions, color mode
- **EXIF Data**: Camera info, settings, timestamps
- **GPS Information**: Coordinates, altitude (if present)
- **Format-specific metadata**: PNG chunks, GIF animation info

### Examples

```bash
# Analyze a single image
python scorpion.py photo.jpg

# Analyze multiple images
python scorpion.py photo1.jpg photo2.png image.gif

# Analyze all images in a directory (shell expansion)
python scorpion.py ./data/*.jpg

# Modify metadata (bonus, requires piexif)
python scorpion.py -m Artist "John Doe" photo.jpg

# Delete all EXIF metadata (bonus, requires piexif)
python scorpion.py -d photo.jpg
```

### Supported Metadata Tags for Modification

- `ImageDescription`
- `Artist`
- `Copyright`
- `Software`
- `DateTime`
- `UserComment`

## Project Structure

```
arachnida/
├── spider.py          # Web image scraper
├── scorpion.py        # Metadata analyzer
├── requirements.txt   # Python dependencies
├── README.md          # This file
└── data/              # Default download directory
```

## Dependencies

- **requests** - HTTP library for web requests
- **beautifulsoup4** - HTML parsing
- **Pillow** - Image processing and EXIF reading
- **piexif** (optional) - EXIF modification/deletion

## Security Considerations

- The spider respects the same-domain policy by default
- User-agent is set to mimic a browser
- Timeout is set to prevent hanging on slow connections
- Invalid or malicious URLs are handled gracefully

## Notes

- The spider only downloads images from the same domain as the starting URL
- Duplicate images are handled by appending numbers to filenames
- Binary content in metadata is displayed as `<binary data: N bytes>`
- GPS coordinates are converted to decimal format when possible

## License

Educational project - Cybersecurity Piscine

---

*Named after Arachnids: the class of chelicerate arthropods including spiders and scorpions* 🕸️
