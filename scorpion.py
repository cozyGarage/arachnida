#!/usr/bin/env python3
"""
Scorpion - Image metadata parser
Parses and displays EXIF and other metadata from image files.

Usage: python scorpion.py FILE1 [FILE2 ...]
"""

import argparse
import os
import sys
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import struct


# Supported image extensions
SUPPORTED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp'}


def get_extension(filepath: str) -> str:
    """Get lowercase file extension."""
    return os.path.splitext(filepath)[1].lower()


def is_supported_file(filepath: str) -> bool:
    """Check if file has a supported extension."""
    return get_extension(filepath) in SUPPORTED_EXTENSIONS


def format_value(value) -> str:
    """Format metadata value for display."""
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8', errors='replace')
        except:
            return f"<binary data: {len(value)} bytes>"
    elif isinstance(value, tuple):
        return ', '.join(str(v) for v in value)
    elif isinstance(value, dict):
        return str(value)
    return str(value)


def decode_gps_info(gps_info: dict) -> dict:
    """Decode GPS information from EXIF."""
    gps_data = {}
    
    for key, val in gps_info.items():
        tag = GPSTAGS.get(key, key)
        gps_data[tag] = val
    
    # Try to convert to decimal coordinates
    try:
        if 'GPSLatitude' in gps_data and 'GPSLatitudeRef' in gps_data:
            lat = gps_data['GPSLatitude']
            lat_ref = gps_data['GPSLatitudeRef']
            lat_decimal = lat[0] + lat[1] / 60 + lat[2] / 3600
            if lat_ref == 'S':
                lat_decimal = -lat_decimal
            gps_data['Latitude (Decimal)'] = f"{lat_decimal:.6f}"
        
        if 'GPSLongitude' in gps_data and 'GPSLongitudeRef' in gps_data:
            lon = gps_data['GPSLongitude']
            lon_ref = gps_data['GPSLongitudeRef']
            lon_decimal = lon[0] + lon[1] / 60 + lon[2] / 3600
            if lon_ref == 'W':
                lon_decimal = -lon_decimal
            gps_data['Longitude (Decimal)'] = f"{lon_decimal:.6f}"
    except (TypeError, IndexError, KeyError):
        pass
    
    return gps_data


def get_basic_info(filepath: str) -> dict:
    """Get basic file information."""
    info = {}
    
    try:
        stat = os.stat(filepath)
        info['File Name'] = os.path.basename(filepath)
        info['File Path'] = os.path.abspath(filepath)
        info['File Size'] = f"{stat.st_size:,} bytes ({stat.st_size / 1024:.2f} KB)"
        info['Created'] = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        info['Modified'] = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        info['Accessed'] = datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
    except OSError as e:
        info['Error'] = str(e)
    
    return info


def get_image_info(filepath: str) -> dict:
    """Get image-specific information."""
    info = {}
    
    try:
        with Image.open(filepath) as img:
            info['Format'] = img.format
            info['Mode'] = img.mode
            info['Width'] = f"{img.width} px"
            info['Height'] = f"{img.height} px"
            info['Resolution'] = f"{img.width} x {img.height}"
            
            if hasattr(img, 'info'):
                # Get additional format-specific info
                for key, value in img.info.items():
                    if key not in ('exif', 'icc_profile') and not isinstance(value, bytes):
                        info[f"Info: {key}"] = format_value(value)
    except Exception as e:
        info['Error'] = str(e)
    
    return info


def get_exif_data(filepath: str) -> dict:
    """Extract EXIF data from image."""
    exif_data = {}
    gps_data = {}
    
    try:
        with Image.open(filepath) as img:
            exif = img._getexif()
            
            if exif is None:
                return exif_data, gps_data
            
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                
                # Handle GPS info separately
                if tag == 'GPSInfo':
                    gps_data = decode_gps_info(value)
                elif tag == 'MakerNote':
                    exif_data[tag] = "<Manufacturer-specific data>"
                elif tag == 'UserComment':
                    if isinstance(value, bytes):
                        # Try to decode user comment
                        try:
                            if value.startswith(b'ASCII\x00\x00\x00'):
                                exif_data[tag] = value[8:].decode('ascii', errors='replace').strip('\x00')
                            elif value.startswith(b'UNICODE\x00'):
                                exif_data[tag] = value[8:].decode('utf-16', errors='replace').strip('\x00')
                            else:
                                exif_data[tag] = format_value(value)
                        except:
                            exif_data[tag] = format_value(value)
                    else:
                        exif_data[tag] = format_value(value)
                else:
                    exif_data[tag] = format_value(value)
    
    except Exception as e:
        exif_data['Error'] = str(e)
    
    return exif_data, gps_data


def get_png_metadata(filepath: str) -> dict:
    """Extract PNG-specific metadata (tEXt, iTXt, zTXt chunks)."""
    metadata = {}
    
    try:
        with Image.open(filepath) as img:
            if img.format != 'PNG':
                return metadata
            
            # PNG stores metadata in img.info
            for key, value in img.info.items():
                if isinstance(value, str):
                    metadata[key] = value
                elif isinstance(value, bytes):
                    try:
                        metadata[key] = value.decode('utf-8', errors='replace')
                    except:
                        metadata[key] = f"<binary: {len(value)} bytes>"
    except Exception as e:
        metadata['Error'] = str(e)
    
    return metadata


def get_gif_metadata(filepath: str) -> dict:
    """Extract GIF-specific metadata."""
    metadata = {}
    
    try:
        with Image.open(filepath) as img:
            if img.format != 'GIF':
                return metadata
            
            metadata['Is Animated'] = 'Yes' if getattr(img, 'is_animated', False) else 'No'
            if hasattr(img, 'n_frames'):
                metadata['Frame Count'] = img.n_frames
            if 'duration' in img.info:
                metadata['Frame Duration'] = f"{img.info['duration']} ms"
            if 'loop' in img.info:
                metadata['Loop Count'] = img.info['loop'] if img.info['loop'] > 0 else 'Infinite'
            if 'comment' in img.info:
                metadata['Comment'] = img.info['comment']
    except Exception as e:
        metadata['Error'] = str(e)
    
    return metadata


def print_section(title: str, data: dict, indent: int = 2):
    """Print a section of metadata."""
    if not data:
        return
    
    print(f"\n{'─' * 40}")
    print(f"  {title}")
    print(f"{'─' * 40}")
    
    for key, value in data.items():
        value_str = str(value)
        # Truncate very long values
        if len(value_str) > 100:
            value_str = value_str[:100] + "..."
        print(f"{' ' * indent}{key}: {value_str}")


def analyze_file(filepath: str):
    """Analyze a single file and display its metadata."""
    print("\n" + "=" * 60)
    print(f"  FILE: {filepath}")
    print("=" * 60)
    
    # Check if file exists
    if not os.path.exists(filepath):
        print(f"  [ERROR] File not found: {filepath}")
        return False
    
    # Check if it's a supported file
    if not is_supported_file(filepath):
        print(f"  [ERROR] Unsupported file type: {get_extension(filepath)}")
        print(f"  Supported types: {', '.join(SUPPORTED_EXTENSIONS)}")
        return False
    
    # Get and display basic file info
    basic_info = get_basic_info(filepath)
    print_section("📁 Basic File Information", basic_info)
    
    # Get and display image info
    image_info = get_image_info(filepath)
    print_section("🖼️  Image Properties", image_info)
    
    # Get and display EXIF data
    exif_data, gps_data = get_exif_data(filepath)
    if exif_data:
        print_section("📷 EXIF Data", exif_data)
    
    if gps_data:
        print_section("📍 GPS Information", gps_data)
    
    # Get format-specific metadata
    ext = get_extension(filepath)
    if ext == '.png':
        png_meta = get_png_metadata(filepath)
        if png_meta:
            print_section("🔷 PNG Metadata", png_meta)
    elif ext == '.gif':
        gif_meta = get_gif_metadata(filepath)
        if gif_meta:
            print_section("🎞️  GIF Metadata", gif_meta)
    
    # Check if no EXIF data found
    if not exif_data and not gps_data:
        print(f"\n  ℹ️  No EXIF metadata found in this image")
    
    return True


def modify_metadata(filepath: str, tag: str, value: str) -> bool:
    """Modify a metadata tag in an image (bonus feature)."""
    try:
        import piexif
        
        if not os.path.exists(filepath):
            print(f"[-] File not found: {filepath}")
            return False
        
        ext = get_extension(filepath)
        if ext not in {'.jpg', '.jpeg'}:
            print(f"[-] Metadata modification only supported for JPEG files")
            return False
        
        exif_dict = piexif.load(filepath)
        
        # Map common tag names to EXIF IDs
        tag_mapping = {
            'ImageDescription': piexif.ImageIFD.ImageDescription,
            'Artist': piexif.ImageIFD.Artist,
            'Copyright': piexif.ImageIFD.Copyright,
            'Software': piexif.ImageIFD.Software,
            'DateTime': piexif.ImageIFD.DateTime,
            'UserComment': piexif.ExifIFD.UserComment,
        }
        
        if tag in tag_mapping:
            ifd = '0th' if tag in ['ImageDescription', 'Artist', 'Copyright', 'Software', 'DateTime'] else 'Exif'
            exif_dict[ifd][tag_mapping[tag]] = value.encode('utf-8')
            
            exif_bytes = piexif.dump(exif_dict)
            piexif.insert(exif_bytes, filepath)
            print(f"[+] Successfully modified {tag} in {filepath}")
            return True
        else:
            print(f"[-] Unknown tag: {tag}")
            print(f"    Supported tags: {', '.join(tag_mapping.keys())}")
            return False
    
    except ImportError:
        print("[-] piexif library required for metadata modification")
        print("    Install with: pip install piexif")
        return False
    except Exception as e:
        print(f"[-] Error modifying metadata: {e}")
        return False


def delete_metadata(filepath: str) -> bool:
    """Delete all EXIF metadata from an image (bonus feature)."""
    try:
        import piexif
        
        if not os.path.exists(filepath):
            print(f"[-] File not found: {filepath}")
            return False
        
        ext = get_extension(filepath)
        if ext not in {'.jpg', '.jpeg'}:
            print(f"[-] Metadata deletion only supported for JPEG files")
            return False
        
        piexif.remove(filepath)
        print(f"[+] Successfully removed all EXIF metadata from {filepath}")
        return True
    
    except ImportError:
        print("[-] piexif library required for metadata deletion")
        print("    Install with: pip install piexif")
        return False
    except Exception as e:
        print(f"[-] Error deleting metadata: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Scorpion - Image metadata parser and viewer',
        usage='%(prog)s [OPTIONS] FILE1 [FILE2 ...]'
    )
    parser.add_argument('files', metavar='FILE', nargs='+',
                        help='Image files to analyze')
    parser.add_argument('-m', '--modify', nargs=2, metavar=('TAG', 'VALUE'),
                        help='Modify a metadata tag (JPEG only, requires piexif)')
    parser.add_argument('-d', '--delete', action='store_true',
                        help='Delete all EXIF metadata (JPEG only, requires piexif)')
    
    args = parser.parse_args()
    
    success_count = 0
    total_count = len(args.files)
    
    for filepath in args.files:
        if args.modify:
            tag, value = args.modify
            if modify_metadata(filepath, tag, value):
                success_count += 1
        elif args.delete:
            if delete_metadata(filepath):
                success_count += 1
        else:
            if analyze_file(filepath):
                success_count += 1
    
    print("\n" + "=" * 60)
    print(f"  Summary: {success_count}/{total_count} files processed successfully")
    print("=" * 60 + "\n")
    
    return 0 if success_count == total_count else 1


if __name__ == '__main__':
    sys.exit(main())
