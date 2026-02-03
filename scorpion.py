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
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading


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


class ScorpionGUI:
    """Graphical User Interface for Scorpion."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Scorpion - Metadata Explorer")
        self.root.geometry("1000x700")
        self.root.configure(bg="#1e1e1e")
        
        self.current_file = None
        self.setup_ui()
        
    def setup_ui(self):
        # Professional Dark Theme Styling
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#2d2d2d", foreground="white", fieldbackground="#2d2d2d", borderwidth=0)
        style.map("Treeview", background=[('selected', '#3d3d3d')])
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="white", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#007acc")
        style.configure("TButton", padding=6)

        # Main Layout
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Toolbar
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar, text="Open File", command=self.load_file_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Delete All Metadata", command=self.delete_all_metadata).pack(side=tk.LEFT, padx=5)
        
        self.status_label = ttk.Label(toolbar, text="Welcome to Scorpion")
        self.status_label.pack(side=tk.RIGHT, padx=5)
        
        # Content Area (Split Panes)
        panes = tk.PanedWindow(main_frame, orient=tk.HORIZONTAL, bg="#333333", sashwidth=4)
        panes.pack(fill=tk.BOTH, expand=True)
        
        # Left Side: File Info Panel
        info_frame = ttk.Frame(panes)
        panes.add(info_frame, width=300)
        
        ttk.Label(info_frame, text="File Information", style="Header.TLabel").pack(anchor=tk.W, pady=5)
        self.files_text = tk.Text(info_frame, bg="#252526", fg="#cccccc", borderwidth=0, padx=10, pady=10, font=("Consolas", 9), height=15)
        self.files_text.pack(fill=tk.BOTH, expand=True)
        self.files_text.config(state=tk.DISABLED)
        
        # Right Side: Metadata Tree
        tree_frame = ttk.Frame(panes)
        panes.add(tree_frame)
        
        ttk.Label(tree_frame, text="Metadata Browser", style="Header.TLabel").pack(anchor=tk.W, pady=5)
        
        columns = ("Tag", "Value")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        self.tree.heading("Tag", text="Attribute")
        self.tree.heading("Value", text="Value")
        self.tree.column("Tag", width=200)
        self.tree.column("Value", width=400)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Double-click to edit (Experimental/Bonus)
        self.tree.bind("<Double-1>", self.on_double_click)

    def load_file_dialog(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.gif *.bmp"), ("All files", "*.*")]
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, filepath):
        self.current_file = filepath
        self.status_label.config(text=f"Viewing: {os.path.basename(filepath)}")
        
        # Clear existing
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # File info
        basic = get_basic_info(filepath)
        img_info = get_image_info(filepath)
        
        self.files_text.config(state=tk.NORMAL)
        self.files_text.delete(1.0, tk.END)
        for k, v in {**basic, **img_info}.items():
            self.files_text.insert(tk.END, f"{k}: {v}\n")
        self.files_text.config(state=tk.DISABLED)
        
        # Metadata
        exif, gps = get_exif_data(filepath)
        
        # Insert EXIF
        exif_node = self.tree.insert("", tk.END, values=("Camera/EXIF Data", ""), open=True)
        for k, v in exif.items():
            self.tree.insert(exif_node, tk.END, values=(k, v))
            
        # Insert GPS
        if gps:
            gps_node = self.tree.insert("", tk.END, values=("GPS Coordinates", ""), open=True)
            for k, v in gps.items():
                self.tree.insert(gps_node, tk.END, values=(k, v))
        
        # Format specific
        ext = get_extension(filepath)
        if ext == '.png':
            png_meta = get_png_metadata(filepath)
            if png_meta:
                node = self.tree.insert("", tk.END, values=("PNG Chunks", ""), open=True)
                for k, v in png_meta.items():
                    self.tree.insert(node, tk.END, values=(k, v))
        elif ext == '.gif':
            gif_meta = get_gif_metadata(filepath)
            if gif_meta:
                node = self.tree.insert("", tk.END, values=("GIF Animation Info", ""), open=True)
                for k, v in gif_meta.items():
                    self.tree.insert(node, tk.END, values=(k, v))

    def on_double_click(self, event):
        """Allow editing a tag value."""
        item = self.tree.selection()[0]
        column = self.tree.identify_column(event.x)
        if column == "#2":  # Only allow editing the value column
            tag = self.tree.item(item, "values")[0]
            current_val = self.tree.item(item, "values")[1]
            
            # Create a popup for editing
            edit_win = tk.Toplevel(self.root)
            edit_win.title(f"Edit {tag}")
            edit_win.geometry("400x150")
            
            ttk.Label(edit_win, text=f"New value for {tag}:").pack(pady=10)
            entry = ttk.Entry(edit_win, width=50)
            entry.insert(0, current_val)
            entry.pack(pady=5, padx=10)
            
            def save_edit():
                new_val = entry.get()
                if modify_metadata(self.current_file, tag, new_val):
                    self.load_file(self.current_file)
                    edit_win.destroy()
                else:
                    messagebox.showerror("Error", "Could not modify metadata. Usually only JPEG EXIF tags are editable.")

            ttk.Button(edit_win, text="Save", command=save_edit).pack(pady=10)

    def delete_all_metadata(self):
        if not self.current_file:
            return
        if messagebox.askyesno("Confirm Delete", "Remove ALL EXIF metadata from this image? (JPEG only)"):
            if delete_metadata(self.current_file):
                self.load_file(self.current_file)
                messagebox.showinfo("Success", "Metadata removed.")
            else:
                messagebox.showerror("Error", "Could not remove metadata (ensure piexif is installed and it's a JPEG).")

    def run(self):
        self.root.mainloop()


def main():
    parser = argparse.ArgumentParser(
        description='Scorpion - Image metadata parser and viewer',
        usage='%(prog)s [OPTIONS] FILE1 [FILE2 ...]'
    )
    parser.add_argument('files', metavar='FILE', nargs='*',
                        help='Image files to analyze')
    parser.add_argument('-m', '--modify', nargs=2, metavar=('TAG', 'VALUE'),
                        help='Modify a metadata tag (JPEG only, requires piexif)')
    parser.add_argument('-d', '--delete', action='store_true',
                        help='Delete all EXIF metadata (JPEG only, requires piexif)')
    parser.add_argument('-g', '--gui', action='store_true',
                        help='Launch graphical interface')
    
    args = parser.parse_args()
    
    if args.gui or len(args.files) == 0:
        gui = ScorpionGUI()
        if args.files:
            gui.load_file(args.files[0])
        gui.run()
        return 0

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
