#pdf_utils.py
import os
import logging
import fitz  # PyMuPDF

logger = logging.getLogger(__name__)

RENDER_DPI = 200  # good balance of OCR/Scout legibility vs file size/token cost


def get_page_count(pdf_path):
    doc = fitz.open(pdf_path)
    count = doc.page_count
    doc.close()
    return count


def pdf_to_images(pdf_path, out_dir, job_id, dpi=RENDER_DPI):
    """
    Render every page of the PDF to a JPEG.
    Returns a list of (page_index, image_path, width, height), in page order.
    """
    os.makedirs(out_dir, exist_ok=True)
    doc = fitz.open(pdf_path)
    zoom = dpi / 72.0  # PDF default is 72 dpi
    matrix = fitz.Matrix(zoom, zoom)

    pages = []
    for page_index in range(doc.page_count):
        page = doc.load_page(page_index)
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        image_path = os.path.join(out_dir, f'{job_id}_page{page_index}.jpg')
        pix.save(image_path)
        pages.append((page_index, image_path, pix.width, pix.height))
        logger.info(f"📄 Rendered page {page_index + 1}/{doc.page_count} -> {image_path} "
                    f"({pix.width}x{pix.height})")

    doc.close()
    return pages


def images_to_pdf(image_paths, output_pdf_path):
    """
    Stitch a list of (already redacted) page images back into a single PDF,
    in the given order. image_paths must be pre-sorted by page index.
    """
    os.makedirs(os.path.dirname(output_pdf_path), exist_ok=True)
    doc = fitz.open()
    for image_path in image_paths:
        img_doc = fitz.open(image_path)
        rect = img_doc[0].rect
        pdf_bytes = img_doc.convert_to_pdf()
        img_doc.close()
        img_pdf = fitz.open("pdf", pdf_bytes)
        doc.insert_pdf(img_pdf)
        img_pdf.close()

    doc.save(output_pdf_path)
    doc.close()
    logger.info(f"✅ Assembled {len(image_paths)} pages -> {output_pdf_path}")
    return output_pdf_path


def is_pdf(filename_or_path):
    return filename_or_path.lower().endswith('.pdf')