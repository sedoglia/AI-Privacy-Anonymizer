#!/usr/bin/env python
"""Debug script to trace OCR and redaction matching for a scanned PDF."""
from pathlib import Path
from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig

# Process the problematic document
pdf_path = Path(r"C:\TEMP\Piano_aghi_2025.pdf")
output_dir = Path(r"C:\TEMP\elaborati_debug")
output_dir.mkdir(exist_ok=True)

print(f"\n=== Processing {pdf_path.name} ===\n")

# Create anonymizer with hybrid mode
config = LayerConfig(
    opf_enabled=True,
    opf_recall_mode="aggressive",
    gliner_enabled=True,
    gliner_threshold=0.3,
    pattern_enabled=True,
    parallel=False,  # Sequential for clearer logging
    low_memory=False,
)
anon = Anonymizer(config=config)

# Process file - this will extract OCR text
print("Step 1: Reading and OCR extraction...")
content = anon.docling_extractor.read_text(pdf_path) if anon.docling_extractor else None
if not content:
    from privacy_anonymizer.io import get_adapter
    adapter = get_adapter(pdf_path)
    content = adapter.read_text(pdf_path)

print(f"\nExtracted text ({len(content.text)} chars):")
print("=" * 80)
print(content.text)
print("=" * 80)

# Detect entities
print("\nStep 2: Entity detection...")
spans = anon.detect_text(content.text)
print(f"Found {len(spans)} spans:")
for span in spans:
    text = content.text[span.start:span.end]
    print(f"  [{span.start:4d}-{span.end:4d}] {span.label:20s} '{text}'")

# Show which spans are BONOMO KATIA
bonomo_spans = [s for s in spans if "BONOMO" in content.text[s.start:s.end].upper()]
print(f"\nBONOMO KATIA spans found: {len(bonomo_spans)}")
for span in bonomo_spans:
    text = content.text[span.start:span.end]
    print(f"  [{span.start:4d}-{span.end:4d}] {span.label:20s} '{text}'")

# Process file with debug redaction
print("\nStep 3: Processing file with debug redaction...")
from privacy_anonymizer.io.pdf import _write_ocr_redacted_pdf, _pdf_is_scanned
from privacy_anonymizer.masking import build_masking_plan

is_scanned = _pdf_is_scanned(pdf_path)
print(f"Is scanned: {is_scanned}")

if is_scanned:
    # Get OCR words from content
    if hasattr(content, 'ocr_words') and content.ocr_words:
        print(f"OCR words cached: {len(content.ocr_words)} pages")

    plan = build_masking_plan(content.text, spans, "replace")
    print(f"Redaction plan: {len(plan.replacements)} replacements")

    output_pdf = output_dir / f"{pdf_path.stem}_debug_anonymized.pdf"
    redacted = _write_ocr_redacted_pdf(
        pdf_path,
        output_pdf,
        plan.replacements,
        keep_metadata=True,
        cached_words=content.ocr_words,
        debug=True,  # Enable debug output
    )
    print(f"\nRedacted {redacted} word boxes")
    print(f"Output: {output_pdf}")
else:
    print("Not a scanned PDF, skipping OCR redaction debug")
