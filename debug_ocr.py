#!/usr/bin/env python
"""Debug script to trace OCR and redaction matching for a scanned PDF."""
from pathlib import Path
from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig
import difflib

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
for i, span in enumerate(bonomo_spans):
    text = content.text[span.start:span.end]
    print(f"  [{i}] [{span.start:4d}-{span.end:4d}] {span.label:20s} '{text}'")

# Process file with debug redaction
print("\nStep 3: Analyzing OCR word structure...")
from privacy_anonymizer.io.pdf import (
    _write_ocr_redacted_pdf,
    _pdf_is_scanned,
    _find_word_matches,
    _normalize_token,
)
from privacy_anonymizer.masking import build_masking_plan

is_scanned = _pdf_is_scanned(pdf_path)
print(f"Is scanned: {is_scanned}")

if is_scanned:
    # Get OCR words from content
    if hasattr(content, "ocr_words") and content.ocr_words:
        print(f"\nOCR words cached: {len(content.ocr_words)} pages")

        # Show OCR words for each page that has BONOMO KATIA
        for page_idx, page_words in enumerate(content.ocr_words):
            # Check if any BONOMO KATIA span is on this page
            page_has_bonomo = any(
                content.text[s.start : s.end].find("BONOMO") >= 0
                for s in bonomo_spans
                if page_idx < len(content.ocr_words)  # Rough page estimate
            )
            if page_words:
                print(f"\n  Page {page_idx}: {len(page_words)} words")
                word_texts = [w["text"] for w in page_words[:50]]
                print(f"    Words: {' '.join(word_texts)}{'...' if len(page_words) > 50 else ''}")

    plan = build_masking_plan(content.text, spans, "replace")
    print(f"\nRedaction plan: {len(plan.replacements)} replacements")

    # For each BONOMO KATIA span, manually test word matching
    print("\n" + "=" * 80)
    print("DETAILED SPAN MATCHING ANALYSIS")
    print("=" * 80)
    for span_idx, span in enumerate(bonomo_spans):
        span_text = content.text[span.start : span.end]
        print(f"\nSpan {span_idx}: [{span.start:4d}-{span.end:4d}] '{span_text}'")

        # Find the replacement for this span
        replacement = next(
            (r for r in plan.replacements if r.original == span_text), None
        )
        if not replacement:
            print(f"  WARNING: No replacement found for this span")
            continue

        # Test matching on all pages
        for page_idx, page_words in enumerate(content.ocr_words):
            if not page_words:
                continue

            # Try text-content matching
            matches = _find_word_matches(page_words, span_text)
            if matches:
                print(f"  Page {page_idx}: {len(matches)} match(es) via text_content")
                for match_idx, match in enumerate(matches):
                    match_text = " ".join(w["text"] for w in match)
                    print(f"    Match {match_idx}: [{match_idx}] words '{match_text}'")

    # Now process with debug output
    print("\n" + "=" * 80)
    print("PROCESSING FILE WITH REDACTION")
    print("=" * 80)
    output_pdf = output_dir / f"{pdf_path.stem}_debug_anonymized.pdf"
    redacted = _write_ocr_redacted_pdf(
        pdf_path,
        output_pdf,
        plan.replacements,
        keep_metadata=True,
        cached_words=content.ocr_words,
        debug=True,  # Enable debug output
    )
    print(f"\nRedacted {redacted} word boxes total")
    print(f"Output: {output_pdf}")
else:
    print("Not a scanned PDF, skipping OCR redaction debug")
