#!/bin/bash
# Pfad zum Verzeichnis mit PDF-Dateien
pdf_folder="/mnt/c/path/to/pdfs"  # Anpassung auf Windows-Verzeichnis

# Suchbegriff
search_word="deinSuchwort"

# Durchsuche alle PDFs im Verzeichnis
for pdf_file in "$pdf_folder"/*.pdf; do
    # Konvertiere das PDF in Text und speichere es in einer temporären Datei
    txt_output=$(mktemp)
    pdftotext "$pdf_file" "$txt_output"

    # Suche in der Textdatei nach dem Wort und gib die Zeilen aus
    grep -H "$search_word" "$txt_output" && echo "Datei: $pdf_file"
    
    # Lösche die temporäre Datei
    rm "$txt_output"
done

