import os
from docxtpl import DocxTemplate

def generate_docx_report(template_path, output_path, data):
    """
    Renders the Word template (.docx) with the provided data dictionary.
    """
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template file not found at: {template_path}")
        
    doc = DocxTemplate(template_path)
    
    # Process or clean data before rendering if necessary
    # Example: ensuring severities are upper-cased
    if 'vulnerabilities' in data:
        for vuln in data['vulnerabilities']:
            if 'severity' in vuln:
                vuln['severity'] = vuln['severity'].upper()
                
    # docxtpl renders using jinja2 context in the Word file
    doc.render(data)
    doc.save(output_path)
    return True

def convert_docx_to_pdf(docx_path, pdf_path):
    """
    Attempts to convert the generated DOCX file to PDF on Windows using Microsoft Word.
    Returns True if successful, or raises/returns False if Word is not installed.
    """
    docx_abs = os.path.abspath(docx_path)
    pdf_abs = os.path.abspath(pdf_path)
    
    # Try importing win32com to control Microsoft Word
    try:
        import win32com.client
        import pythoncom
        
        # Initialize COM library for multi-threaded Flask requests
        pythoncom.CoInitialize()
        
        # Dispatch Word application
        word = win32com.client.DispatchEx("Word.Application")
        word.Visible = False
        
        # Open document
        doc = word.Documents.Open(docx_abs)
        
        # Save as PDF (FileFormat 17 represents PDF in Word object model)
        doc.SaveAs(pdf_abs, FileFormat=17)
        doc.Close()
        word.Quit()
        
        return True
    except Exception as e:
        print(f"PDF Conversion Failed: {e}")
        # Return False so that the caller knows conversion failed
        return False
