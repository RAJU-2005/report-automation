import os
import uuid
import datetime
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from parsers import parse_scan_file
from generator import generate_docx_report, convert_docx_to_pdf

app = Flask(__name__, template_folder='templates', static_folder='static')

# Define folders inside the project directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
OUTPUT_FOLDER = os.path.join(BASE_DIR, 'outputs')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Simple in-memory storage for active sessions/jobs
# In a real app, this might be a database or cache, but for a local utility, in-memory works perfectly
jobs = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload_files():
    """
    Handles uploading the scan report and optional word template.
    Parses the scan report and returns the structured data.
    """
    if 'scan_report' not in request.files:
        return jsonify({"error": "No scan report file uploaded."}), 400
        
    scan_file = request.files['scan_report']
    template_file = request.files.get('template')
    
    if scan_file.filename == '':
        return jsonify({"error": "Scan report file name is empty."}), 400
        
    job_id = str(uuid.uuid4())
    
    # Save Scan Report
    scan_filename = secure_filename(scan_file.filename)
    scan_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{job_id}_scan_{scan_filename}")
    scan_file.save(scan_path)
    
    # Save Template if provided, otherwise check for default template
    template_path = None
    if template_file and template_file.filename != '':
        template_filename = secure_filename(template_file.filename)
        template_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{job_id}_tmpl_{template_filename}")
        template_file.save(template_path)
    else:
        # Check if default template exists
        default_tmpl_path = os.path.join(BASE_DIR, 'default_template.docx')
        if os.path.exists(default_tmpl_path):
            template_path = default_tmpl_path
            
    # Parse the scan report
    try:
        parsed_data = parse_scan_file(scan_path, scan_file.filename)
    except Exception as e:
        return jsonify({"error": f"Failed to parse scan report: {str(e)}"}), 500
        
    # Store job info
    jobs[job_id] = {
        "scan_path": scan_path,
        "template_path": template_path,
        "original_scan_name": scan_file.filename,
        "parsed_data": parsed_data
    }
    
    return jsonify({
        "job_id": job_id,
        "data": parsed_data,
        "has_template": template_path is not None
    })

@app.route('/api/generate', methods=['POST'])
def generate_report():
    """
    Receives edited report data, renders the Word template, and returns the finished document.
    """
    payload = request.json or {}
    job_id = payload.get('job_id')
    format_type = payload.get('format', 'word').lower()  # 'word' or 'pdf'
    
    if not job_id or job_id not in jobs:
        return jsonify({"error": "Invalid or expired job session."}), 400
        
    job_info = jobs[job_id]
    
    # 1. Update template path if user uploaded one in a separate step or we check files
    # Check if a custom template was uploaded during this call (passed as raw file)
    # But in our flow, template is uploaded in Stage 1 and stored in job_info
    template_path = job_info.get('template_path')
    if not template_path:
        # Check if default template is available
        default_tmpl_path = os.path.join(BASE_DIR, 'default_template.docx')
        if os.path.exists(default_tmpl_path):
            template_path = default_tmpl_path
        else:
            return jsonify({"error": "No Word template (.docx) was uploaded, and no default template was found."}), 400

    # 2. Extract reviewed data from frontend
    user_data = payload.get('data', {})
    
    # Ensure nested objects are fully setup
    # e.g., mapping metrics, metadata, vulnerabilities
    render_context = {
        "scan_name": user_data.get('metadata', {}).get('scan_name', 'Vulnerability Assessment'),
        "scan_date": user_data.get('metadata', {}).get('scan_date', datetime.date.today().strftime("%Y-%m-%d")),
        "target_scope": user_data.get('metadata', {}).get('target_scope', 'N/A'),
        "client_name": user_data.get('metadata', {}).get('client_name', 'Acme Corp'),
        "tester_name": user_data.get('metadata', {}).get('tester_name', 'Security Tester'),
        "metrics": user_data.get('metrics', {}),
        "vulnerabilities": user_data.get('vulnerabilities', [])
    }
    
    # Generate Output Files
    output_filename = f"Vulnerability_Report_{datetime.date.today().strftime('%Y%m%d')}_{job_id[:8]}"
    docx_output_path = os.path.join(app.config['OUTPUT_FOLDER'], f"{output_filename}.docx")
    
    try:
        # Render the DOCX template
        generate_docx_report(template_path, docx_output_path, render_context)
    except Exception as e:
        return jsonify({"error": f"Failed to generate Word report: {str(e)}"}), 500
        
    # Check if PDF format is requested
    if format_type == 'pdf':
        pdf_output_path = os.path.join(app.config['OUTPUT_FOLDER'], f"{output_filename}.pdf")
        pdf_success = convert_docx_to_pdf(docx_output_path, pdf_output_path)
        
        if pdf_success and os.path.exists(pdf_output_path):
            return send_file(
                pdf_output_path,
                as_attachment=True,
                download_name=f"{output_filename}.pdf",
                mimetype='application/pdf'
            )
        else:
            # Fallback to Word but include a header so frontend can display warning
            return send_file(
                docx_output_path,
                as_attachment=True,
                download_name=f"{output_filename}.docx",
                mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                headers={"X-PDF-Conversion-Status": "failed"}
            )
            
    # Default return Word (.docx)
    return send_file(
        docx_output_path,
        as_attachment=True,
        download_name=f"{output_filename}.docx",
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    )

if __name__ == '__main__':
    # Ensure default template exists on startup
    # We will create a script/method to build the default template
    print("Starting Report Automation Server at http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
