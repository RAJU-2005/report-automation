// Frontend Logic for RepAuto

document.addEventListener('DOMContentLoaded', () => {
    // Application State
    const state = {
        scanFile: null,
        templateFile: null,
        jobId: null,
        data: null, // Holds parsed metadata, metrics, and vulnerabilities list
        currentStage: 1
    };

    // DOM Elements
    const elements = {
        progressFill: document.getElementById('progressFill'),
        step1: document.getElementById('step1'),
        step2: document.getElementById('step2'),
        step3: document.getElementById('step3'),
        step4: document.getElementById('step4'),
        
        stage1Section: document.getElementById('stage1Section'),
        stage2Section: document.getElementById('stage2Section'),
        stage3Section: document.getElementById('stage3Section'),
        stage4Section: document.getElementById('stage4Section'),
        
        scanUploadZone: document.getElementById('scanUploadZone'),
        scanFileInput: document.getElementById('scanFileInput'),
        selectedScanBadge: document.getElementById('selectedScanBadge'),
        selectedScanName: document.getElementById('selectedScanName'),
        removeScanBtn: document.getElementById('removeScanBtn'),
        
        templateUploadZone: document.getElementById('templateUploadZone'),
        templateFileInput: document.getElementById('templateFileInput'),
        selectedTemplateBadge: document.getElementById('selectedTemplateBadge'),
        selectedTemplateName: document.getElementById('selectedTemplateName'),
        removeTemplateBtn: document.getElementById('removeTemplateBtn'),
        useDefaultTemplateBtn: document.getElementById('useDefaultTemplateBtn'),
        
        startExtractionBtn: document.getElementById('startExtractionBtn'),
        backToUploadBtn: document.getElementById('backToUploadBtn'),
        goToGenerateBtn: document.getElementById('goToGenerateBtn'),
        backToReviewBtn: document.getElementById('backToReviewBtn'),
        
        extractionBarFill: document.getElementById('extractionBarFill'),
        extractionPercentage: document.getElementById('extractionPercentage'),
        extractionStatus: document.getElementById('extractionStatus'),
        extractionLogs: document.getElementById('extractionLogs'),
        
        // Metadata inputs
        metaClient: document.getElementById('metaClient'),
        metaScanName: document.getElementById('metaScanName'),
        metaScanDate: document.getElementById('metaScanDate'),
        metaTarget: document.getElementById('metaTarget'),
        metaTester: document.getElementById('metaTester'),
        
        // Metrics totals
        metricCrit: document.getElementById('metricCrit'),
        metricHigh: document.getElementById('metricHigh'),
        metricMed: document.getElementById('metricMed'),
        metricLow: document.getElementById('metricLow'),
        metricTotal: document.getElementById('metricTotal'),
        
        // Findings
        findingsTableBody: document.getElementById('findingsTableBody'),
        addFindingBtn: document.getElementById('addFindingBtn'),
        
        // Download triggers
        downloadWordBtn: document.getElementById('downloadWordBtn'),
        downloadPdfBtn: document.getElementById('downloadPdfBtn'),
        pdfWarningAlert: document.getElementById('pdfWarningAlert')
    };

    // Stage Navigation
    function setStage(stage) {
        state.currentStage = stage;
        
        // Update progress bar & classes
        const progressPercentages = { 1: 12.5, 2: 37.5, 3: 62.5, 4: 87.5 };
        elements.progressFill.style.width = `${progressPercentages[stage]}%`;
        
        // Update active classes on wizard bubbles
        const steps = [elements.step1, elements.step2, elements.step3, elements.step4];
        steps.forEach((step, idx) => {
            const stepNum = idx + 1;
            step.classList.remove('active', 'completed');
            if (stepNum === stage) {
                step.classList.add('active');
            } else if (stepNum < stage) {
                step.classList.add('completed');
            }
        });
        
        // Update active sections
        const sections = [elements.stage1Section, elements.stage2Section, elements.stage3Section, elements.stage4Section];
        sections.forEach((sect, idx) => {
            sect.classList.toggle('active', (idx + 1) === stage);
        });
    }

    // --- STAGE 1: UPLOAD HANDLING ---

    // Drag over styling helpers
    function setupDragDropZone(zone, fileInput, fileCallback) {
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('dragover');
        });
        
        zone.addEventListener('dragleave', () => {
            zone.classList.remove('dragover');
        });
        
        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                fileCallback(e.dataTransfer.files[0]);
            }
        });
        
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                fileCallback(e.target.files[0]);
            }
        });
    }

    // Handle scan file choice
    setupDragDropZone(elements.scanUploadZone, elements.scanFileInput, (file) => {
        state.scanFile = file;
        elements.selectedScanName.textContent = file.name;
        elements.selectedScanBadge.style.display = 'flex';
        elements.startExtractionBtn.disabled = false;
        
        // Play subtle sound/animation triggers here if needed
        console.log(`Scan report loaded: ${file.name}`);
    });

    elements.removeScanBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        state.scanFile = null;
        elements.scanFileInput.value = '';
        elements.selectedScanBadge.style.display = 'none';
        elements.startExtractionBtn.disabled = true;
    });

    // Handle template file choice
    setupDragDropZone(elements.templateUploadZone, elements.templateFileInput, (file) => {
        state.templateFile = file;
        elements.selectedTemplateName.textContent = file.name;
        elements.selectedTemplateBadge.style.display = 'flex';
        console.log(`Custom Word template loaded: ${file.name}`);
    });

    elements.removeTemplateBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        state.templateFile = null;
        elements.templateFileInput.value = '';
        elements.selectedTemplateBadge.style.display = 'none';
    });

    // Helper button to set template state as "default"
    elements.useDefaultTemplateBtn.addEventListener('click', () => {
        state.templateFile = null; // Backend uses local default
        elements.selectedTemplateName.textContent = "Using default vulnerability template";
        elements.selectedTemplateBadge.style.display = 'flex';
    });

    // --- STAGE 2: EXTRACTION FLOW (ANIMATION + API CALL) ---

    elements.startExtractionBtn.addEventListener('click', () => {
        if (!state.scanFile) return;
        
        setStage(2);
        
        // UI Log Helper
        const logContainer = elements.extractionLogs;
        logContainer.innerHTML = '';
        function addLog(text, delay = 0) {
            return new Promise((resolve) => {
                setTimeout(() => {
                    const div = document.createElement('div');
                    div.className = 'log-line';
                    div.textContent = `> ${text}`;
                    logContainer.appendChild(div);
                    logContainer.scrollTop = logContainer.scrollHeight;
                    resolve();
                }, delay);
            });
        }

        // Animate progress loading while waiting for actual server response
        let progress = 0;
        const progressInterval = setInterval(() => {
            if (progress < 90) { // Hold at 90 until finished
                progress += Math.floor(Math.random() * 8) + 2;
                if (progress > 90) progress = 90;
                elements.extractionBarFill.style.width = `${progress}%`;
                elements.extractionPercentage.textContent = `${progress}%`;
            }
        }, 300);

        // Chain of simulated logs for premium UX
        const logSequence = async () => {
            await addLog("Uploading report to server...", 100);
            await addLog(`File detected: ${state.scanFile.name} (${(state.scanFile.size/1024).toFixed(1)} KB)`, 400);
            await addLog("Mounting document parser module...", 500);
            await addLog("Scanning tables and finding risk keywords...", 600);
        };
        logSequence();

        // Perform actual fetch
        const formData = new FormData();
        formData.append('scan_report', state.scanFile);
        if (state.templateFile) {
            formData.append('template', state.templateFile);
        }

        fetch('/api/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error("Server failed to parse the file.");
            }
            return response.json();
        })
        .then(async (result) => {
            // Once data is ready, complete progress bar
            clearInterval(progressInterval);
            elements.extractionBarFill.style.width = '100%';
            elements.extractionPercentage.textContent = '100%';
            
            state.jobId = result.job_id;
            state.data = result.data;
            
            await addLog("Data parsed successfully!", 100);
            await addLog(`Found ${result.data.vulnerabilities.length} vulnerabilities.`, 200);
            await addLog("Preparing interactive findings editor...", 300);
            
            setTimeout(() => {
                initializeEditor();
                setStage(3);
            }, 1200);
        })
        .catch(async (error) => {
            clearInterval(progressInterval);
            elements.extractionBarFill.style.width = '0%';
            elements.extractionPercentage.textContent = 'ERROR';
            elements.extractionStatus.textContent = 'Extraction failed.';
            await addLog(`ERROR: ${error.message}`, 100);
            await addLog("Please check file format and try again.", 300);
            
            // Show a back button
            setTimeout(() => {
                setStage(1);
            }, 5000);
        });
    });

    // --- STAGE 3: REVIEW & EDIT EDITOR ---

    function initializeEditor() {
        if (!state.data) return;
        
        // Fill Metadata
        const meta = state.data.metadata || {};
        elements.metaClient.value = meta.client_name || '';
        elements.metaScanName.value = meta.scan_name || '';
        elements.metaScanDate.value = meta.scan_date || '';
        elements.metaTarget.value = meta.target_scope || '';
        elements.metaTester.value = meta.tester_name || '';
        
        renderFindingsTable();
        recalculateMetrics();
    }

    function renderFindingsTable() {
        const tbody = elements.findingsTableBody;
        tbody.innerHTML = '';
        
        if (!state.data.vulnerabilities || state.data.vulnerabilities.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 3rem;">No vulnerabilities extracted. Click "Add Finding" to create one.</td></tr>`;
            return;
        }

        state.data.vulnerabilities.forEach((vuln, idx) => {
            const tr = document.createElement('tr');
            tr.dataset.index = idx;
            
            // Severity dropdown class color picker
            const sevLower = (vuln.severity || 'MEDIUM').toLowerCase();
            const sevClass = sevLower === 'critical' ? 'crit' :
                             sevLower === 'high' ? 'high' :
                             sevLower === 'medium' ? 'med' :
                             sevLower === 'low' ? 'low' : 'info';

            tr.innerHTML = `
                <td>
                    <select class="severity-select ${sevClass}" data-field="severity">
                        <option value="CRITICAL" ${vuln.severity === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                        <option value="HIGH" ${vuln.severity === 'HIGH' ? 'selected' : ''}>HIGH</option>
                        <option value="MEDIUM" ${vuln.severity === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                        <option value="LOW" ${vuln.severity === 'LOW' ? 'selected' : ''}>LOW</option>
                        <option value="INFO" ${vuln.severity === 'INFO' ? 'selected' : ''}>INFO</option>
                    </select>
                </td>
                <td>
                    <input type="text" class="edit-cell-input" data-field="title" value="${escapeHtml(vuln.title || '')}" placeholder="Vulnerability Title">
                </td>
                <td>
                    <input type="text" class="edit-cell-input" data-field="host" value="${escapeHtml(`${vuln.host || ''}${vuln.port && vuln.port !== 'N/A' ? ':' + vuln.port : ''}`)}" placeholder="e.g. 192.168.1.5:80">
                </td>
                <td>
                    <textarea class="edit-cell-input edit-cell-textarea" data-field="description" placeholder="Describe the vulnerability details...">${escapeHtml(vuln.description || '')}</textarea>
                </td>
                <td>
                    <textarea class="edit-cell-input edit-cell-textarea" data-field="remediation" placeholder="Steps to resolve the issue...">${escapeHtml(vuln.remediation || '')}</textarea>
                </td>
                <td style="text-align: center; vertical-align: middle;">
                    <button class="btn-delete-row" title="Delete Row"><i class="fa-solid fa-trash-can"></i></button>
                </td>
            `;
            
            // Listeners for inline modifications
            const inputs = tr.querySelectorAll('[data-field]');
            inputs.forEach(input => {
                input.addEventListener('change', (e) => {
                    const field = e.target.dataset.field;
                    let val = e.target.value;
                    
                    if (field === 'severity') {
                        // Update color classes on severity select
                        e.target.className = `severity-select ${val.toLowerCase() === 'critical' ? 'crit' :
                                                               val.toLowerCase() === 'high' ? 'high' :
                                                               val.toLowerCase() === 'medium' ? 'med' :
                                                               val.toLowerCase() === 'low' ? 'low' : 'info'}`;
                    }

                    if (field === 'host') {
                        // Split back into host and port if colon exists
                        const parts = val.split(':');
                        state.data.vulnerabilities[idx]['host'] = parts[0] || 'N/A';
                        state.data.vulnerabilities[idx]['port'] = parts[1] || 'N/A';
                    } else {
                        state.data.vulnerabilities[idx][field] = val;
                    }

                    recalculateMetrics();
                });
            });

            // Delete action
            tr.querySelector('.btn-delete-row').addEventListener('click', () => {
                state.data.vulnerabilities.splice(idx, 1);
                // Re-number vulnerability IDs
                state.data.vulnerabilities.forEach((v, i) => v.id = i + 1);
                renderFindingsTable();
                recalculateMetrics();
            });

            tbody.appendChild(tr);
        });
    }

    // Recalculates metrics and updates summaries
    function recalculateMetrics() {
        const metrics = {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        };

        if (state.data && state.data.vulnerabilities) {
            metrics.total = state.data.vulnerabilities.length;
            state.data.vulnerabilities.forEach(v => {
                const sev = (v.severity || 'MEDIUM').toLowerCase();
                if (sev in metrics) {
                    metrics[sev]++;
                }
            });
        }

        // Update DOM
        elements.metricCrit.textContent = metrics.critical;
        elements.metricHigh.textContent = metrics.high;
        elements.metricMed.textContent = metrics.medium;
        elements.metricLow.textContent = metrics.low;
        elements.metricTotal.textContent = metrics.total;
        
        // Sync metrics back to state
        if (state.data) {
            state.data.metrics = metrics;
        }
    }

    // Add Finding
    elements.addFindingBtn.addEventListener('click', () => {
        if (!state.data) return;
        
        const newVuln = {
            id: state.data.vulnerabilities.length + 1,
            severity: "MEDIUM",
            title: "New Vulnerability Finding",
            host: "N/A",
            port: "N/A",
            description: "Provide description detailing the vulnerability finding here.",
            remediation: "Provide recommended resolution steps here."
        };
        
        state.data.vulnerabilities.push(newVuln);
        renderFindingsTable();
        recalculateMetrics();
        
        // Scroll to bottom of table wrapper
        const wrapper = document.querySelector('.table-wrapper');
        wrapper.scrollTop = wrapper.scrollHeight;
    });

    elements.backToUploadBtn.addEventListener('click', () => {
        setStage(1);
    });

    // Go to Generation (Stage 3 -> Stage 4)
    elements.goToGenerateBtn.addEventListener('click', () => {
        // Collect current metadata
        if (state.data) {
            state.data.metadata = {
                client_name: elements.metaClient.value,
                scan_name: elements.metaScanName.value,
                scan_date: elements.metaScanDate.value,
                target_scope: elements.metaTarget.value,
                tester_name: elements.metaTester.value
            };
        }
        
        elements.pdfWarningAlert.style.display = 'none';
        setStage(4);
    });

    elements.backToReviewBtn.addEventListener('click', () => {
        setStage(3);
    });

    // --- STAGE 4: DOWNLOAD & COMPILE ---

    function triggerGeneration(format) {
        if (!state.jobId || !state.data) return;
        
        // Disable buttons & show loading feedback
        const activeBtn = format === 'word' ? elements.downloadWordBtn : elements.downloadPdfBtn;
        const originalHtml = activeBtn.innerHTML;
        activeBtn.disabled = true;
        activeBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Generating...`;

        const payload = {
            job_id: state.jobId,
            format: format,
            data: state.data
        };

        fetch('/api/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        })
        .then(response => {
            if (!response.ok) throw new Error("Compilation failed.");
            
            // Check headers to see if PDF failed and reverted to Word
            const pdfStatus = response.headers.get('X-PDF-Conversion-Status');
            if (pdfStatus === 'failed') {
                elements.pdfWarningAlert.style.display = 'flex';
            }
            
            // Extract filename from Content-Disposition header if possible
            let filename = `Vulnerability_Report.${format === 'word' ? 'docx' : 'pdf'}`;
            const disposition = response.headers.get('Content-Disposition');
            if (disposition && disposition.indexOf('attachment') !== -1) {
                const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                const matches = filenameRegex.exec(disposition);
                if (matches != null && matches[1]) { 
                    filename = matches[1].replace(/['"]/g, '');
                }
            }
            if (pdfStatus === 'failed') {
                // Rename filename to docx because it reverted
                filename = filename.replace('.pdf', '.docx');
            }
            
            return response.blob().then(blob => ({ blob, filename }));
        })
        .then(({ blob, filename }) => {
            // Initiate browser file download
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        })
        .catch(err => {
            alert(`Compilation error: ${err.message}`);
        })
        .finally(() => {
            activeBtn.disabled = false;
            activeBtn.innerHTML = originalHtml;
        });
    }

    elements.downloadWordBtn.addEventListener('click', () => {
        triggerGeneration('word');
    });

    elements.downloadPdfBtn.addEventListener('click', () => {
        triggerGeneration('pdf');
    });

    // Helper functions
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
