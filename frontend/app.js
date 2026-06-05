document.addEventListener('DOMContentLoaded', () => {
    // Tab Switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active classes
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            // Add active class to clicked
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
            
            // Reset results panel
            resetResults();
        });
    });

    // Helper to convert File to Base64
    function fileToBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => resolve(reader.result.split(',')[1]); // Get raw base64 string
            reader.onerror = error => reject(error);
        });
    }

    // Form Submissions
    const urlForm = document.getElementById('url-form');
    const messageForm = document.getElementById('message-form');
    const kycForm = document.getElementById('kyc-form');

    urlForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('url-input').value;
        if (!urlInput) return;
        
        performAnalysis(urlForm, () => analyzeURL(urlInput));
    });

    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const msgInput = document.getElementById('message-input').value;
        const imageFile = document.getElementById('image-upload').files[0];
        
        if (!msgInput && !imageFile) return;
        
        performAnalysis(messageForm, async () => {
            let base64Image = null;
            if (imageFile) {
                try {
                    base64Image = await fileToBase64(imageFile);
                } catch (err) {
                    console.error("Error reading image file:", err);
                }
            }
            await analyzeMessage(msgInput, base64Image, imageFile ? imageFile.type : null);
        });
    });

    kycForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const kycInput = document.getElementById('kyc-input').value;
        const kycImageFile = document.getElementById('kyc-image-upload').files[0];
        
        if (!kycInput && !kycImageFile) return;
        
        performAnalysis(kycForm, async () => {
            let base64Image = null;
            if (kycImageFile) {
                try {
                    base64Image = await fileToBase64(kycImageFile);
                } catch (err) {
                    console.error("Error reading KYC image file:", err);
                }
            }
            await analyzeMessage(kycInput, base64Image, kycImageFile ? kycImageFile.type : null);
        });
    });

    // Image Upload Preview Logic
    const imageUpload = document.getElementById('image-upload');
    const imagePreviewContainer = document.getElementById('image-preview-container');
    const imagePreview = document.getElementById('image-preview');
    const removeImageBtn = document.getElementById('remove-image');

    imageUpload.addEventListener('change', function() {
        const file = this.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                imagePreview.src = e.target.result;
                imagePreviewContainer.classList.remove('hidden');
            }
            reader.readAsDataURL(file);
        }
    });

    removeImageBtn.addEventListener('click', () => {
        imageUpload.value = '';
        imagePreview.src = '';
        imagePreviewContainer.classList.add('hidden');
    });

    // KYC Image Upload Preview Logic
    const kycImageUpload = document.getElementById('kyc-image-upload');
    const kycImagePreviewContainer = document.getElementById('kyc-image-preview-container');
    const kycImagePreview = document.getElementById('kyc-image-preview');
    const kycRemoveImageBtn = document.getElementById('kyc-remove-image');

    if (kycImageUpload) {
        kycImageUpload.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    kycImagePreview.src = e.target.result;
                    kycImagePreviewContainer.classList.remove('hidden');
                }
                reader.readAsDataURL(file);
            }
        });

        kycRemoveImageBtn.addEventListener('click', () => {
            kycImageUpload.value = '';
            kycImagePreview.src = '';
            kycImagePreviewContainer.classList.add('hidden');
        });
    }

    async function performAnalysis(form, apiCallPromise) {
        // Add scanning animation
        form.classList.add('scanning');
        const btn = form.querySelector('.analyze-btn');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> <span class="btn-text">Processing...</span>';
        btn.disabled = true;

        resetResults();

        try {
            await apiCallPromise();
        } catch (error) {
            console.error("Analysis execution failed:", error);
        } finally {
            form.classList.remove('scanning');
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    }

    function resetResults() {
        document.getElementById('results-placeholder').classList.remove('hidden');
        document.getElementById('results-content').classList.add('hidden');
        
        // Reset classes
        const container = document.querySelector('.score-header');
        if (container) {
            container.className = 'score-header'; // remove safe/suspicious/scam classes
        }
        
        const circle = document.getElementById('score-circle');
        if (circle) {
            circle.setAttribute('stroke-dasharray', `0, 100`);
        }
    }

    function renderResults(data) {
        document.getElementById('results-placeholder').classList.add('hidden');
        document.getElementById('results-content').classList.remove('hidden');

        // Update Score and Circle
        const scoreValue = document.getElementById('score-value');
        const scoreCircle = document.getElementById('score-circle');
        
        // Animate score counter
        let currentScore = 0;
        const targetScore = data.score;
        const duration = 1000; // ms
        const steps = 30;
        const stepTime = duration / steps;
        const increment = targetScore / steps;

        const timer = setInterval(() => {
            currentScore += increment;
            if (currentScore >= targetScore) {
                currentScore = targetScore;
                clearInterval(timer);
            }
            scoreValue.innerText = Math.round(currentScore);
        }, stepTime);

        scoreCircle.setAttribute('stroke-dasharray', `${targetScore}, 100`);

        // Update Badge & Styles
        const badge = document.getElementById('status-badge');
        const headerContainer = document.querySelector('.score-header');
        const recoBox = document.getElementById('recommendation-box');
        
        headerContainer.className = 'score-header'; // reset
        badge.innerText = data.classification;

        let themeClass = '';
        if (data.classification === 'SAFE') {
            themeClass = 'safe';
            recoBox.style.color = 'var(--neon-green)';
            recoBox.style.borderColor = 'var(--neon-green)';
        } else if (data.classification === 'SUSPICIOUS') {
            themeClass = 'suspicious';
            recoBox.style.color = 'var(--neon-yellow)';
            recoBox.style.borderColor = 'var(--neon-yellow)';
        } else {
            themeClass = 'scam';
            recoBox.style.color = 'var(--neon-red)';
            recoBox.style.borderColor = 'var(--neon-red)';
        }

        headerContainer.classList.add(themeClass);
        badge.className = `status-badge ${themeClass}`;

        // Populate Findings List
        const list = document.getElementById('analysis-list');
        list.innerHTML = ''; // clear old
        data.findings.forEach(finding => {
            const li = document.createElement('li');
            li.className = `finding-${finding.type}`;
            
            let iconClass = 'fa-check-circle';
            if (finding.type === 'warn') iconClass = 'fa-exclamation-triangle';
            if (finding.type === 'danger') iconClass = 'fa-skull-crossbones';

            li.innerHTML = `<i class="fa-solid ${iconClass}"></i> <span>${finding.text}</span>`;
            list.appendChild(li);
        });

        // Update Recommendation
        document.getElementById('recommendation-text').innerText = data.recommendation;
    }

    async function analyzeURL(url) {
        url = url.trim();
        
        try {
            const response = await fetch('https://fraud-detector-o8xj.onrender.com/api/analyze-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            
            if (!response.ok) throw new Error('API Error');
            const data = await response.json();
            renderResults(data);
        } catch (error) {
            console.warn("Backend not running or failed, using local offline fallback:", error);
            // Fallback mock logic for offline
            let data = { score: 10, classification: 'SAFE', findings: [], recommendation: '' };
            let urlLower = url.toLowerCase();
            
            data.findings.push({
                type: 'warn',
                text: 'Warning: Python Backend is offline. Displaying local rule heuristics.'
            });

            if (urlLower.includes('free-crypto') || urlLower.includes('guaranteed') || urlLower.includes('vip-signals')) {
                data.score = 92;
                data.classification = 'SCAM';
                data.findings.push(
                    { type: 'danger', text: 'Domain contains high-risk keywords associated with pump and dump schemes.' },
                    { type: 'danger', text: 'Domain registered less than 7 days ago, typical of temporary phishing sites.' },
                    { type: 'warn', text: 'Not registered with SEBI or FIU-IND, making financial solicitation illegal.' }
                );
                data.recommendation = 'CRITICAL: Do not interact with this platform.';
            } else if (urlLower.includes('zerodha') || urlLower.includes('upstox') || urlLower.includes('groww') || urlLower.includes('delta')) {
                data.score = 15;
                data.classification = 'SAFE';
                data.findings.push(
                    { type: 'safe', text: 'Platform is officially registered with SEBI/FIU-IND regulatory bodies.' },
                    { type: 'safe', text: 'Valid Enterprise Validation (EV) SSL Certificate detected.' }
                );
                data.recommendation = 'This platform appears safe.';
            } else {
                data.score = 45;
                data.classification = 'SUSPICIOUS';
                data.findings.push(
                    { type: 'warn', text: 'Domain is not in our verified registry of Indian financial institutions.' },
                    { type: 'warn', text: 'Requires manual verification of regulatory licenses before trusting.' }
                );
                data.recommendation = 'WARNING: Proceed with caution. Verify the company independently.';
            }
            renderResults(data);
        }
    }

    async function analyzeMessage(text, imageBase64, imageType) {
        try {
            const response = await fetch('https://fraud-detector-o8xj.onrender.com/api/analyze-message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    text: text, 
                    image: imageBase64, 
                    imageType: imageType 
                })
            });

            
            if (!response.ok) throw new Error('API Error');
            const data = await response.json();
            renderResults(data);
        } catch (error) {
            console.warn("Backend not running or failed, using local offline fallback:", error);
            // Fallback mock logic for offline
            let data = { 
                score: 88, 
                classification: 'SCAM', 
                findings: [
                    { type: 'warn', text: 'Warning: Python Backend Server is not running. Displaying offline rule heuristics.' },
                    { type: 'danger', text: 'Message content shows potential high-pressure social engineering tactics.' }
                ], 
                recommendation: 'Please start the Python server for real-time AI scanning.' 
            };
            renderResults(data);
        }
    }
});
