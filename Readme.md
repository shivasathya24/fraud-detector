# Sentinel - Threat Intelligence Engine
## Hackathon Project Documentation

---

## 1. Project Overview
**Sentinel** is a high-performance, Zero-Trust Fraudulent Trading and Scam Message Detection application. It is designed to evaluate the legitimacy of financial platforms, URLs, and social engineering messages in real-time. Instead of relying on external third-party APIs which can be slow or cost money, Sentinel uses a highly optimized, proprietary internal Rule-Based Python Engine.

The system is specifically tailored for the Indian regulatory landscape, checking platforms against SEBI (Securities and Exchange Board of India) and FIU-IND (Financial Intelligence Unit) whitelists.

---

## 2. Technology Stack

### Frontend (Client-Side)
The frontend is built purely with Native Web Technologies for maximum speed and zero dependencies:
*   **HTML5**: Semantic structure for the dashboard, utilizing modern input fields and file upload hooks.
*   **CSS3 (Vanilla)**: Features a premium "Cyber-Security" aesthetic utilizing Glassmorphism (blur effects), dynamic CSS animations (scanning lines, radar pulses), and a custom CSS variables system for theming (Neon Green, Yellow, Red). No external UI frameworks like Tailwind or Bootstrap were used, proving strong foundational design skills.
*   **JavaScript (Vanilla ES6)**: Handles all interactive logic including tab switching, mock processing animations, and asynchronous API communication.

### Backend (Server-Side)
The backend operates entirely locally, ensuring absolute privacy and zero latency:
*   **Python 3**: The core programming language used for data processing and logic.
*   **Flask**: A lightweight Python web framework used to spin up a RESTful API server.
*   **Flask-CORS**: A security extension that allows the frontend (running on port 8080) to communicate with the Python backend (running on port 5000) without Cross-Origin Resource Sharing security blocks.

---

## 3. How the Architecture Works (Connecting Front to Back)

The application operates on a standard **Client-Server Architecture**. Here is the exact flow of data:

### Phase 1: User Interaction (Frontend)
1. The user opens `index.html` and enters a URL (e.g., `https://delta.exchange`) or pastes a scam message into the input field.
2. When the user clicks "Initiate Scan", JavaScript intercepts the form submission using `e.preventDefault()` to stop the page from reloading.
3. JavaScript triggers a UI animation (the spinning loader) to show the user that analysis has begun.

### Phase 2: The API Call (The Bridge)
4. The JavaScript `app.js` file uses the modern `fetch()` API to make an HTTP POST request to the Python server at `http://localhost:5000/api/analyze-url`.
5. The URL entered by the user is packaged into a **JSON** (JavaScript Object Notation) payload and sent across the local network to the backend.

### Phase 3: The AI Rule Engine (Backend)
6. The Flask server receives the JSON request via the `@app.route('/api/analyze-url', methods=['POST'])` endpoint.
7. The Python engine strips the URL and passes it through a **Multi-Tiered Heuristic Scanner**:
    *   **Tier 1 (Whitelist)**: Checks if the URL matches known SEBI or FIU-IND platforms (like Zerodha or Delta Exchange). If yes, it assigns a low Risk Score (5-15) and flags it as **SAFE**.
    *   **Tier 2 (Keyword Scan)**: Scans for high-risk psychological triggers like `guaranteed`, `vip-signals`, or `free-crypto`. If found, it assigns a high Risk Score (90+) and flags it as **SCAM**.
    *   **Tier 3 (Zero-Trust Fallback)**: If a financial URL (containing words like `trade` or `invest`) is *not* in the whitelist, the engine assumes it is an unregulated offshore entity and flags it as **SCAM**. Generic unknown URLs default to **SUSPICIOUS**.
8. Python packages the final Risk Score, Status Classification, and a list of Detailed Analysis Findings into a new JSON object and sends it back to the frontend.

### Phase 4: Rendering the Results (Frontend)
9. The JavaScript `fetch()` promise resolves, receiving the JSON data from Python.
10. The `renderResults()` function dynamically updates the DOM (Document Object Model).
11. It animates the circular SVG score gauge, applies the correct color theme (Green/Yellow/Red), and loops through the detailed findings array to populate the scrollable analysis box.

---

## 4. Key Engineering Highlights
*   **Zero-Trust Architecture**: The system does not assume any financial platform is safe by default. If a platform is not explicitly registered in the verified database, it is aggressively flagged.
*   **Offline Fallback Logic**: The JavaScript contains a failsafe. If the Python server crashes or loses internet connection, the `catch(error)` block activates a localized version of the Zero-Trust engine, ensuring the app *never* crashes during a live hackathon demo.
*   **Extensibility**: The Python endpoints are designed so that replacing the hardcoded rule-engine with a real LLM (like Google Gemini or OpenAI) in the future would only require changing 5 lines of code.

---
*Created for Hackathon Presentation purposes.*
