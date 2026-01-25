package firewall

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ChallengeResponse represents a challenge response from the firewall
type ChallengeResponse struct {
	Blocked    bool
	StatusCode int
	Headers    map[string]string
	Body       string
}

type ChallengeManager struct {
	mu           sync.RWMutex
	cookieSecret string
	jsSecret     string
	captchaCache map[string]*CaptchaData
	stopChan     chan struct{}
	template     *template.Template
}

type CaptchaData struct {
	ID        string
	Answer    string
	ImageData string
	ExpiresAt time.Time
}

// Template data structure for challenge pages
type ChallengeTemplateData struct {
	Title           string
	Message         string
	IsError         bool
	ShowLoader      bool
	ShowProgress    bool
	StatusMessage   string
	CaptchaData     *CaptchaData
	ShowRetryButton bool
	RayID           string
	ClientIP        string
	AgentID         string
	ActionURL       string
	JSCode          template.JS
}

var globalChallengeManager *ChallengeManager

func init() {
	globalChallengeManager = NewChallengeManager()
}

func NewChallengeManager() *ChallengeManager {
	// Try multiple paths for the template file
	templatePaths := []string{
		"assets/html/challenge_template.html",
		"./assets/html/challenge_template.html",
		"/opt/defenra-agent/assets/html/challenge_template.html",
		"/usr/local/bin/assets/html/challenge_template.html",
	}

	var tmpl *template.Template
	var err error

	// Try to load template from file
	for _, path := range templatePaths {
		tmpl, err = template.ParseFiles(path)
		if err == nil {
			break
		}
	}

	// If all file paths fail, use embedded template
	if err != nil {
		tmpl = template.Must(template.New("challenge").Parse(getEmbeddedTemplate()))
	}

	cm := &ChallengeManager{
		cookieSecret: generateSecret(),
		jsSecret:     generateSecret(),
		captchaCache: make(map[string]*CaptchaData),
		stopChan:     make(chan struct{}),
		template:     tmpl,
	}

	go cm.cleanup()
	return cm
}

func GetChallengeManager() *ChallengeManager {
	return globalChallengeManager
}

// Cookie Challenge (Stage 1)
func (cm *ChallengeManager) IssueCookieChallenge(w http.ResponseWriter, r *http.Request, clientIP string) ChallengeResponse {
	// Generate verification cookie
	accessKey := fmt.Sprintf("%s_%s_%s_%d", clientIP, r.UserAgent(), r.Host, time.Now().Hour())
	verificationCookie := cm.generateVerificationCookie(accessKey)

	// Set cookie
	cookie := &http.Cookie{
		Name:     "__defenra_v",
		Value:    verificationCookie,
		Path:     "/",
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	rayID := generateRayID()

	// For testing or simple cases, use direct redirect
	// In production, we might want to use the HTML template approach
	if w == nil {
		// Testing mode - return simple redirect
		return ChallengeResponse{
			Blocked:    true,
			StatusCode: http.StatusFound,
			Headers: map[string]string{
				"Set-Cookie":    cookie.String(),
				"Location":      r.RequestURI,
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
			},
			Body: "Redirecting...",
		}
	}

	// Create a loading page that will redirect after cookie is set
	redirectScript := fmt.Sprintf(`
		document.cookie = '%s';
		setTimeout(function() {
			window.location.href = '%s';
		}, 1500);
	`, cookie.String(), r.RequestURI)

	data := ChallengeTemplateData{
		Title:      "Проверка безопасности",
		Message:    "Проверяем безопасность вашего соединения. Пожалуйста, подождите...",
		ShowLoader: true,
		RayID:      rayID,
		ClientIP:   clientIP,
		AgentID:    getShortAgentID(),
		JSCode:     template.JS(redirectScript),
	}

	var buf bytes.Buffer
	if err := cm.template.Execute(&buf, data); err != nil {
		// Fallback to simple redirect if template fails
		return ChallengeResponse{
			Blocked:    true,
			StatusCode: http.StatusFound,
			Headers: map[string]string{
				"Set-Cookie":    cookie.String(),
				"Location":      r.RequestURI,
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
			},
			Body: "Redirecting...",
		}
	}

	return ChallengeResponse{
		Blocked:    true,
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Set-Cookie":    cookie.String(),
			"Content-Type":  "text/html; charset=utf-8",
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
		},
		Body: buf.String(),
	}
}

func (cm *ChallengeManager) ValidateCookieChallenge(r *http.Request, clientIP string) bool {
	cookie, err := r.Cookie("__defenra_v")
	if err != nil {
		return false
	}

	accessKey := fmt.Sprintf("%s_%s_%s_%d", clientIP, r.UserAgent(), r.Host, time.Now().Hour())
	expectedCookie := cm.generateVerificationCookie(accessKey)

	isValid := cookie.Value == expectedCookie

	// If cookie challenge is valid, clear violations for this IP
	if isValid {
		violationTracker := GetViolationTracker()
		violationTracker.ClearViolations(clientIP)
		log.Printf("[Challenge] Cookie challenge passed, cleared violations for IP: %s", clientIP)
	}

	return isValid
}

// JavaScript PoW Challenge (Stage 2)
func (cm *ChallengeManager) IssueJSChallenge(w http.ResponseWriter, r *http.Request, clientIP string, difficulty int) ChallengeResponse {
	// Generate challenge parameters
	publicSalt := generateRandomString(16)
	target := strings.Repeat("0", difficulty)
	rayID := generateRayID()

	// Create heavily obfuscated JavaScript
	obfuscator := NewSimpleJSObfuscator()
	obfuscatedScript := obfuscator.ObfuscatePoWScript(publicSalt, target)

	data := ChallengeTemplateData{
		Title:         "Проверка браузера",
		Message:       "Пожалуйста, подождите. Мы проверяем безопасность вашего соединения перед доступом к сайту.",
		ShowLoader:    true,
		ShowProgress:  true,
		StatusMessage: "Вычисление доказательства работы...",
		RayID:         rayID,
		ClientIP:      clientIP,
		AgentID:       getShortAgentID(),
		JSCode:        template.JS(obfuscatedScript),
	}

	var buf bytes.Buffer
	if err := cm.template.Execute(&buf, data); err != nil {
		// Fallback to simple HTML if template fails
		return cm.fallbackJSChallenge(publicSalt, target, clientIP, rayID)
	}

	return ChallengeResponse{
		Blocked:    true,
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":  "text/html; charset=utf-8",
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
		},
		Body: buf.String(),
	}
}

func (cm *ChallengeManager) ValidateJSChallenge(r *http.Request, difficulty int) bool {
	if r.Method != "POST" {
		return false
	}

	nonce := r.FormValue("defenra_pow_nonce")
	salt := r.FormValue("defenra_pow_salt")

	if nonce == "" || salt == "" {
		return false
	}

	// Verify the proof of work
	input := salt + nonce
	hash := sha256Hash(input)
	target := strings.Repeat("0", difficulty)

	isValid := strings.HasPrefix(hash, target)

	// If JS challenge is valid, clear violations for this IP
	if isValid {
		clientIP := getClientIP(r)
		if clientIP != "" {
			violationTracker := GetViolationTracker()
			violationTracker.ClearViolations(clientIP)
			log.Printf("[Challenge] JS PoW solved successfully, cleared violations for IP: %s", clientIP)
		}
	}

	return isValid
}

// CAPTCHA Challenge (Stage 3)
func (cm *ChallengeManager) IssueCaptchaChallenge(w http.ResponseWriter, r *http.Request, clientIP string) ChallengeResponse {
	// Generate CAPTCHA
	captchaID := generateRandomString(8)
	captchaData := cm.generateCaptcha(captchaID)

	cm.mu.Lock()
	cm.captchaCache[captchaID] = captchaData
	cm.mu.Unlock()

	rayID := generateRayID()

	// Add obfuscated CAPTCHA validation script
	obfuscator := NewSimpleJSObfuscator()
	captchaScript := obfuscator.ObfuscateCaptchaScript()

	data := ChallengeTemplateData{
		Title:       "Проверка безопасности",
		Message:     "Пожалуйста, введите текст с изображения для подтверждения, что вы человек.",
		CaptchaData: captchaData,
		RayID:       rayID,
		ClientIP:    clientIP,
		AgentID:     getShortAgentID(),
		ActionURL:   r.RequestURI,
		JSCode:      template.JS(captchaScript),
	}

	var buf bytes.Buffer
	if err := cm.template.Execute(&buf, data); err != nil {
		// Fallback to simple HTML if template fails
		return cm.fallbackCaptchaChallenge(captchaData, r.RequestURI, clientIP, rayID)
	}

	return ChallengeResponse{
		Blocked:    true,
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":  "text/html; charset=utf-8",
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
		},
		Body: buf.String(),
	}
}

// Error page for origin server issues
func (cm *ChallengeManager) IssueErrorPage(w http.ResponseWriter, r *http.Request, clientIP string, errorCode int, errorMessage string) ChallengeResponse {
	rayID := generateRayID()

	var title, message string
	switch errorCode {
	case 502:
		title = "Ошибка соединения (502)"
		message = "Не удалось соединиться с сервером источника. Возможно, сервер перегружен или находится на техническом обслуживании."
	case 503:
		title = "Сервис недоступен (503)"
		message = "Сервер временно недоступен из-за перегрузки или технического обслуживания. Попробуйте позже."
	case 504:
		title = "Превышено время ожидания (504)"
		message = "Сервер не ответил в течение установленного времени. Попробуйте обновить страницу."
	default:
		title = fmt.Sprintf("Ошибка сервера (%d)", errorCode)
		message = errorMessage
	}

	data := ChallengeTemplateData{
		Title:           title,
		Message:         message,
		IsError:         true,
		ShowRetryButton: true,
		RayID:           rayID,
		ClientIP:        clientIP,
		AgentID:         getShortAgentID(),
	}

	var buf bytes.Buffer
	if err := cm.template.Execute(&buf, data); err != nil {
		// Fallback to simple HTML if template fails
		return ChallengeResponse{
			Blocked:    true,
			StatusCode: errorCode,
			Headers: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
			Body: fmt.Sprintf("<html><body><h1>%s</h1><p>%s</p></body></html>", title, message),
		}
	}

	return ChallengeResponse{
		Blocked:    true,
		StatusCode: errorCode,
		Headers: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		Body: buf.String(),
	}
}

func (cm *ChallengeManager) ValidateCaptchaChallenge(r *http.Request) bool {
	if r.Method != "POST" {
		return false
	}

	captchaID := r.FormValue("captcha_id")
	answer := strings.ToLower(strings.TrimSpace(r.FormValue("captcha_answer")))

	if captchaID == "" || answer == "" {
		return false
	}

	cm.mu.RLock()
	captchaData, exists := cm.captchaCache[captchaID]
	cm.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(captchaData.ExpiresAt) {
		cm.mu.Lock()
		delete(cm.captchaCache, captchaID)
		cm.mu.Unlock()
		return false
	}

	// Clean up used CAPTCHA
	cm.mu.Lock()
	delete(cm.captchaCache, captchaID)
	cm.mu.Unlock()

	isValid := answer == strings.ToLower(captchaData.Answer)

	// If CAPTCHA is valid, clear violations for this IP
	if isValid {
		clientIP := getClientIP(r)
		if clientIP != "" {
			violationTracker := GetViolationTracker()
			violationTracker.ClearViolations(clientIP)
			log.Printf("[Challenge] CAPTCHA solved successfully, cleared violations for IP: %s", clientIP)
		}
	}

	return isValid
}

// Helper functions
func (cm *ChallengeManager) generateVerificationCookie(accessKey string) string {
	hash := sha256.Sum256([]byte(accessKey + cm.cookieSecret))
	return hex.EncodeToString(hash[:])[:16]
}

func (cm *ChallengeManager) generateCaptcha(captchaID string) *CaptchaData {
	// Generate random text (numbers and letters for better readability)
	answer := generateCaptchaText(5)

	// Create larger CAPTCHA image with better visibility
	img := image.NewRGBA(image.Rect(0, 0, 300, 120))

	// Fill background with dark theme
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{24, 24, 27, 255}}, image.Point{}, draw.Src)

	// Add noise and distortion to prevent OCR
	addNoise(img)

	// Draw text manually with larger size and distortion
	textColor := color.RGBA{228, 228, 231, 255} // Light gray text

	// Draw each character with random positioning and rotation
	for i, char := range answer {
		baseX := 40 + i*45
		baseY := 40

		// Add random offset for distortion
		offsetX := (i*17+int(char))%15 - 7 // Random offset -7 to +7
		offsetY := (i*23+int(char))%10 - 5 // Random offset -5 to +5

		x := baseX + offsetX
		y := baseY + offsetY

		// Draw character with larger scale
		drawLargeChar(img, char, x, y, textColor)
	}

	// Add more distortion lines
	addDistortionLines(img)

	// Convert to base64
	var buf bytes.Buffer
	png.Encode(&buf, img)
	imageData := base64.StdEncoding.EncodeToString(buf.Bytes())

	return &CaptchaData{
		ID:        captchaID,
		Answer:    answer,
		ImageData: imageData,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func (cm *ChallengeManager) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cm.mu.Lock()
			now := time.Now()
			for id, data := range cm.captchaCache {
				if now.After(data.ExpiresAt) {
					delete(cm.captchaCache, id)
				}
			}
			cm.mu.Unlock()

		case <-cm.stopChan:
			return
		}
	}
}

func (cm *ChallengeManager) Stop() {
	close(cm.stopChan)
}

// Fallback methods for when template fails
func (cm *ChallengeManager) fallbackJSChallenge(publicSalt, target, clientIP, rayID string) ChallengeResponse {
	jsChallenge := fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Проверка браузера</title>
    <style>
        :root {
            --bg-color: #09090b;
            --card-bg: #18181b;
            --border-color: #27272a;
            --text-main: #e4e4e7;
            --text-muted: #a1a1aa;
            --accent-blue: #3b82f6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background-image: 
                linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 30px 30px;
        }
        .container { width: 100%%; max-width: 480px; padding: 20px; }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px 32px;
            text-align: center;
            box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-blue), transparent);
            opacity: 0.8;
        }
        .loader-container {
            position: relative;
            width: 64px;
            height: 64px;
            margin: 0 auto 24px auto;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .radar-spinner {
            width: 100%%;
            height: 100%%;
            border-radius: 50%%;
            border: 2px solid var(--border-color);
            border-top-color: var(--accent-blue);
            animation: spin 1.2s cubic-bezier(0.55, 0.055, 0.675, 0.19) infinite;
        }
        .radar-pulse {
            position: absolute;
            width: 100%%;
            height: 100%%;
            border-radius: 50%%;
            background: var(--accent-blue);
            opacity: 0.2;
            animation: pulse 2s ease-out infinite;
        }
        .progress-container {
            width: 100%%;
            background-color: var(--border-color);
            border-radius: 4px;
            margin: 20px 0;
            height: 8px;
            overflow: hidden;
        }
        .progress-bar {
            height: 100%%;
            background: linear-gradient(90deg, var(--accent-blue), #60a5fa);
            border-radius: 4px;
            width: 0%%;
            transition: width 0.3s ease;
        }
        .tech-info {
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
            font-size: 11px;
            color: #52525b;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .info-row { display: flex; justify-content: space-between; }
        .info-label { opacity: 0.7; }
        .info-value { color: var(--text-muted); }
        h1 { font-size: 20px; font-weight: 600; margin-bottom: 12px; letter-spacing: -0.02em; }
        p { font-size: 14px; line-height: 1.6; color: var(--text-muted); margin-bottom: 24px; }
        .status-message { font-size: 12px; color: var(--text-muted); margin: 8px 0; font-family: monospace; }
        @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
        @keyframes pulse { 0%% { transform: scale(0.8); opacity: 0.5; } 100%% { transform: scale(1.5); opacity: 0; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="loader-container">
                <div class="radar-pulse"></div>
                <div class="radar-spinner"></div>
            </div>
            <h1>Проверка браузера</h1>
            <p>Пожалуйста, подождите. Мы проверяем безопасность вашего соединения перед доступом к сайту.</p>
            <div class="progress-container">
                <div class="progress-bar" id="progressBar"></div>
            </div>
            <div class="status-message" id="statusMessage">Вычисление доказательства работы...</div>
            <div class="tech-info">
                <div class="info-row">
                    <span class="info-label">Ray ID:</span>
                    <span class="info-value">%s</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Your IP:</span>
                    <span class="info-value">%s</span>
                </div>
                <div class="info-row">
                    <span class="info-label">System:</span>
                    <span class="info-value">Defenra Shield</span>
                </div>
            </div>
        </div>
    </div>
    <script>
        const publicSalt='%s';const target='%s';let nonce=0;
        async function solve(){
            while(true){
                const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(publicSalt+nonce))
                    .then(b=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join(''));
                if(hash.startsWith(target)){
                    const statusMsg=document.getElementById('statusMessage');
                    const progressBar=document.getElementById('progressBar');
                    if(statusMsg)statusMsg.textContent='Доказательство работы завершено! Перенаправление...';
                    if(progressBar)progressBar.style.width='100%%';
                    const f=document.createElement('form');
                    f.method='POST';
                    f.innerHTML='<input name="defenra_pow_nonce" value="'+nonce+'"><input name="defenra_pow_salt" value="'+publicSalt+'">';
                    document.body.appendChild(f);
                    f.submit();
                    return;
                }
                nonce++;
                if(nonce%%1000===0){
                    const progress=Math.min((nonce/100000)*100,95);
                    const progressBar=document.getElementById('progressBar');
                    if(progressBar)progressBar.style.width=progress+'%%';
                    await new Promise(r=>setTimeout(r,1));
                }
            }
        }
        setTimeout(solve,100);
    </script>
</body>
</html>`, rayID, clientIP, publicSalt, target)

	return ChallengeResponse{
		Blocked:    true,
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":  "text/html; charset=utf-8",
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
		},
		Body: jsChallenge,
	}
}

func (cm *ChallengeManager) fallbackCaptchaChallenge(captchaData *CaptchaData, actionURL, clientIP, rayID string) ChallengeResponse {
	captchaHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Проверка безопасности</title>
    <style>
        :root {
            --bg-color: #09090b;
            --card-bg: #18181b;
            --border-color: #27272a;
            --text-main: #e4e4e7;
            --text-muted: #a1a1aa;
            --accent-blue: #3b82f6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background-image: 
                linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 30px 30px;
        }
        .container { width: 100%%; max-width: 480px; padding: 20px; }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px 32px;
            text-align: center;
            box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-blue), transparent);
            opacity: 0.8;
        }
        .captcha-container {
            position: relative;
            display: inline-block;
            margin: 20px 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        .captcha-image { display: block; max-width: 100%%; }
        .captcha-input {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 14px;
            margin: 16px 0;
            width: 200px;
            text-align: center;
            font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
            letter-spacing: 2px;
        }
        .captcha-input:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15);
        }
        .action-btn {
            background: var(--accent-blue);
            border: 1px solid var(--accent-blue);
            color: white;
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
            margin: 8px;
        }
        .action-btn:hover {
            background: #2563eb;
            border-color: #2563eb;
        }
        .tech-info {
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
            font-size: 11px;
            color: #52525b;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .info-row { display: flex; justify-content: space-between; }
        .info-label { opacity: 0.7; }
        .info-value { color: var(--text-muted); }
        h1 { font-size: 20px; font-weight: 600; margin-bottom: 12px; letter-spacing: -0.02em; }
        p { font-size: 14px; line-height: 1.6; color: var(--text-muted); margin-bottom: 24px; }
        form { margin: 0; }
        @media (max-width: 480px) {
            .container { padding: 16px; }
            .card { padding: 24px 20px; }
            .captcha-input { width: 100%%; max-width: 200px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Проверка безопасности</h1>
            <p>Пожалуйста, введите текст с изображения для подтверждения, что вы человек.</p>
            <div class="captcha-container">
                <img src="data:image/png;base64,%s" alt="CAPTCHA" class="captcha-image">
            </div>
            <form method="POST" action="%s">
                <input type="hidden" name="captcha_id" value="%s">
                <input type="text" name="captcha_answer" placeholder="Введите текст с картинки" 
                       autocomplete="off" required class="captcha-input" maxlength="6">
                <br>
                <button type="submit" class="action-btn">Проверить</button>
            </form>
            <p style="font-size: 12px; margin-top: 16px;">
                <a href="javascript:location.reload()" style="color: var(--text-muted); text-decoration: none;">
                    Не видите изображение? Обновить страницу
                </a>
            </p>
            <div class="tech-info">
                <div class="info-row">
                    <span class="info-label">Ray ID:</span>
                    <span class="info-value">%s</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Your IP:</span>
                    <span class="info-value">%s</span>
                </div>
                <div class="info-row">
                    <span class="info-label">System:</span>
                    <span class="info-value">Defenra Shield</span>
                </div>
            </div>
        </div>
    </div>
    <script>
        var captchaInput=document.querySelector('input[name="captcha_answer"]');
        if(captchaInput){
            captchaInput.addEventListener('input',function(){
                this.value=this.value.toUpperCase().replace(/[^A-Z0-9]/g,'');
            });
            captchaInput.addEventListener('keypress',function(e){
                if(e.keyCode===13){
                    var form=this.closest('form');
                    if(form)form.submit();
                }
            });
        }
    </script>
</body>
</html>`, captchaData.ImageData, actionURL, captchaData.ID, rayID, clientIP)

	return ChallengeResponse{
		Blocked:    true,
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":  "text/html; charset=utf-8",
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
		},
		Body: captchaHTML,
	}
}

// Utility functions
func generateSecret() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateRandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[num.Int64()]
	}
	return string(result)
}

func generateCaptchaText(length int) string {
	// Use more readable characters for CAPTCHA
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	result := make([]byte, length)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[num.Int64()]
	}
	return string(result)
}

func generateRayID() string {
	bytes := make([]byte, 6)
	rand.Read(bytes)
	return strings.ToUpper(hex.EncodeToString(bytes))
}

func getShortAgentID() string {
	// Get the global config manager and extract agent ID
	// This is a simplified approach - in production, we'd pass the config manager
	// For now, return a placeholder that matches the D-Agent-ID format
	return "DEF-" + generateRandomString(4)
}

func sha256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// Embedded template fallback
func getEmbeddedTemplate() string {
	return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        :root {
            /* Палитра (Dark Zinc/Slate style) */
            --bg-color: #09090b;
            --card-bg: #18181b;
            --border-color: #27272a;
            --text-main: #e4e4e7;
            --text-muted: #a1a1aa;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-glow: rgba(59, 130, 246, 0.15);
            --font-stack: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: var(--font-stack);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            /* Тонкая сетка на фоне для технического вида */
            background-image: 
                linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 30px 30px;
        }

        .container {
            width: 100%;
            max-width: 480px;
            padding: 20px;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px 32px;
            text-align: center;
            box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }

        /* Декоративная полоса сверху */
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-blue), transparent);
            opacity: 0.8;
            transition: background 0.3s ease;
        }

        /* Состояние ошибки меняет цвет полосы */
        .card.error-state::before {
            background: linear-gradient(90deg, transparent, var(--accent-red), transparent);
        }

        /* --- Анимация Радара (Loader) --- */
        .loader-container {
            position: relative;
            width: 64px;
            height: 64px;
            margin: 0 auto 24px auto;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .radar-spinner {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            border: 2px solid var(--border-color);
            border-top-color: var(--accent-blue);
            animation: spin 1.2s cubic-bezier(0.55, 0.055, 0.675, 0.19) infinite;
        }

        .radar-pulse {
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: var(--accent-blue);
            opacity: 0.2;
            animation: pulse 2s ease-out infinite;
        }

        /* --- Иконка ошибки (Скрыта по умолчанию) --- */
        .error-icon {
            display: none;
            width: 64px;
            height: 64px;
            margin: 0 auto 24px auto;
            color: var(--accent-red);
        }

        .error-icon svg {
            width: 100%;
            height: 100%;
        }

        /* --- Progress Bar --- */
        .progress-container {
            width: 100%;
            background-color: var(--border-color);
            border-radius: 4px;
            margin: 20px 0;
            height: 8px;
            overflow: hidden;
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--accent-blue), #60a5fa);
            border-radius: 4px;
            width: 0%;
            transition: width 0.3s ease;
        }

        /* --- CAPTCHA Styles --- */
        .captcha-container {
            position: relative;
            display: inline-block;
            margin: 20px 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }

        .captcha-image {
            display: block;
            max-width: 100%;
        }

        .captcha-input {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 14px;
            margin: 16px 0;
            width: 200px;
            text-align: center;
            font-family: var(--font-mono);
            letter-spacing: 2px;
        }

        .captcha-input:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 2px var(--accent-glow);
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes pulse {
            0% { transform: scale(0.8); opacity: 0.5; }
            100% { transform: scale(1.5); opacity: 0; }
        }

        h1 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 12px;
            letter-spacing: -0.02em;
        }

        p {
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-muted);
            margin-bottom: 24px;
        }

        /* --- Техническая информация (Footer) --- */
        .tech-info {
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            font-family: var(--font-mono);
            font-size: 11px;
            color: #52525b; /* Еще более приглушенный цвет */
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
        }

        .info-label { 
            opacity: 0.7; 
        }
        
        .info-value { 
            color: var(--text-muted); 
        }

        /* --- Кнопка (для капчи или ретрая) --- */
        .action-btn {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
            margin: 8px;
        }

        .action-btn:hover {
            border-color: var(--text-muted);
            background: rgba(255,255,255,0.03);
        }

        .action-btn.primary {
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: white;
        }

        .action-btn.primary:hover {
            background: #2563eb;
            border-color: #2563eb;
        }

        /* --- Form Styles --- */
        form {
            margin: 0;
        }

        /* --- Status Messages --- */
        .status-message {
            font-size: 12px;
            color: var(--text-muted);
            margin: 8px 0;
            font-family: var(--font-mono);
        }

        /* --- Responsive --- */
        @media (max-width: 480px) {
            .container {
                padding: 16px;
            }
            
            .card {
                padding: 24px 20px;
            }
            
            .captcha-input {
                width: 100%;
                max-width: 200px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card{{if .IsError}} error-state{{end}}" id="statusCard">
            {{if .IsError}}
                <!-- Режим ошибки -->
                <div class="error-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" />
                    </svg>
                </div>
            {{else if .ShowLoader}}
                <!-- Режим проверки/загрузки -->
                <div class="loader-container">
                    <div class="radar-pulse"></div>
                    <div class="radar-spinner"></div>
                </div>
            {{end}}

            <h1>{{.Title}}</h1>
            <p>{{.Message}}</p>

            {{if .ShowProgress}}
                <div class="progress-container">
                    <div class="progress-bar" id="progressBar"></div>
                </div>
                <div class="status-message" id="statusMessage">{{.StatusMessage}}</div>
            {{end}}

            {{if .CaptchaData}}
                <!-- CAPTCHA Challenge -->
                <div class="captcha-container">
                    <img src="data:image/png;base64,{{.CaptchaData.ImageData}}" alt="CAPTCHA" class="captcha-image">
                </div>
                
                <form method="POST" action="{{.ActionURL}}">
                    <input type="hidden" name="captcha_id" value="{{.CaptchaData.ID}}">
                    <input type="text" name="captcha_answer" placeholder="Введите текст с картинки" 
                           autocomplete="off" required class="captcha-input" maxlength="6">
                    <br>
                    <button type="submit" class="action-btn primary">Проверить</button>
                </form>
                
                <p style="font-size: 12px; margin-top: 16px;">
                    <a href="javascript:location.reload()" style="color: var(--text-muted); text-decoration: none;">
                        Не видите изображение? Обновить страницу
                    </a>
                </p>
            {{end}}

            {{if .ShowRetryButton}}
                <button id="retryBtn" class="action-btn" onclick="window.location.reload()">
                    Повторить попытку
                </button>
            {{end}}

            <div class="tech-info">
                <div class="info-row">
                    <span class="info-label">Ray ID:</span>
                    <span class="info-value">{{.RayID}}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Your IP:</span>
                    <span class="info-value">{{.ClientIP}}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">System:</span>
                    <span class="info-value">Defenra Shield</span>
                </div>
                {{if .AgentID}}
                <div class="info-row">
                    <span class="info-label">Agent:</span>
                    <span class="info-value">{{.AgentID}}</span>
                </div>
                {{end}}
            </div>
        </div>
    </div>

    {{if .JSCode}}
    <script>
        {{.JSCode}}
    </script>
    {{end}}
</body>
</html>`
}

// Simple character drawing function for CAPTCHA
func drawSimpleChar(img *image.RGBA, char rune, x, y int, c color.RGBA) {
	// Simple 5x7 pixel patterns for characters
	patterns := map[rune][]string{
		'A': {
			" ### ",
			"#   #",
			"#   #",
			"#####",
			"#   #",
			"#   #",
			"     ",
		},
		'B': {
			"#### ",
			"#   #",
			"#### ",
			"#### ",
			"#   #",
			"#### ",
			"     ",
		},
		'C': {
			" ####",
			"#    ",
			"#    ",
			"#    ",
			"#    ",
			" ####",
			"     ",
		},
		'D': {
			"#### ",
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			"#### ",
			"     ",
		},
		'E': {
			"#####",
			"#    ",
			"#### ",
			"#    ",
			"#    ",
			"#####",
			"     ",
		},
		'F': {
			"#####",
			"#    ",
			"#### ",
			"#    ",
			"#    ",
			"#    ",
			"     ",
		},
		'G': {
			" ####",
			"#    ",
			"# ###",
			"#   #",
			"#   #",
			" ####",
			"     ",
		},
		'H': {
			"#   #",
			"#   #",
			"#####",
			"#   #",
			"#   #",
			"#   #",
			"     ",
		},
		'J': {
			"  ###",
			"    #",
			"    #",
			"    #",
			"#   #",
			" ### ",
			"     ",
		},
		'K': {
			"#   #",
			"#  # ",
			"# #  ",
			"##   ",
			"# #  ",
			"#  ##",
			"     ",
		},
		'L': {
			"#    ",
			"#    ",
			"#    ",
			"#    ",
			"#    ",
			"#####",
			"     ",
		},
		'M': {
			"#   #",
			"## ##",
			"# # #",
			"#   #",
			"#   #",
			"#   #",
			"     ",
		},
		'N': {
			"#   #",
			"##  #",
			"# # #",
			"#  ##",
			"#   #",
			"#   #",
			"     ",
		},
		'P': {
			"#### ",
			"#   #",
			"#### ",
			"#    ",
			"#    ",
			"#    ",
			"     ",
		},
		'Q': {
			" ### ",
			"#   #",
			"#   #",
			"# # #",
			"#  ##",
			" ####",
			"     ",
		},
		'R': {
			"#### ",
			"#   #",
			"#### ",
			"# #  ",
			"#  # ",
			"#   #",
			"     ",
		},
		'S': {
			" ####",
			"#    ",
			" ### ",
			"    #",
			"    #",
			"#### ",
			"     ",
		},
		'T': {
			"#####",
			"  #  ",
			"  #  ",
			"  #  ",
			"  #  ",
			"  #  ",
			"     ",
		},
		'U': {
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			" ### ",
			"     ",
		},
		'V': {
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			" # # ",
			"  #  ",
			"     ",
		},
		'W': {
			"#   #",
			"#   #",
			"#   #",
			"# # #",
			"## ##",
			"#   #",
			"     ",
		},
		'X': {
			"#   #",
			" # # ",
			"  #  ",
			"  #  ",
			" # # ",
			"#   #",
			"     ",
		},
		'Y': {
			"#   #",
			" # # ",
			"  #  ",
			"  #  ",
			"  #  ",
			"  #  ",
			"     ",
		},
		'Z': {
			"#####",
			"   # ",
			"  #  ",
			" #   ",
			"#    ",
			"#####",
			"     ",
		},
		'2': {
			" ### ",
			"#   #",
			"   # ",
			"  #  ",
			" #   ",
			"#####",
			"     ",
		},
		'3': {
			" ### ",
			"#   #",
			"  ## ",
			"    #",
			"#   #",
			" ### ",
			"     ",
		},
		'4': {
			"   # ",
			"  ## ",
			" # # ",
			"#  # ",
			"#####",
			"   # ",
			"     ",
		},
		'5': {
			"#####",
			"#    ",
			"#### ",
			"    #",
			"#   #",
			" ### ",
			"     ",
		},
		'6': {
			" ### ",
			"#    ",
			"#### ",
			"#   #",
			"#   #",
			" ### ",
			"     ",
		},
		'7': {
			"#####",
			"    #",
			"   # ",
			"  #  ",
			" #   ",
			"#    ",
			"     ",
		},
		'8': {
			" ### ",
			"#   #",
			" ### ",
			"#   #",
			"#   #",
			" ### ",
			"     ",
		},
		'9': {
			" ### ",
			"#   #",
			"#   #",
			" ####",
			"    #",
			" ### ",
			"     ",
		},
	}

	pattern, exists := patterns[char]
	if !exists {
		// Draw a simple rectangle for unknown characters
		for dy := 0; dy < 7; dy++ {
			for dx := 0; dx < 5; dx++ {
				if dy == 0 || dy == 6 || dx == 0 || dx == 4 {
					img.Set(x+dx, y+dy, c)
				}
			}
		}
		return
	}

	// Draw the character pattern
	for dy, row := range pattern {
		for dx, pixel := range row {
			if pixel == '#' {
				img.Set(x+dx, y+dy, c)
			}
		}
	}
}

// Add noise to CAPTCHA image to prevent OCR
func addNoise(img *image.RGBA) {
	bounds := img.Bounds()
	noiseColor := color.RGBA{60, 60, 67, 255} // Slightly lighter than background

	// Add random noise pixels
	for i := 0; i < 200; i++ {
		x := (i*37 + 123) % bounds.Max.X
		y := (i*41 + 456) % bounds.Max.Y
		img.Set(x, y, noiseColor)
	}
}

// Add distortion lines to make OCR harder
func addDistortionLines(img *image.RGBA) {
	bounds := img.Bounds()
	lineColor := color.RGBA{100, 100, 107, 255} // Medium gray

	// Add some diagonal lines
	for i := 0; i < 3; i++ {
		startX := (i * 47) % bounds.Max.X
		startY := (i * 31) % bounds.Max.Y
		endX := ((i + 1) * 73) % bounds.Max.X
		endY := ((i + 1) * 59) % bounds.Max.Y

		drawLine(img, startX, startY, endX, endY, lineColor)
	}
}

// Draw a line between two points
func drawLine(img *image.RGBA, x1, y1, x2, y2 int, c color.RGBA) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	sx := 1
	sy := 1

	if x1 > x2 {
		sx = -1
	}
	if y1 > y2 {
		sy = -1
	}

	err := dx - dy
	x, y := x1, y1

	for {
		if x >= 0 && y >= 0 && x < img.Bounds().Max.X && y < img.Bounds().Max.Y {
			img.Set(x, y, c)
		}

		if x == x2 && y == y2 {
			break
		}

		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x += sx
		}
		if e2 < dx {
			err += dx
			y += sy
		}
	}
}

// Draw larger characters for better visibility
func drawLargeChar(img *image.RGBA, char rune, x, y int, c color.RGBA) {
	// Use the existing patterns but scale them up 2x
	patterns := getLargeCharPatterns()

	pattern, exists := patterns[char]
	if !exists {
		// Draw a larger rectangle for unknown characters
		for dy := 0; dy < 14; dy++ {
			for dx := 0; dx < 10; dx++ {
				if dy < 2 || dy > 11 || dx < 2 || dx > 7 {
					if x+dx >= 0 && y+dy >= 0 && x+dx < img.Bounds().Max.X && y+dy < img.Bounds().Max.Y {
						img.Set(x+dx, y+dy, c)
					}
				}
			}
		}
		return
	}

	// Draw the character pattern scaled 2x
	for dy, row := range pattern {
		for dx, pixel := range row {
			if pixel == '#' {
				// Draw 2x2 pixel block for each pattern pixel
				for py := 0; py < 2; py++ {
					for px := 0; px < 2; px++ {
						nx, ny := x+dx*2+px, y+dy*2+py
						if nx >= 0 && ny >= 0 && nx < img.Bounds().Max.X && ny < img.Bounds().Max.Y {
							img.Set(nx, ny, c)
						}
					}
				}
			}
		}
	}
}

// Get larger character patterns (same as before but will be scaled)
func getLargeCharPatterns() map[rune][]string {
	return map[rune][]string{
		'A': {
			" ### ",
			"#   #",
			"#   #",
			"#####",
			"#   #",
			"#   #",
			"     ",
		},
		'B': {
			"#### ",
			"#   #",
			"#### ",
			"#### ",
			"#   #",
			"#### ",
			"     ",
		},
		'C': {
			" ####",
			"#    ",
			"#    ",
			"#    ",
			"#    ",
			" ####",
			"     ",
		},
		'D': {
			"#### ",
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			"#### ",
			"     ",
		},
		'E': {
			"#####",
			"#    ",
			"#### ",
			"#    ",
			"#    ",
			"#####",
			"     ",
		},
		'F': {
			"#####",
			"#    ",
			"#### ",
			"#    ",
			"#    ",
			"#    ",
			"     ",
		},
		'G': {
			" ####",
			"#    ",
			"# ###",
			"#   #",
			"#   #",
			" ####",
			"     ",
		},
		'H': {
			"#   #",
			"#   #",
			"#####",
			"#   #",
			"#   #",
			"#   #",
			"     ",
		},
		'J': {
			"  ###",
			"    #",
			"    #",
			"    #",
			"#   #",
			" ### ",
			"     ",
		},
		'K': {
			"#   #",
			"#  # ",
			"# #  ",
			"##   ",
			"# #  ",
			"#  ##",
			"     ",
		},
		'L': {
			"#    ",
			"#    ",
			"#    ",
			"#    ",
			"#    ",
			"#####",
			"     ",
		},
		'M': {
			"#   #",
			"## ##",
			"# # #",
			"#   #",
			"#   #",
			"#   #",
			"     ",
		},
		'N': {
			"#   #",
			"##  #",
			"# # #",
			"#  ##",
			"#   #",
			"#   #",
			"     ",
		},
		'P': {
			"#### ",
			"#   #",
			"#### ",
			"#    ",
			"#    ",
			"#    ",
			"     ",
		},
		'Q': {
			" ### ",
			"#   #",
			"#   #",
			"# # #",
			"#  ##",
			" ####",
			"     ",
		},
		'R': {
			"#### ",
			"#   #",
			"#### ",
			"# #  ",
			"#  # ",
			"#   #",
			"     ",
		},
		'S': {
			" ####",
			"#    ",
			" ### ",
			"    #",
			"    #",
			"#### ",
			"     ",
		},
		'T': {
			"#####",
			"  #  ",
			"  #  ",
			"  #  ",
			"  #  ",
			"  #  ",
			"     ",
		},
		'U': {
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			" ### ",
			"     ",
		},
		'V': {
			"#   #",
			"#   #",
			"#   #",
			"#   #",
			" # # ",
			"  #  ",
			"     ",
		},
		'W': {
			"#   #",
			"#   #",
			"#   #",
			"# # #",
			"## ##",
			"#   #",
			"     ",
		},
		'X': {
			"#   #",
			" # # ",
			"  #  ",
			"  #  ",
			" # # ",
			"#   #",
			"     ",
		},
		'Y': {
			"#   #",
			" # # ",
			"  #  ",
			"  #  ",
			"  #  ",
			"  #  ",
			"     ",
		},
		'Z': {
			"#####",
			"   # ",
			"  #  ",
			" #   ",
			"#    ",
			"#####",
			"     ",
		},
		'2': {
			" ### ",
			"#   #",
			"   # ",
			"  #  ",
			" #   ",
			"#####",
			"     ",
		},
		'3': {
			" ### ",
			"#   #",
			"  ## ",
			"    #",
			"#   #",
			" ### ",
			"     ",
		},
		'4': {
			"   # ",
			"  ## ",
			" # # ",
			"#  # ",
			"#####",
			"   # ",
			"     ",
		},
		'5': {
			"#####",
			"#    ",
			"#### ",
			"    #",
			"#   #",
			" ### ",
			"     ",
		},
		'6': {
			" ### ",
			"#    ",
			"#### ",
			"#   #",
			"#   #",
			" ### ",
			"     ",
		},
		'7': {
			"#####",
			"    #",
			"   # ",
			"  #  ",
			" #   ",
			"#    ",
			"     ",
		},
		'8': {
			" ### ",
			"#   #",
			" ### ",
			"#   #",
			"#   #",
			" ### ",
			"     ",
		},
		'9': {
			" ### ",
			"#   #",
			"#   #",
			" ####",
			"    #",
			" ### ",
			"     ",
		},
	}
}

// Helper function for absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// getClientIP extracts client IP from request (helper for challenges)
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

// CreateSessionAfterChallenge creates a session after successful challenge completion
func (cm *ChallengeManager) CreateSessionAfterChallenge(clientIP, userAgent, host string) string {
	sessionManager := GetSessionManager()
	return sessionManager.CreateSession(clientIP, userAgent, host)
}

// CreateSessionCookie creates a session cookie for the response
func (cm *ChallengeManager) CreateSessionCookie(sessionID string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     "__defenra_session",
		Value:    sessionID,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	}
}
