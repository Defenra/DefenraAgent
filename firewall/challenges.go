package firewall

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
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
}

type CaptchaData struct {
	Answer     string
	ImageData  string
	MaskData   string
	ExpiresAt  time.Time
}

var globalChallengeManager *ChallengeManager

func init() {
	globalChallengeManager = NewChallengeManager()
}

func NewChallengeManager() *ChallengeManager {
	cm := &ChallengeManager{
		cookieSecret: generateSecret(),
		jsSecret:     generateSecret(),
		captchaCache: make(map[string]*CaptchaData),
		stopChan:     make(chan struct{}),
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

	// Set cookie and redirect
	cookie := &http.Cookie{
		Name:     "__defenra_v",
		Value:    verificationCookie,
		Path:     "/",
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return ChallengeResponse{
		Blocked:    true,
		StatusCode: http.StatusFound,
		Headers: map[string]string{
			"Set-Cookie": cookie.String(),
			"Location":   r.RequestURI,
			"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
		},
		Body: "Verifying your browser...",
	}
}

func (cm *ChallengeManager) ValidateCookieChallenge(r *http.Request, clientIP string) bool {
	cookie, err := r.Cookie("__defenra_v")
	if err != nil {
		return false
	}

	accessKey := fmt.Sprintf("%s_%s_%s_%d", clientIP, r.UserAgent(), r.Host, time.Now().Hour())
	expectedCookie := cm.generateVerificationCookie(accessKey)

	return cookie.Value == expectedCookie
}

// JavaScript PoW Challenge (Stage 2)
func (cm *ChallengeManager) IssueJSChallenge(w http.ResponseWriter, r *http.Request, clientIP string, difficulty int) ChallengeResponse {
	// Generate challenge parameters
	publicSalt := generateRandomString(16)
	target := strings.Repeat("0", difficulty)

	jsChallenge := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Verifying your browser...</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%%; width: 40px; height: 40px; animation: spin 2s linear infinite; margin: 20px auto; }
        @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
        .progress { width: 100%%; background-color: #f0f0f0; border-radius: 4px; margin: 20px 0; }
        .progress-bar { height: 20px; background-color: #4CAF50; border-radius: 4px; width: 0%%; transition: width 0.3s; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Verifying your browser...</h2>
        <p>Please wait while we verify that you're a human.</p>
        <div class="spinner"></div>
        <div class="progress">
            <div class="progress-bar" id="progressBar"></div>
        </div>
        <p id="status">Computing proof of work...</p>
    </div>

    <script>
        const publicSalt = '%s';
        const target = '%s';
        let nonce = 0;
        let startTime = Date.now();

        function updateProgress(attempts) {
            const progress = Math.min((attempts / 100000) * 100, 95);
            document.getElementById('progressBar').style.width = progress + '%%';
            
            if (attempts %% 10000 === 0) {
                const elapsed = (Date.now() - startTime) / 1000;
                document.getElementById('status').textContent = 
                    'Computing proof of work... (' + attempts + ' attempts, ' + elapsed.toFixed(1) + 's)';
            }
        }

        function sha256(str) {
            return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
                .then(buffer => Array.from(new Uint8Array(buffer))
                    .map(b => b.toString(16).padStart(2, '0')).join(''));
        }

        async function solveChallenge() {
            while (true) {
                const input = publicSalt + nonce;
                const hash = await sha256(input);
                
                if (hash.startsWith(target)) {
                    // Solution found!
                    document.getElementById('status').textContent = 'Proof of work completed! Redirecting...';
                    document.getElementById('progressBar').style.width = '100%%';
                    
                    // Submit solution
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = window.location.pathname + window.location.search;
                    
                    const nonceInput = document.createElement('input');
                    nonceInput.type = 'hidden';
                    nonceInput.name = 'defenra_pow_nonce';
                    nonceInput.value = nonce;
                    
                    const saltInput = document.createElement('input');
                    saltInput.type = 'hidden';
                    saltInput.name = 'defenra_pow_salt';
                    saltInput.value = publicSalt;
                    
                    form.appendChild(nonceInput);
                    form.appendChild(saltInput);
                    document.body.appendChild(form);
                    form.submit();
                    return;
                }
                
                nonce++;
                if (nonce %% 1000 === 0) {
                    updateProgress(nonce);
                    // Allow UI to update
                    await new Promise(resolve => setTimeout(resolve, 1));
                }
            }
        }

        // Start solving when page loads
        window.onload = () => {
            setTimeout(solveChallenge, 100);
        };
    </script>
</body>
</html>`, publicSalt, target)

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

	return strings.HasPrefix(hash, target)
}

// CAPTCHA Challenge (Stage 3)
func (cm *ChallengeManager) IssueCaptchaChallenge(w http.ResponseWriter, r *http.Request, clientIP string) ChallengeResponse {
	// Generate CAPTCHA
	captchaID := generateRandomString(8)
	captchaData := cm.generateCaptcha(captchaID)

	cm.mu.Lock()
	cm.captchaCache[captchaID] = captchaData
	cm.mu.Unlock()

	captchaHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .captcha-container { position: relative; display: inline-block; margin: 20px 0; }
        .captcha-image { border: 2px solid #ddd; border-radius: 4px; }
        .captcha-mask { position: absolute; top: 0; left: 0; pointer-events: none; }
        input[type="text"] { padding: 10px; font-size: 16px; border: 2px solid #ddd; border-radius: 4px; margin: 10px; }
        button { background: #4CAF50; color: white; padding: 12px 24px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #45a049; }
        .error { color: #f44336; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Security Check</h2>
        <p>Please complete the CAPTCHA to continue:</p>
        
        <div class="captcha-container">
            <img src="data:image/png;base64,%s" alt="CAPTCHA" class="captcha-image">
            <img src="data:image/png;base64,%s" alt="" class="captcha-mask">
        </div>
        
        <form method="POST" action="%s">
            <input type="hidden" name="captcha_id" value="%s">
            <br>
            <input type="text" name="captcha_answer" placeholder="Enter the text you see" autocomplete="off" required>
            <br>
            <button type="submit">Verify</button>
        </form>
        
        <p><small>Can't see the image? <a href="javascript:location.reload()">Refresh page</a></small></p>
    </div>
</body>
</html>`, captchaData.ImageData, captchaData.MaskData, r.RequestURI, captchaID)

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

	return answer == strings.ToLower(captchaData.Answer)
}

// Helper functions
func (cm *ChallengeManager) generateVerificationCookie(accessKey string) string {
	hash := sha256.Sum256([]byte(accessKey + cm.cookieSecret))
	return hex.EncodeToString(hash[:])[:16]
}

func (cm *ChallengeManager) generateCaptcha(captchaID string) *CaptchaData {
	// Generate random text
	answer := generateRandomString(6)
	
	// Create CAPTCHA image
	img := image.NewRGBA(image.Rect(0, 0, 200, 80))
	
	// Fill background
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{240, 240, 240, 255}}, image.Point{}, draw.Src)
	
	// Add noise and text (simplified implementation)
	// In production, use a proper CAPTCHA library
	
	// Convert to base64
	var buf bytes.Buffer
	png.Encode(&buf, img)
	imageData := base64.StdEncoding.EncodeToString(buf.Bytes())
	
	// Create mask (simplified)
	maskImg := image.NewRGBA(img.Bounds())
	var maskBuf bytes.Buffer
	png.Encode(&maskBuf, maskImg)
	maskData := base64.StdEncoding.EncodeToString(maskBuf.Bytes())

	return &CaptchaData{
		Answer:    answer,
		ImageData: imageData,
		MaskData:  maskData,
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

func sha256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}