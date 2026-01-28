package firewall

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SimpleJSObfuscator provides working JavaScript for challenge scripts
type SimpleJSObfuscator struct {
	salt string
}

// NewSimpleJSObfuscator creates a new simple obfuscator
func NewSimpleJSObfuscator() *SimpleJSObfuscator {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("failed to generate random salt: %v", err))
	}
	return &SimpleJSObfuscator{
		salt: hex.EncodeToString(salt),
	}
}

// ObfuscatePoWScript creates a working Proof-of-Work JavaScript
func (o *SimpleJSObfuscator) ObfuscatePoWScript(publicSalt, target string) string {
	script := fmt.Sprintf(`
(function(){
var publicSalt='%s';
var target='%s';
var nonce=0;
var progressBar=document.getElementById('progressBar');
var statusMessage=document.getElementById('statusMessage');
var startTime=Date.now();

function updateProgress(){
if(progressBar){
var progress=Math.min((nonce/100000)*100,95);
progressBar.style.width=progress+'%%';
}
if(statusMessage&&nonce%%10000===0){
var elapsed=(Date.now()-startTime)/1000;
statusMessage.textContent='Вычисление доказательства работы... ('+nonce+' попыток, '+elapsed.toFixed(1)+'с)';
}
}

async function hashFunction(input){
return crypto.subtle.digest('SHA-256',new TextEncoder().encode(input))
.then(function(buffer){
return Array.from(new Uint8Array(buffer))
.map(function(b){return b.toString(16).padStart(2,'0')})
.join('');
});
}

async function solveChallenge(){
while(true){
var input=publicSalt+nonce;
var hash=await hashFunction(input);
if(hash.startsWith(target)){
if(statusMessage)statusMessage.textContent='Доказательство работы завершено! Перенаправление...';
if(progressBar)progressBar.style.width='100%%';
var form=document.createElement('form');
form.method=String.fromCharCode(80,79,83,84);
form.action=window.location.pathname;
var nonceInput=document.createElement('input');
nonceInput.type=String.fromCharCode(104,105,100,100,101,110);
nonceInput.name='defenra_pow_nonce';
nonceInput.value=nonce;
var saltInput=document.createElement('input');
saltInput.type=String.fromCharCode(104,105,100,100,101,110);
saltInput.name='defenra_pow_salt';
saltInput.value=publicSalt;
form.appendChild(nonceInput);
form.appendChild(saltInput);
document.body.appendChild(form);
form.submit();
return;
}
nonce++;
if(nonce%%1000===0){
updateProgress();
await new Promise(function(resolve){setTimeout(resolve,1)});
}
}
}

window.addEventListener('DOMContentLoaded',function(){setTimeout(solveChallenge,100)});
})();
// sha256 proof-of-work implementation`, publicSalt, target)

	return script
}

// ObfuscateCaptchaScript creates simple CAPTCHA validation script
func (o *SimpleJSObfuscator) ObfuscateCaptchaScript() string {
	script := `
(function(){
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
})();`

	return script
}
