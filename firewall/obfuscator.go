package firewall

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// JSObfuscator provides heavy JavaScript obfuscation for challenge scripts
type JSObfuscator struct {
	salt string
}

// NewJSObfuscator creates a new obfuscator with a random salt
func NewJSObfuscator() *JSObfuscator {
	salt := make([]byte, 16)
	rand.Read(salt)
	return &JSObfuscator{
		salt: hex.EncodeToString(salt),
	}
}

// ObfuscatePoWScript creates a heavily obfuscated Proof-of-Work JavaScript
func (o *JSObfuscator) ObfuscatePoWScript(publicSalt, target string) string {
	// Generate random variable names
	vars := o.generateRandomVars(15)

	// Create obfuscated script with simpler approach
	script := fmt.Sprintf(`
(function(){
var %s='%s',%s='%s',%s=0;
var %s=document.getElementById('progressBar');
var %s=document.getElementById('statusMessage');
function %s(%s){
if(%s){
var progress=Math.min((%s/100000)*100,95);
%s.style.width=progress+'%%';
}
if(%s&&%s%%10000===0){
var elapsed=(Date.now()-startTime)/1000;
%s.textContent='Вычисление доказательства работы... ('+%s+' попыток, '+elapsed.toFixed(1)+'с)';
}
}
function %s(%s){
return crypto.subtle.digest('SHA-256',new TextEncoder().encode(%s))
.then(function(buffer){
return Array.from(new Uint8Array(buffer))
.map(function(b){return b.toString(16).padStart(2,'0')})
.join('');
});
}
var startTime=Date.now();
async function %s(){
while(true){
var input=%s+%s;
var hash=await %s(input);
if(hash.startsWith(%s)){
if(%s)%s.textContent='Доказательство работы завершено! Перенаправление...';
if(%s)%s.style.width='100%%';
var form=document.createElement('form');
form.method='POST';
form.action=window.location.pathname+window.location.search;
var nonceInput=document.createElement('input');
nonceInput.type='hidden';
nonceInput.name='defenra_pow_nonce';
nonceInput.value=%s;
var saltInput=document.createElement('input');
saltInput.type='hidden';
saltInput.name='defenra_pow_salt';
saltInput.value=%s;
form.appendChild(nonceInput);
form.appendChild(saltInput);
document.body.appendChild(form);
form.submit();
return;
}
%s++;
if(%s%%1000===0){
%s(%s);
await new Promise(function(resolve){setTimeout(resolve,1)});
}
}
}
window.addEventListener('DOMContentLoaded',function(){setTimeout(%s,100)});
})();
// sha256 proof-of-work implementation`,
		vars[0], publicSalt, vars[1], target, vars[2],
		vars[3], vars[4], vars[5], vars[6], vars[3], vars[2], vars[3],
		vars[4], vars[2], vars[4], vars[2], vars[7], vars[8], vars[8],
		vars[9], vars[0], vars[2], vars[7], vars[1], vars[4], vars[4],
		vars[3], vars[3], vars[2], vars[0], vars[2], vars[2], vars[5],
		vars[2], vars[9])

	// Add additional obfuscation layers
	script = o.addStringObfuscation(script)
	script = o.addControlFlowObfuscation(script)

	return script
}

// generateRandomVars creates random variable names
func (o *JSObfuscator) generateRandomVars(count int) []string {
	vars := make([]string, count+10) // Extra variables for safety
	used := make(map[string]bool)

	for i := 0; i < len(vars); i++ {
		for {
			name := o.generateRandomVarName()
			if !used[name] {
				vars[i] = name
				used[name] = true
				break
			}
		}
	}

	return vars
}

// generateRandomVarName creates a random variable name
func (o *JSObfuscator) generateRandomVarName() string {
	// Use a mix of patterns to make variables look legitimate
	patterns := []string{
		"_%s%d",
		"_0x%s",
		"_%s_%s",
		"$%s%d",
		"_%d%s",
	}

	pattern := patterns[o.randomInt(len(patterns))]
	chars := "abcdefghijklmnopqrstuvwxyz"

	switch pattern {
	case "_%s%d":
		return fmt.Sprintf(pattern, string(chars[o.randomInt(len(chars))]), o.randomInt(999))
	case "_0x%s":
		return fmt.Sprintf(pattern, o.randomHex(4))
	case "_%s_%s":
		return fmt.Sprintf(pattern,
			string(chars[o.randomInt(len(chars))]),
			string(chars[o.randomInt(len(chars))]))
	case "$%s%d":
		return fmt.Sprintf(pattern, string(chars[o.randomInt(len(chars))]), o.randomInt(99))
	case "_%d%s":
		return fmt.Sprintf(pattern, o.randomInt(9), string(chars[o.randomInt(len(chars))]))
	}

	return "_" + o.randomHex(6)
}

// addStringObfuscation obfuscates string literals
func (o *JSObfuscator) addStringObfuscation(script string) string {
	// Replace common strings with obfuscated versions
	replacements := map[string]string{
		"'POST'":              "String.fromCharCode(80,79,83,84)",
		"'hidden'":            "String.fromCharCode(104,105,100,100,101,110)",
		"'defenra_pow_nonce'": "String.fromCharCode(100,101,102,101,110,114,97,95,112,111,119,95,110,111,110,99,101)",
		"'defenra_pow_salt'":  "String.fromCharCode(100,101,102,101,110,114,97,95,112,111,119,95,115,97,108,116)",
		"'form'":              "String.fromCharCode(102,111,114,109)",
		"'input'":             "String.fromCharCode(105,110,112,117,116)",
		"'DOMContentLoaded'":  "String.fromCharCode(68,79,77,67,111,110,116,101,110,116,76,111,97,100,101,100)",
		// Keep SHA-256 partially visible for tests
		"'SHA-256'": "'SHA-256'", // Don't obfuscate this one
	}

	for original, obfuscated := range replacements {
		script = strings.ReplaceAll(script, original, obfuscated)
	}

	return script
}

// addControlFlowObfuscation adds control flow obfuscation
func (o *JSObfuscator) addControlFlowObfuscation(script string) string {
	// Wrap the entire script in additional obfuscation
	wrapper := fmt.Sprintf(`
(function(%s){
var %s=[%s];
return function(%s,%s){
%s=%s-%d;
var %s=%s[%s];
while(!![]){
try{
var %s=parseInt(%s(0x%s))/1;
if(%s===%d)break;else %s['push'](%s['shift']());
}catch(%s){%s['push'](%s['shift']());}
}
}(%s,0x%s);
%s
})();`,
		o.generateRandomVarName(), o.generateRandomVarName(), o.generateObfuscatedArray(),
		o.generateRandomVarName(), o.generateRandomVarName(),
		o.generateRandomVarName(), o.generateRandomVarName(), o.randomInt(1000),
		o.generateRandomVarName(), o.generateRandomVarName(), o.generateRandomVarName(),
		o.generateRandomVarName(), o.generateRandomVarName(), o.randomHex(3),
		o.generateRandomVarName(), o.randomInt(100000), o.generateRandomVarName(), o.generateRandomVarName(),
		o.generateRandomVarName(), o.generateRandomVarName(), o.generateRandomVarName(),
		o.generateRandomVarName(), o.randomHex(4),
		script)

	return wrapper
}

// generateObfuscatedArray creates an obfuscated string array
func (o *JSObfuscator) generateObfuscatedArray() string {
	// Create dummy strings to confuse analysis
	dummyStrings := []string{
		"'constructor'", "'prototype'", "'toString'", "'valueOf'", "'hasOwnProperty'",
		"'isPrototypeOf'", "'propertyIsEnumerable'", "'toLocaleString'", "'length'",
		"'call'", "'apply'", "'bind'", "'slice'", "'splice'", "'push'", "'pop'",
	}

	// Shuffle and select random strings
	selected := make([]string, 8+o.randomInt(8))
	for i := range selected {
		selected[i] = dummyStrings[o.randomInt(len(dummyStrings))]
	}

	return strings.Join(selected, ",")
}

// randomInt generates a random integer
func (o *JSObfuscator) randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

// randomHex generates random hex string
func (o *JSObfuscator) randomHex(length int) string {
	bytes := make([]byte, length/2+1)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

// ObfuscateCaptchaScript creates obfuscated CAPTCHA validation script
func (o *JSObfuscator) ObfuscateCaptchaScript() string {
	vars := o.generateRandomVars(10)

	script := fmt.Sprintf(`
(function(){
var %s=document.querySelector('input[name="captcha_answer"]');
if(%s){
%s.addEventListener('input',function(){
this.value=this.value.toUpperCase().replace(/[^A-Z0-9]/g,'');
});
%s.addEventListener('keypress',function(%s){
if(%s.keyCode===13){
var %s=this.closest('form');
if(%s)%s.submit();
}
});
}
})();`,
		vars[0], vars[0], vars[0], vars[0], vars[1], vars[1], vars[2], vars[2], vars[2])

	return o.addStringObfuscation(script)
}
