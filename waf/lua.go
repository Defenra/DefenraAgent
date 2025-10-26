package waf

import (
	"log"
	"net/http"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

type LuaWAF struct {
	pool        *sync.Pool
	sharedCache map[string]interface{}
	cacheMutex  *sync.RWMutex
}

type WAFResponse struct {
	Blocked    bool
	StatusCode int
	Body       string
	Headers    map[string]string
}

func NewLuaWAF() *LuaWAF {
	return &LuaWAF{
		pool: &sync.Pool{
			New: func() interface{} {
				return lua.NewState()
			},
		},
		sharedCache: make(map[string]interface{}),
		cacheMutex:  &sync.RWMutex{},
	}
}

func (w *LuaWAF) Execute(luaCode string, r *http.Request) (bool, WAFResponse) {
	L := w.pool.Get().(*lua.LState)
	defer w.pool.Put(L)

	L.SetGlobal("_blocked", lua.LNil)
	L.SetGlobal("_status_code", lua.LNumber(403))
	L.SetGlobal("_body", lua.LNil) // Will be set by ngx.say/print or default on block

	// Extract IP without port (like nginx does for ngx.var.remote_addr)
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	requestTable := L.NewTable()
	L.SetField(requestTable, "method", lua.LString(r.Method))
	L.SetField(requestTable, "uri", lua.LString(r.RequestURI))
	L.SetField(requestTable, "host", lua.LString(r.Host))
	L.SetField(requestTable, "remote_addr", lua.LString(remoteIP))

	headersTable := L.NewTable()
	for key, values := range r.Header {
		if len(values) > 0 {
			L.SetField(headersTable, key, lua.LString(values[0]))
		}
	}
	L.SetField(requestTable, "headers", headersTable)

	L.SetGlobal("request", requestTable)

	w.setupNginxAPI(L)

	if err := L.DoString(luaCode); err != nil {
		// Check if this is ngx.exit() (which is expected behavior, not an error)
		if !strings.Contains(err.Error(), "ngx_exit") {
			log.Printf("[WAF] Lua execution error: %v", err)
			return false, WAFResponse{}
		}
		// ngx.exit() was called, continue to check _blocked flag
	}

	// Extract headers set by script
	headers := make(map[string]string)
	if ngx := L.GetGlobal("ngx"); ngx != lua.LNil {
		if ngxTable, ok := ngx.(*lua.LTable); ok {
			if headerTable := L.GetField(ngxTable, "header"); headerTable != lua.LNil {
				if hTable, ok := headerTable.(*lua.LTable); ok {
					hTable.ForEach(func(key, value lua.LValue) {
						if keyStr, ok := key.(lua.LString); ok {
							if valStr, ok := value.(lua.LString); ok {
								headers[string(keyStr)] = string(valStr)
							}
						}
					})
				}
			}
		}
	}

	blocked := L.GetGlobal("_blocked")
	if blocked != lua.LNil && blocked != lua.LFalse {
		statusCode := 403
		if sc := L.GetGlobal("_status_code"); sc != lua.LNil {
			if num, ok := sc.(lua.LNumber); ok {
				statusCode = int(num)
			} else {
				log.Printf("[WAF] Invalid _status_code type: expected number, got %s", sc.Type())
			}
		}

		body := ""
		if bd := L.GetGlobal("_body"); bd != lua.LNil {
			if str, ok := bd.(lua.LString); ok {
				body = string(str)
			} else {
				log.Printf("[WAF] Invalid _body type: expected string, got %s", bd.Type())
			}
		}
		
		// Use default body if empty
		if body == "" {
			body = "Blocked by WAF"
		}

		return true, WAFResponse{
			Blocked:    true,
			StatusCode: statusCode,
			Body:       body,
			Headers:    headers,
		}
	}

	return false, WAFResponse{
		Blocked: false,
		Headers: headers,
	}
}

func (w *LuaWAF) setupNginxAPI(L *lua.LState) {
	ngxTable := L.NewTable()

	L.SetField(ngxTable, "exit", L.NewFunction(func(L *lua.LState) int {
		statusCode := L.CheckInt(1)
		L.SetGlobal("_blocked", lua.LTrue)
		L.SetGlobal("_status_code", lua.LNumber(statusCode))
		// Raise error to stop execution immediately (like ngx.exit in OpenResty)
		L.RaiseError("ngx_exit")
		return 0
	}))

	varTable := L.NewTable()
	if request := L.GetGlobal("request"); request != lua.LNil {
		if reqTable, ok := request.(*lua.LTable); ok {
			if remoteAddr := L.GetField(reqTable, "remote_addr"); remoteAddr != lua.LNil {
				L.SetField(varTable, "remote_addr", remoteAddr)
			}
			if uri := L.GetField(reqTable, "uri"); uri != lua.LNil {
				L.SetField(varTable, "uri", uri)
				// Also set request_uri (alias for uri in nginx)
				L.SetField(varTable, "request_uri", uri)
			}
			if host := L.GetField(reqTable, "host"); host != lua.LNil {
				L.SetField(varTable, "host", host)
			}
			if method := L.GetField(reqTable, "method"); method != lua.LNil {
				L.SetField(varTable, "method", method)
			}
		}
	}
	L.SetField(ngxTable, "var", varTable)

	sharedTable := L.NewTable()
	cacheTable := w.createSharedCache(L)
	L.SetField(sharedTable, "cache", cacheTable)
	L.SetField(ngxTable, "shared", sharedTable)

	headerTable := L.NewTable()
	L.SetField(ngxTable, "header", headerTable)

	// ngx.say() - append text to response body
	L.SetField(ngxTable, "say", L.NewFunction(func(L *lua.LState) int {
		text := L.CheckString(1)
		
		// Get current body and append
		currentBody := L.GetGlobal("_body")
		if currentBody == lua.LNil {
			L.SetGlobal("_body", lua.LString(text))
		} else if str, ok := currentBody.(lua.LString); ok {
			L.SetGlobal("_body", lua.LString(string(str)+text))
		} else {
			L.SetGlobal("_body", lua.LString(text))
		}
		return 0
	}))

	// ngx.print() - same as ngx.say() but without newline (we treat them the same)
	L.SetField(ngxTable, "print", L.NewFunction(func(L *lua.LState) int {
		text := L.CheckString(1)
		
		// Get current body and append
		currentBody := L.GetGlobal("_body")
		if currentBody == lua.LNil {
			L.SetGlobal("_body", lua.LString(text))
		} else if str, ok := currentBody.(lua.LString); ok {
			L.SetGlobal("_body", lua.LString(string(str)+text))
		} else {
			L.SetGlobal("_body", lua.LString(text))
		}
		return 0
	}))

	L.SetGlobal("ngx", ngxTable)
}

func (w *LuaWAF) createSharedCache(L *lua.LState) *lua.LTable {
	cacheTable := L.NewTable()

	L.SetField(cacheTable, "get", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(2)

		w.cacheMutex.RLock()
		value, ok := w.sharedCache[key]
		w.cacheMutex.RUnlock()

		if !ok {
			L.Push(lua.LNil)
			return 1
		}

		switch v := value.(type) {
		case int:
			L.Push(lua.LNumber(v))
		case string:
			L.Push(lua.LString(v))
		default:
			L.Push(lua.LNil)
		}

		return 1
	}))

	L.SetField(cacheTable, "set", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(2)
		value := L.Get(3)

		w.cacheMutex.Lock()
		defer w.cacheMutex.Unlock()

		switch value.Type() {
		case lua.LTNumber:
			w.sharedCache[key] = int(value.(lua.LNumber))
		case lua.LTString:
			w.sharedCache[key] = string(value.(lua.LString))
		}

		L.Push(lua.LTrue)
		return 1
	}))

	L.SetField(cacheTable, "incr", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(2)
		delta := L.CheckInt(3)
		initial := L.OptInt(4, 0)

		w.cacheMutex.Lock()
		defer w.cacheMutex.Unlock()

		currentValue, ok := w.sharedCache[key]
		if !ok {
			w.sharedCache[key] = initial + delta
			L.Push(lua.LNumber(initial + delta))
			return 1
		}

		if intValue, ok := currentValue.(int); ok {
			newValue := intValue + delta
			w.sharedCache[key] = newValue
			L.Push(lua.LNumber(newValue))
			return 1
		}

		L.Push(lua.LNil)
		return 1
	}))

	return cacheTable
}
