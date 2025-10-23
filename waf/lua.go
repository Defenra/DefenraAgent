package waf

import (
	"log"
	"net/http"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

type LuaWAF struct {
	pool *sync.Pool
}

type WAFResponse struct {
	Blocked    bool
	StatusCode int
	Body       string
}

func NewLuaWAF() *LuaWAF {
	return &LuaWAF{
		pool: &sync.Pool{
			New: func() interface{} {
				return lua.NewState()
			},
		},
	}
}

func (w *LuaWAF) Execute(luaCode string, r *http.Request) (bool, WAFResponse) {
	L := w.pool.Get().(*lua.LState)
	defer w.pool.Put(L)

	L.SetGlobal("_blocked", lua.LNil)
	L.SetGlobal("_status_code", lua.LNumber(403))
	L.SetGlobal("_body", lua.LString("Blocked by WAF"))

	requestTable := L.NewTable()
	L.SetField(requestTable, "method", lua.LString(r.Method))
	L.SetField(requestTable, "uri", lua.LString(r.RequestURI))
	L.SetField(requestTable, "host", lua.LString(r.Host))
	L.SetField(requestTable, "remote_addr", lua.LString(r.RemoteAddr))

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
		log.Printf("[WAF] Lua execution error: %v", err)
		return false, WAFResponse{}
	}

	blocked := L.GetGlobal("_blocked")
	if blocked != lua.LNil && blocked != lua.LFalse {
		statusCode := int(L.GetGlobal("_status_code").(lua.LNumber))
		body := string(L.GetGlobal("_body").(lua.LString))

		return true, WAFResponse{
			Blocked:    true,
			StatusCode: statusCode,
			Body:       body,
		}
	}

	return false, WAFResponse{}
}

func (w *LuaWAF) setupNginxAPI(L *lua.LState) {
	ngxTable := L.NewTable()

	L.SetField(ngxTable, "exit", L.NewFunction(func(L *lua.LState) int {
		statusCode := L.CheckInt(1)
		L.SetGlobal("_blocked", lua.LTrue)
		L.SetGlobal("_status_code", lua.LNumber(statusCode))
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
			}
			if host := L.GetField(reqTable, "host"); host != lua.LNil {
				L.SetField(varTable, "host", host)
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

	L.SetGlobal("ngx", ngxTable)
}

func (w *LuaWAF) createSharedCache(L *lua.LState) *lua.LTable {
	cache := make(map[string]interface{})
	cacheMutex := &sync.RWMutex{}

	cacheTable := L.NewTable()

	L.SetField(cacheTable, "get", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(2)

		cacheMutex.RLock()
		value, ok := cache[key]
		cacheMutex.RUnlock()

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

		cacheMutex.Lock()
		defer cacheMutex.Unlock()

		switch value.Type() {
		case lua.LTNumber:
			cache[key] = int(value.(lua.LNumber))
		case lua.LTString:
			cache[key] = string(value.(lua.LString))
		}

		L.Push(lua.LTrue)
		return 1
	}))

	L.SetField(cacheTable, "incr", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(2)
		delta := L.CheckInt(3)
		initial := L.OptInt(4, 0)

		cacheMutex.Lock()
		defer cacheMutex.Unlock()

		currentValue, ok := cache[key]
		if !ok {
			cache[key] = initial + delta
			L.Push(lua.LNumber(initial + delta))
			return 1
		}

		if intValue, ok := currentValue.(int); ok {
			newValue := intValue + delta
			cache[key] = newValue
			L.Push(lua.LNumber(newValue))
			return 1
		}

		L.Push(lua.LNil)
		return 1
	}))

	return cacheTable
}
