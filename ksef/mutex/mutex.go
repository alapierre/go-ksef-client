package mutex

import (
	"sync"
	"sync/atomic"
)

type rwentry struct {
	mu   sync.RWMutex
	refs int32
}

type KeyedRWMutex[K comparable] struct {
	table sync.Map // map[K]*rwentry
}

func (m *KeyedRWMutex[K]) get(key K) *rwentry {
	v, _ := m.table.LoadOrStore(key, &rwentry{refs: 1})
	e := v.(*rwentry)
	if atomic.AddInt32(&e.refs, 1) == 1 {
		// ktoś zdążył wyzerować; skoryguj do 1
		atomic.StoreInt32(&e.refs, 1)
	}
	return e
}

func (m *KeyedRWMutex[K]) put(key K, e *rwentry) {
	if atomic.AddInt32(&e.refs, -1) == 0 {
		m.table.CompareAndDelete(key, e) // Go 1.20+
	}
}

// Public API
func (m *KeyedRWMutex[K]) RLock(key K)   { e := m.get(key); e.mu.RLock(); m.put(key, e) }
func (m *KeyedRWMutex[K]) RUnlock(key K) { v, _ := m.table.Load(key); v.(*rwentry).mu.RUnlock() }
func (m *KeyedRWMutex[K]) Lock(key K)    { e := m.get(key); e.mu.Lock(); m.put(key, e) }
func (m *KeyedRWMutex[K]) Unlock(key K)  { v, _ := m.table.Load(key); v.(*rwentry).mu.Unlock() }
