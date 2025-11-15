package ksef

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

// --- MOCKI DO TESTÓW JEDNOSTKOWYCH ---

type mockFullAuthenticator struct {
	delay     time.Duration
	callCount int64
	err       error
}

func (m *mockFullAuthenticator) Auth(ctx context.Context) (*api.AuthenticationTokensResponse, error) {
	atomic.AddInt64(&m.callCount, 1)

	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.delay):
		}
	}
	if m.err != nil {
		return nil, m.err
	}

	now := time.Now().UTC()
	access := api.TokenInfo{
		Token:      "access-" + now.Format(time.RFC3339Nano),
		ValidUntil: now.Add(5 * time.Minute),
	}
	refresh := api.TokenInfo{
		Token:      "refresh-" + now.Format(time.RFC3339Nano),
		ValidUntil: now.Add(30 * time.Minute),
	}

	resp := &api.AuthenticationTokensResponse{}
	resp.SetAccessToken(access)
	resp.SetRefreshToken(refresh)
	return resp, nil
}

type mockTokenRefresher struct {
	delay     time.Duration
	callCount int64
	err       error
}

func (m *mockTokenRefresher) RefreshToken(ctx context.Context, refreshToken string) (api.TokenInfo, error) {
	atomic.AddInt64(&m.callCount, 1)

	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return api.TokenInfo{}, ctx.Err()
		case <-time.After(m.delay):
		}
	}
	if m.err != nil {
		return api.TokenInfo{}, m.err
	}

	now := time.Now().UTC()
	return api.TokenInfo{
		Token:      "refreshed-" + now.Format(time.RFC3339Nano),
		ValidUntil: now.Add(5 * time.Minute),
	}, nil
}

func newTestTokenProvider(auth *mockTokenRefresher, full *mockFullAuthenticator) *TokenProvider {
	p := NewTokenProvider(auth, full.Auth)
	p.refreshSkew = 500 * time.Millisecond
	return p
}

func ctxWithNip(nip string) context.Context {
	return Context(context.Background(), nip)
}

// --- TESTY JEDNOSTKOWE POPRAWNOŚCI ---

func TestTokenProvider_FirstCallDoesFullAuth(t *testing.T) {
	full := &mockFullAuthenticator{delay: 10 * time.Millisecond}
	ref := &mockTokenRefresher{delay: 5 * time.Millisecond}
	p := newTestTokenProvider(ref, full)

	ctx := ctxWithNip("1234567890")

	bearer, err := p.Bearer(ctx, "Op")
	if err != nil {
		t.Fatalf("Bearer() error = %v", err)
	}
	if bearer.Token == "" {
		t.Fatalf("expected non-empty token")
	}
	if got := atomic.LoadInt64(&full.callCount); got != 1 {
		t.Fatalf("expected 1 full auth call, got %d", got)
	}
	if got := atomic.LoadInt64(&ref.callCount); got != 0 {
		t.Fatalf("expected 0 refresh calls, got %d", got)
	}
}

func TestTokenProvider_ConcurrentSameNip_SingleFullAuth(t *testing.T) {
	full := &mockFullAuthenticator{delay: 20 * time.Millisecond}
	ref := &mockTokenRefresher{delay: 5 * time.Millisecond}
	p := newTestTokenProvider(ref, full)

	const goroutines = 50
	ctx := ctxWithNip("1234567890")

	var wg sync.WaitGroup
	wg.Add(goroutines)

	tokens := make([]string, goroutines)
	errs := make([]error, goroutines)

	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			b, err := p.Bearer(ctx, "Op")
			tokens[i] = b.Token
			errs[i] = err
		}(i)
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Bearer() error = %v", i, err)
		}
		if tokens[i] == "" {
			t.Fatalf("goroutine %d: empty token", i)
		}
	}

	first := tokens[0]
	for i, tok := range tokens {
		if tok != first {
			t.Fatalf("goroutine %d: token mismatch: %q != %q", i, tok, first)
		}
	}

	if got := atomic.LoadInt64(&full.callCount); got != 1 {
		t.Fatalf("expected 1 full auth call, got %d", got)
	}
}

// --- BENCHMARKI ---

func BenchmarkTokenProvider_Sequential(b *testing.B) {
	full := &mockFullAuthenticator{delay: 1 * time.Second}
	ref := &mockTokenRefresher{delay: 500 * time.Millisecond}
	p := newTestTokenProvider(ref, full)

	ctx := ctxWithNip("1234567890")

	if _, err := p.Bearer(ctx, "Op"); err != nil {
		b.Fatalf("initial Bearer() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Bearer(ctx, "Op"); err != nil {
			b.Fatalf("Bearer() error = %v", err)
		}
	}
}

func BenchmarkTokenProvider_ParallelSameNip(b *testing.B) {
	full := &mockFullAuthenticator{delay: 1 * time.Second}
	ref := &mockTokenRefresher{delay: 500 * time.Millisecond}
	p := newTestTokenProvider(ref, full)

	ctx := ctxWithNip("1234567890")

	if _, err := p.Bearer(ctx, "Op"); err != nil {
		b.Fatalf("initial Bearer() error = %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := p.Bearer(ctx, "Op"); err != nil {
				b.Fatalf("Bearer() error = %v", err)
			}
		}
	})
}

func BenchmarkTokenProvider_ParallelManyNips(b *testing.B) {
	full := &mockFullAuthenticator{delay: 5 * time.Millisecond}
	ref := &mockTokenRefresher{delay: 1 * time.Millisecond}
	p := newTestTokenProvider(ref, full)

	const nipCount = 100
	nips := make([]string, nipCount)
	for i := 0; i < nipCount; i++ {
		nips[i] = fmt.Sprintf("100000%04d", i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			nip := nips[i%nipCount]
			i++
			ctx := ctxWithNip(nip)
			if _, err := p.Bearer(ctx, "Op"); err != nil {
				b.Fatalf("Bearer() error = %v", err)
			}
		}
	})
}

func BenchmarkTokenProvider_ParallelManyNipsWarmCache(b *testing.B) {
	full := &mockFullAuthenticator{delay: 0}
	ref := &mockTokenRefresher{delay: 0}
	p := newTestTokenProvider(ref, full)

	const nipCount = 40 // tyle mniej więcej masz w realu; możesz zmienić na 100 jeśli chcesz
	nips := make([]string, nipCount)
	for i := 0; i < nipCount; i++ {
		nips[i] = fmt.Sprintf("100000%04d", i)
	}

	// najpierw wypełnij cache – każdy NIP dostaje swoje tokeny
	for _, nip := range nips {
		ctx := ctxWithNip(nip)
		if _, err := p.Bearer(ctx, "Op"); err != nil {
			b.Fatalf("initial Bearer() for %s error = %v", nip, err)
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			nip := nips[i%nipCount]
			i++
			ctx := ctxWithNip(nip)
			if _, err := p.Bearer(ctx, "Op"); err != nil {
				b.Fatalf("Bearer() error = %v", err)
			}
		}
	})
}
