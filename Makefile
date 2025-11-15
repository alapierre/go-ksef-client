# Domyślny target – szybkie testy jednostkowe w całym repo (bez integracji zależnych od env)
test:
	go test ./...

# Testy tylko pakietu ksef (bez innych pakietów)
test-ksef:
	go test ./ksef -run . -v

# Testy TokenProvidera z detektorem race
test-tokenprovider-race:
	go test ./ksef -race -run TestTokenProvider -v

# Testy TokenProvidera bez race (szybciej)
test-tokenprovider:
	go test ./ksef -run TestTokenProvider -v

# Benchmarki TokenProvidera
bench-tokenprovider:
	go test ./ksef -bench 'BenchmarkTokenProvider_' -benchmem

# Integracyjne testy ksef wymagające KSEF_* (zakładamy, że env jest ustawione)
test-ksef-integration:
	go test ./ksef -run 'TestGetToken|TestClient_OpenInteractiveSession' -v