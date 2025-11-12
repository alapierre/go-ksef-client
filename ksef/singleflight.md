Najlepszy „wzorzec” tu to deduplikacja wywołań per klucz (NIP) + cache z TTL. W Go najwygodniej robi się to przez 
`singleflight.Group` per NIP: pierwsza gorutyna naprawdę uwierzytelnia (Twoja pętla AuthWaitAndRedeem), 
a reszta czekających dla tego samego NIP-u dostaje ten sam wynik. Dodatkowo trzymasz w pamięci bearer + jego expiry 
i odświeżasz tuż przed wygaśnięciem.

- https://pkg.go.dev/golang.org/x/sync/singleflight

Zróbmy to nad fasadą, czyli w warstwie, która już implementuje api.SecuritySource.

W skrócie: TokenProvider będzie:
- per-NIP cache + singleflight (żeby jedna gorutyna na NIP robiła flow init→poll→redeem),
- wstrzykiwał bearer do żądania (przez api.SecuritySource),
- obsługiwał 401: unieważnia cache i jednorazowo odświeża token, po czym ponawia żądanie.

Token Provider powinien otrzymywać funkcję, która pobierze pierwszą parę tokenów, a w przypadku gdy wygaśnie refresh 
(lub przy odświeżeniu będzie status 401), ponownie przeprowadzi pełne uwierzytelnienie. NIP powinien być w kontekście.

Dla 429 najlepiej będzie dodać wariant odpowiedzi w OpenAPI ze wskazanym nagłówkiem