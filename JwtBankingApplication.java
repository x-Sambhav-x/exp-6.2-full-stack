package com.example.jwtbank;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.math.BigDecimal;
import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Single-file Spring Boot application:
 * - JWT auth (login returns token)
 * - Protected banking endpoints under /api/bank/**
 * - Transactional money transfers
 * - H2 in-memory DB bootstrap with sample users & accounts
 *
 * Save as src/main/java/com/example/jwtbank/JwtBankingApplication.java
 *
 * Required application.properties (example):
 *  spring.h2.console.enabled=true
 *  spring.datasource.url=jdbc:h2:mem:jwtbank;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
 *  spring.datasource.username=sa
 *  spring.datasource.password=
 *  spring.jpa.hibernate.ddl-auto=create
 *  jwt.secret=ReplaceWithAStrongSecretKeyForProduction
 *  jwt.expiration-ms=3600000
 *
 * Required dependencies: spring-boot-starter-web, spring-boot-starter-security,
 * spring-boot-starter-data-jpa, h2, jjwt-api/impl/jackson, spring-boot-starter-test (optional)
 */
@SpringBootApplication
@EnableMethodSecurity
public class JwtBankingApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtBankingApplication.class, args);
    }

    // ---------- ENTITIES ----------
    @Entity
    @Table(name = "users")
    static class AppUser {
        @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
        @Column(unique = true, nullable = false)
        private String username;
        @Column(nullable = false)
        private String passwordHash;
        // roles as comma-separated, e.g. "USER,ADMIN"
        private String roles;

        public AppUser() {}
        public AppUser(String username, String passwordHash, String roles) {
            this.username = username; this.passwordHash = passwordHash; this.roles = roles;
        }

        public Long getId() { return id; }
        public String getUsername() { return username; }
        public String getPasswordHash() { return passwordHash; }
        public String getRoles() { return roles; }
    }

    @Entity
    @Table(name = "accounts")
    static class Account {
        @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
        @Column(nullable = false, unique = true)
        private String accountNumber;
        @Column(nullable = false)
        private BigDecimal balance;
        @Column(nullable = false)
        private String owner; // username

        public Account() {}
        public Account(String accountNumber, BigDecimal balance, String owner) {
            this.accountNumber = accountNumber; this.balance = balance; this.owner = owner;
        }
        public Long getId() { return id; }
        public String getAccountNumber() { return accountNumber; }
        public BigDecimal getBalance() { return balance; }
        public String getOwner() { return owner; }
        public void setBalance(BigDecimal b) { this.balance = b; }
    }

    // ---------- REPOSITORIES ----------
    @Repository
    interface UserRepo extends org.springframework.data.jpa.repository.JpaRepository<AppUser, Long> {
        Optional<AppUser> findByUsername(String username);
    }

    @Repository
    interface AccountRepo extends org.springframework.data.jpa.repository.JpaRepository<Account, Long> {
        Optional<Account> findByAccountNumber(String accountNumber);
        List<Account> findByOwner(String owner);
    }

    // ---------- JWT UTIL ----------
    @Component
    static class JwtUtil {
        private final Key key;
        private final long expirationMs;

        @Autowired
        public JwtUtil(@Value("${jwt.secret}") String secret,
                       @Value("${jwt.expiration-ms}") long expirationMs) {
            // ensure proper key length (pad/truncate to 64 bytes for HMAC-SHA-512)
            byte[] keyBytes = Arrays.copyOf(secret.getBytes(), 64);
            this.key = Keys.hmacShaKeyFor(keyBytes);
            this.expirationMs = expirationMs;
        }

        public String generateToken(String username, List<String> roles) {
            Instant now = Instant.now();
            return Jwts.builder()
                    .setSubject(username)
                    .claim("roles", roles)
                    .setIssuedAt(Date.from(now))
                    .setExpiration(Date.from(now.plusMillis(expirationMs)))
                    .signWith(key, SignatureAlgorithm.HS512)
                    .compact();
        }

        public Jws<Claims> validateToken(String token) {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        }
    }

    // ---------- AUTH SERVICE ----------
    @Service
    static class AuthService {
        private final UserRepo userRepo;
        private final PasswordEncoder encoder;

        public AuthService(UserRepo userRepo, PasswordEncoder encoder) {
            this.userRepo = userRepo;
            this.encoder = encoder;
        }

        public AppUser register(String username, String rawPassword) {
            if (userRepo.findByUsername(username).isPresent()) {
                throw new RuntimeException("Username exists");
            }
            String hashed = encoder.encode(rawPassword);
            AppUser u = new AppUser(username, hashed, "USER");
            return userRepo.save(u);
        }

        public AppUser authenticate(String username, String rawPassword) {
            return userRepo.findByUsername(username)
                    .filter(u -> encoder.matches(rawPassword, u.getPasswordHash()))
                    .orElseThrow(() -> new BadCredentialsException("Invalid username/password"));
        }
    }

    // ---------- BANKING SERVICE ----------
    @Service
    static class BankingService {
        private final AccountRepo accountRepo;

        public BankingService(AccountRepo accountRepo) {
            this.accountRepo = accountRepo;
        }

        public List<Account> getAccountsForUser(String username) {
            return accountRepo.findByOwner(username);
        }

        public Optional<Account> getAccount(String accNo) {
            return accountRepo.findByAccountNumber(accNo);
        }

        @Transactional
        public void transfer(String fromAcc, String toAcc, BigDecimal amount, String requester) {
            if (amount.compareTo(BigDecimal.ZERO) <= 0) throw new IllegalArgumentException("Amount > 0 required");

            Account src = accountRepo.findByAccountNumber(fromAcc)
                    .orElseThrow(() -> new RuntimeException("Source account not found"));
            Account dst = accountRepo.findByAccountNumber(toAcc)
                    .orElseThrow(() -> new RuntimeException("Destination account not found"));

            if (!src.getOwner().equals(requester)) throw new AccessDeniedException("Not owner of source account");

            if (src.getBalance().compareTo(amount) < 0) throw new RuntimeException("Insufficient funds");

            src.setBalance(src.getBalance().subtract(amount));
            dst.setBalance(dst.getBalance().add(amount));

            accountRepo.save(src);
            accountRepo.save(dst);
        }
    }

    // ---------- SECURITY: JWT FILTER & CONFIG ----------
    static class JwtAuthFilter extends OncePerRequestFilter {
        private final JwtUtil jwtUtil;
        private final UserRepo userRepo;

        public JwtAuthFilter(JwtUtil jwtUtil, UserRepo userRepo) {
            this.jwtUtil = jwtUtil;
            this.userRepo = userRepo;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain) throws ServletException, IOException {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                String token = header.substring(7);
                try {
                    Jws<Claims> claimsJws = jwtUtil.validateToken(token);
                    Claims claims = claimsJws.getBody();
                    String username = claims.getSubject();
                    @SuppressWarnings("unchecked")
                    List<String> roles = claims.get("roles", List.class);
                    List<GrantedAuthority> authorities = roles == null ? List.of() :
                            roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

                    Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                } catch (JwtException ex) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Invalid/expired token\"}");
                    return;
                }
            }
            filterChain.doFilter(request, response);
        }
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtUtil jwtUtil, UserRepo userRepo) throws Exception {
        JwtAuthFilter jwtFilter = new JwtAuthFilter(jwtUtil, userRepo);

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        // Allow H2 console frames
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ---------- REST CONTROLLERS ----------
    record AuthRequest(String username, String password) {}
    record AuthResponse(String token) {}

    @RestController
    @RequestMapping("/api/auth")
    static class AuthController {
        private final AuthService authService;
        private final JwtUtil jwtUtil;
        private final UserRepo userRepo;

        public AuthController(AuthService authService, JwtUtil jwtUtil, UserRepo userRepo) {
            this.authService = authService; this.jwtUtil = jwtUtil; this.userRepo = userRepo;
        }

        @PostMapping("/register")
        public ResponseEntity<?> register(@RequestBody AuthRequest req) {
            try {
                AppUser u = authService.register(req.username(), req.password());
                return ResponseEntity.ok(Map.of("username", u.getUsername()));
            } catch (RuntimeException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", ex.getMessage()));
            }
        }

        @PostMapping("/login")
        public ResponseEntity<?> login(@RequestBody AuthRequest req) {
            try {
                AppUser user = authService.authenticate(req.username(), req.password());
                List<String> roles = Arrays.asList(user.getRoles().split(","));
                String token = jwtUtil.generateToken(user.getUsername(), roles);
                return ResponseEntity.ok(new AuthResponse(token));
            } catch (AuthenticationException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid credentials"));
            }
        }
    }

    record TransferRequest(String fromAccount, String toAccount, String amount) {}

    @RestController
    @RequestMapping("/api/bank")
    static class BankController {
        private final BankingService bankingService;
        private final AccountRepo accountRepo;

        public BankController(BankingService bankingService, AccountRepo accountRepo) {
            this.bankingService = bankingService; this.accountRepo = accountRepo;
        }

        private String currentUser() {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            return auth == null ? null : auth.getName();
        }

        @GetMapping("/accounts")
        public ResponseEntity<?> myAccounts() {
            String user = currentUser();
            if (user == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            List<Account> accounts = bankingService.getAccountsForUser(user);
            var resp = accounts.stream().map(a -> Map.of(
                    "accountNumber", a.getAccountNumber(),
                    "balance", a.getBalance()
            )).collect(Collectors.toList());
            return ResponseEntity.ok(resp);
        }

        @GetMapping("/accounts/{acc}")
        public ResponseEntity<?> getAccount(@PathVariable String acc) {
            String user = currentUser();
            Account a = accountRepo.findByAccountNumber(acc).orElse(null);
            if (a == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error","Account not found"));
            if (!a.getOwner().equals(user)) return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error","Not your account"));
            return ResponseEntity.ok(Map.of("accountNumber", a.getAccountNumber(), "balance", a.getBalance()));
        }

        @PostMapping("/transfer")
        public ResponseEntity<?> transfer(@RequestBody TransferRequest req) {
            String user = currentUser();
            try {
                BigDecimal amt = new BigDecimal(req.amount());
                bankingService.transfer(req.fromAccount(), req.toAccount(), amt, user);
                return ResponseEntity.ok(Map.of("status","ok"));
            } catch (IllegalArgumentException ex) {
                return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
            } catch (AccessDeniedException ex) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", ex.getMessage()));
            } catch (RuntimeException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", ex.getMessage()));
            }
        }
    }

    // ---------- BOOTSTRAP SAMPLE DATA ----------
    @Bean
    CommandLineRunner init(UserRepo userRepo, AccountRepo accountRepo, PasswordEncoder encoder) {
        return args -> {
            if (userRepo.findByUsername("alice").isEmpty()) {
                userRepo.save(new AppUser("alice", encoder.encode("alicepass"), "USER"));
            }
            if (userRepo.findByUsername("bob").isEmpty()) {
                userRepo.save(new AppUser("bob", encoder.encode("bobpass"), "USER"));
            }
            if (accountRepo.findByAccountNumber("A100").isEmpty()) {
                accountRepo.save(new Account("A100", new BigDecimal("1000.00"), "alice"));
            }
            if (accountRepo.findByAccountNumber("B200").isEmpty()) {
                accountRepo.save(new Account("B200", new BigDecimal("250.00"), "bob"));
            }
        };
    }
}
