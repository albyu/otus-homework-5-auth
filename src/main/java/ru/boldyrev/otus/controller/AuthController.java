package ru.boldyrev.otus.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.boldyrev.otus.exception.AlreadyExistsException;
import ru.boldyrev.otus.exception.NotFoundException;
import ru.boldyrev.otus.model.AppUser;
import ru.boldyrev.otus.model.VersionResponse;
import ru.boldyrev.otus.service.AppUserService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController {
    private Map<String, Map<String, String>> SESSIONS = new HashMap<>();

    @Autowired
    private final AppUserService appUserService;

    private String generateSessionId(int size) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            int index = (int) (chars.length() * Math.random());
            sb.append(chars.charAt(index));
        }
        return sb.toString();
    }

    @PostMapping(value = "/register", consumes = "application/json")
    public ResponseEntity<Map<String, String>> register(@RequestBody AppUser u) {
        try {
            AppUser appUser = appUserService.createUser(u);
            return ResponseEntity.ok(appUser.toMap());
        } catch (AlreadyExistsException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("errorReason", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        try {
            AppUser userInfo = appUserService.getUserByCredentials(username, password);
            String sessionId = createSession(userInfo.toMap());
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.SET_COOKIE, "session_id=" + sessionId + "; HttpOnly");
            return ResponseEntity.ok().headers(headers).body(Map.of("status", "ok"));
        } catch (NotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("errorReason", e.getMessage()));
        }
    }

    @RequestMapping(value = "/logout", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response, @CookieValue(value = "session_id", defaultValue = "") String sessionId) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, "session_id=; Max-Age=0");

        return ResponseEntity.ok().headers(headers).body(Map.of("status", "ok"));
    }


    private String createSession(Map<String, String> data) {
        String sessionId = generateSessionId(40);
        SESSIONS.put(sessionId, data);
        return sessionId;
    }


    @GetMapping("/auth")
    public ResponseEntity<Map<String, String>> auth(@CookieValue(name = "session_id", required = false) String session_id) {
        if (session_id != null && SESSIONS.containsKey(session_id)) {
            Map<String, String> data = SESSIONS.get(session_id);
            HttpHeaders headers = new HttpHeaders();
            headers.add("X-User-Name", data.get("username"));
            headers.add("X-Email", data.get("email"));
            headers.add("X-Phone", data.get("phone"));
            headers.add("X-First-Name", data.get("firstName"));
            headers.add("X-Last-Name", data.get("lastName"));
            return ResponseEntity.ok().headers(headers).body(data);

        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("errorReason", "Not authorized"));
        }
    }



    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "OK"));
    }

    @GetMapping("/version")
    public VersionResponse version() {
        return new VersionResponse("v.5.0.auth");
    }


}
