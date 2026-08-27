package kakha.kudava.filedrivespring.controller;

import jakarta.servlet.http.Cookie;
import kakha.kudava.filedrivespring.dto.LoginRequest;
import kakha.kudava.filedrivespring.dto.LoginResponse;
import kakha.kudava.filedrivespring.model.JwtRefresher;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.services.jwt.JwtRefreshService;
import kakha.kudava.filedrivespring.services.jwt.JwtService;
import kakha.kudava.filedrivespring.services.users.DbUserDetailsService;
import kakha.kudava.filedrivespring.services.users.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuthenticationPublicUuidContractTests {
    @Test
    void loginReturnsStablePublicUuid() throws Exception {
        AuthenticationManager authenticationManager=mock(AuthenticationManager.class);
        JwtService jwt=mock(JwtService.class); JwtRefreshService refresh=mock(JwtRefreshService.class);
        UserService users=mock(UserService.class); Authentication authentication=mock(Authentication.class);
        UserDetails details=org.springframework.security.core.userdetails.User.withUsername("alice").password("x").roles("USER").build();
        UUID publicUuid=UUID.fromString("8c98baef-9c78-45d3-8797-b27e9786fa26"); User user=user(7L,"alice",publicUuid);
        when(authenticationManager.authenticate(any())).thenReturn(authentication); when(authentication.getPrincipal()).thenReturn(details);
        when(users.getUserByEmail("alice")).thenReturn(Optional.of(user)); when(jwt.generateAccessToken(details)).thenReturn("access"); when(refresh.createToken(user,7)).thenReturn("refresh");
        LoginRequest request=new LoginRequest(); request.setUsername("alice"); request.setPassword("secret");
        LoginResponse body=new AuthRestController(7,authenticationManager,jwt,refresh,users).login(request,new MockHttpServletResponse()).getBody();
        assertNotNull(body); assertEquals("access",body.getAccessToken());assertEquals(7L,body.getUserId());assertEquals("alice",body.getUsername());assertEquals(publicUuid,body.getPublicUuid());
    }

    @Test
    void refreshReturnsSamePublicUuid() {
        JwtRefreshService refresh=mock(JwtRefreshService.class);JwtService jwt=mock(JwtService.class);DbUserDetailsService detailsService=mock(DbUserDetailsService.class);
        UUID publicUuid=UUID.fromString("8c98baef-9c78-45d3-8797-b27e9786fa26");User user=user(7L,"alice",publicUuid);JwtRefresher stored=new JwtRefresher();stored.setUser(user);
        UserDetails details=org.springframework.security.core.userdetails.User.withUsername("alice").password("x").roles("USER").build();
        when(refresh.validateToken("old-refresh")).thenReturn(stored);when(detailsService.loadUserByUsername("alice")).thenReturn(details);when(jwt.generateAccessToken(details)).thenReturn("new-access");when(refresh.createToken(user,7)).thenReturn("new-refresh");
        MockHttpServletRequest request=new MockHttpServletRequest();request.setCookies(new Cookie("refresh_token","old-refresh"));
        ResponseEntity<?> response=new RefreshRestController(refresh,jwt,7,detailsService).refresh(request,new MockHttpServletResponse());
        assertInstanceOf(LoginResponse.class,response.getBody());LoginResponse body=(LoginResponse)response.getBody();assertEquals(publicUuid,body.getPublicUuid());assertEquals("new-access",body.getAccessToken());
    }

    @Test
    void responseCannotBeConstructedWithoutPublicUuid() {
        assertThrows(NullPointerException.class,()->new LoginResponse("access",1L,"alice",null));
    }

    @Test
    void loginWithoutPublicUuidFailsBeforeIssuingTokens() {
        AuthenticationManager authenticationManager=mock(AuthenticationManager.class); JwtService jwt=mock(JwtService.class);
        JwtRefreshService refresh=mock(JwtRefreshService.class); UserService users=mock(UserService.class); Authentication authentication=mock(Authentication.class);
        UserDetails details=org.springframework.security.core.userdetails.User.withUsername("legacy").password("x").roles("USER").build();
        when(authenticationManager.authenticate(any())).thenReturn(authentication);when(authentication.getPrincipal()).thenReturn(details);
        when(users.getUserByEmail("legacy")).thenReturn(Optional.of(user(8L,"legacy",null)));
        LoginRequest request=new LoginRequest();request.setUsername("legacy");request.setPassword("secret");
        assertThrows(IllegalStateException.class,()->new AuthRestController(7,authenticationManager,jwt,refresh,users).login(request,new MockHttpServletResponse()));
        verifyNoInteractions(jwt);verify(refresh,never()).createToken(any(),anyInt());
    }

    private static User user(Long id,String username,UUID publicUuid){User user=new User();user.setId(id);user.setUsername(username);user.setPublicUuid(publicUuid);return user;}
}
