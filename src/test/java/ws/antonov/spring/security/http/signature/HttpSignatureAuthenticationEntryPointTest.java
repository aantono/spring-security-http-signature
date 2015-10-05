package ws.antonov.spring.security.http.signature;

import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import javax.servlet.http.HttpServletResponse;
import java.util.Collections;

import static org.junit.Assert.*;

/**
 * Created by aantonov on 10/4/15.
 */
public class HttpSignatureAuthenticationEntryPointTest {
    HttpSignatureAuthenticationEntryPoint entryPoint;

    @Before
    public void setup() throws Exception {
        entryPoint = new HttpSignatureAuthenticationEntryPoint();
        entryPoint.afterPropertiesSet();
    }

    @After
    public void teardown() throws Exception {
        entryPoint = null;
    }

    @Test
    public void testCommence() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/test.html");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Challenge challenge = entryPoint.createAuthenticationChallenge(request);
        
        entryPoint.commence(request, response, new BadCredentialsException("Invalid Signature"));
        
        assertEquals(challenge.toString(), response.getHeader(Constants.CHALLENGE));
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    }

    @Test
    public void testCreateAuthenticationChallenge() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/test.html");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Challenge challenge = entryPoint.createAuthenticationChallenge(request);

        assertNotNull(challenge);
        assertEquals(1, challenge.getAlgorithms().size());
        assertTrue(challenge.getAlgorithms().contains(Algorithm.SSH_RSA));
        assertEquals(1, challenge.getHeaders().size());
        assertTrue(challenge.getHeaders().contains(Constants.HEADER_DATE));
    }
}