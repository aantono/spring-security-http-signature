package ws.antonov.spring.security.http.signature;

import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by aantonov on 10/4/15.
 */
public class HttpSignatureAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {
    private Challenge challenge = HttpSignatureAuthenticationFilter.DEFAULT_CHALLENGE;

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(challenge, "challenge must be specified");
    }

    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        response.addHeader(Constants.CHALLENGE, createAuthenticationChallenge(request).toString());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                authException.getMessage());
    }

    /**
     * @param request
     * @return @NotNull <code>Challenge</code>
     * @see Challenge
     */
    protected Challenge createAuthenticationChallenge(HttpServletRequest request) {
        return getChallenge();
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }
}
