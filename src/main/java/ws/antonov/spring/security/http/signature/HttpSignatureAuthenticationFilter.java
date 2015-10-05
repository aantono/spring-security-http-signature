package ws.antonov.spring.security.http.signature;

import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.DefaultVerifier;
import net.adamcin.httpsig.api.RequestContent;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.api.VerifyResult;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Enumeration;

/**
 * Created by aantonov on 10/4/15.
 */
public class HttpSignatureAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {
    public static Challenge DEFAULT_CHALLENGE = new Challenge("Spring Security Http Signature",
        Arrays.asList(Constants.HEADER_DATE), Arrays.asList(Algorithm.SSH_RSA));

    private HttpSignaturePrincipalExtractor principalExtractor;
    private Verifier verifier = new DefaultVerifier(new DefaultKeychain());
    private Enumeration<String> headerNames;
    private Challenge challenge = DEFAULT_CHALLENGE;

    public HttpSignatureAuthenticationFilter(HttpSignaturePrincipalExtractor principalExtractor) {
        this.principalExtractor = principalExtractor;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        verifyHttpRequestSignature(request);
        return principalExtractor.extractPrincipal(request);
    }

    private void verifyHttpRequestSignature(HttpServletRequest request) {
        Authorization authorization = Authorization.parse(request.getHeader(Constants.AUTHORIZATION));
        if (authorization != null) {
            RequestContent requestContent = createRequestContent(request);
            VerifyResult verifyResult = verifier.verifyWithResult(challenge, requestContent, authorization);
            if (VerifyResult.SUCCESS != verifyResult) {
                throw new InsufficientAuthenticationException("Verification Error: " + verifyResult.name());
            }

        } else {
            throw new PreAuthenticatedCredentialsNotFoundException("Unable to find " +
                    Constants.AUTHORIZATION + " header");
        }
    }

    protected RequestContent createRequestContent(HttpServletRequest request) {
        RequestContent.Builder requestContentBuilder = new RequestContent.Builder();
        requestContentBuilder.setRequestTarget(request.getMethod(), request.getRequestURI());
        headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            String value = request.getHeader(name);
            requestContentBuilder.addHeader(name, value);
        }
        return requestContentBuilder.build();
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return Authorization.parse(request.getHeader(Constants.AUTHORIZATION));
    }

    public Verifier getVerifier() {
        return verifier;
    }

    public void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }
}
