package ws.antonov.spring.security.http.signature;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by aantonov on 10/4/15.
 */
public interface HttpSignaturePrincipalExtractor {

    Object extractPrincipal(HttpServletRequest request);
}
