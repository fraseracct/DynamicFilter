import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest

/*
 * input: ServletRequest request
 * input: ServletResponse response
 *
 * output: String username
 * output: Set<String> roles
 */

Logger log = LoggerFactory.getLogger("sso.groovy")

HttpServletRequest httpRequest = (HttpServletRequest) request
HttpServletResponse httpResponse = (HttpServletResponse) response

for (Cookie cookie : httpRequest.getCookies()) {
    if (cookie.getName() == "DynamicSSO") {
        text = new String(Base64.getUrlDecoder().decode(cookie.getValue()))
        json = new JsonSlurper().parseText(text)
        username = json.username
        roles = json.roles as Set

        return
    }
}

log.info("Setting DynamicSSO Cookie")

username = httpRequest.getHeader("KEYCLOAK_USERNAME")
if (username != null) {
    username = username.trim()
    if (username.empty) {
        username = null
    }
}

token = httpRequest.getHeader("KEYCLOAK_ACCESS_TOKEN")
parts = token.split("\\.")
text =  new String(Base64.getUrlDecoder().decode(parts[1]))
json = new JsonSlurper().parseText(text)
if(json.get("realm_access").get("roles").contains("uma_authorization")) {
    roles.add("User")
}

cookieValue = JsonOutput.toJson([username: username, roles: roles])
cookieValue = Base64.getUrlEncoder().encodeToString(cookieValue.getBytes());
httpResponse.addCookie(new Cookie("DynamicSSO", cookieValue))
