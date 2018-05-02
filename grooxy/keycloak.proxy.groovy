/*
 * input: ServletRequest request
 * input: ServletResponse response
 * input: FilterChain chain
 * 
 * output: Set<String> adiRoles
 * output: String username
 */

org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger("sso.groovy")

javax.servlet.http.HttpServletRequest httpRequest = (javax.servlet.http.HttpServletRequest) request
javax.servlet.ServletResponse httpResponse = (javax.servlet.ServletResponse) response

for (javax.servlet.http.Cookie c : httpRequest.getCookies()) {
  if (c.getName() == "DynamicSSO") {
     java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder()
     json = new String (decoder.decode(c.getValue()))
     jsonSlurper = new groovy.json.JsonSlurper()
     cookie = jsonSlurper.parseText(json)
     username = cookie.username
     adiRoles = cookie.roles as Set
  
    return
  }
}

log.info("Setting DynamicSSO Cookie")

username = httpRequest.getHeader("KEYCLOAK_USERNAME")

if (username != null) {
    username = username.trim()
    if (username.length()<1) username=null
}

token = httpRequest.getHeader("KEYCLOAK_ACCESS_TOKEN")

parts = token.split("\\.")
java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder()
json = new String (decoder.decode(parts[1]))

jsonSlurper = new groovy.json.JsonSlurper()
jsonSlurper.parseText(json).get("realm_access").get("roles").each { role ->
   if (role == "uma_authorization") adiRoles.add("User")  
}

cookieValue = groovy.json.JsonOutput.toJson([username: username, roles: adiRoles])
java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder()
httpResponse.addCookie(new javax.servlet.http.Cookie("DynamicSSO", new String(encoder.encode(cookieValue.getBytes()))));
