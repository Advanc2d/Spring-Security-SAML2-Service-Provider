# SAML with Spring Boot and Spring Security
> 인증 정보 제공자(Identity Provider)에게 인증이 필요한 서비스 제공자를 구성하기 위한 프로젝트입니다.
- Spring Boot 2.7.0
- JAVA 11
- Spring Security
- Spring Security SAML2 Service Provider



## **SAML 이란?**
- `Security Assertion Markup Language`
- 인증 정보 제공자(identity provider)와 서비스 제공자(service provider) 간의 인증 및 인가 데이터를 교환하기 위한 XML 기반의 개방형 표준 데이터 포맷. 
- 즉, 인증 프로세스

## 서비스 제공자(SP) 설정
1. Identity Provider의 메타데이터 설정
   - application.yml 
```yaml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          {registrationId}:         # 설정할 SP Alias Name
            entity-id: sp
            assertingparty:
              entity-id: <IDP Entity ID>
              # IDP Response Or Assertion Signing Public Cert(X.509) file path
              verification:
                credentials:
                  - certificate-location: classpath:/sso/local/saml.cert
              singlesignon:
                url: <IDP SSO ENDPOINT> ex) http(s)://idp.dev.com/idp/sso/redirect/
                binding: REDIRECT
                # whether saml request(authnrequest) is signed or not
                sign-request: false
```

2. Security Filter Chain 설정

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    public SecurityConfig(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        configureCsrfDisable(http);
        configureAuthorization(http);
        configureSaml2Login(http);
        addSaml2MetadataFilter(http);
    }

    private void configureCsrfDisable(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    private void configureAuthorization(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(
                        "/saml2/service-provider-metadata/**",
                        "/login/**", "/login",
                        "/logout",  "/logout/saml2/**",
                        "/"
                )
                .permitAll()
                .anyRequest().authenticated();
    }

    private void configureSaml2Login(HttpSecurity http) throws Exception {
        http.saml2Login()
                .failureHandler((request, response, exception) -> {
                    System.out.println("SAML authentication failed: " + exception.getMessage());
                    exception.printStackTrace();
                    response.sendRedirect("/error");
                });
    }

   private void addSaml2MetadataFilter(HttpSecurity http) {
      Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
              new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);

      Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(
              relyingPartyRegistrationResolver, new OpenSamlMetadataResolver()
      );

      http.addFilterBefore(metadataFilter, Saml2WebSsoAuthenticationFilter.class);
   }
}
```

## 트러블슈팅
- SLO [spring-security-saml2-service-provider - opensaml 버전 문제](https://github.com/spring-projects/spring-security/issues/10539)
```yaml
implementation 'org.opensaml:opensaml-saml-impl:4.1.1'
```