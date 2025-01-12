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
```yaml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          #{registrationId}:
            entity-id: sp
            signing:
              credentials:
                - private-key-location: classpath:local.key
                  certificate-location: classpath:local.crt
            singlelogout:
              binding: POST
              response-url: "{baseUrl}/logout/saml2/slo"
            assertingparty:
              metadata-uri: "classpath:metadata/metadata-idp.xml"
              singlesignon:
                url: <IDP SSO ENDPOINT> ex) http(s)://idp.dev.com/idp/sso/redirect/
                binding: REDIRECT
                # whether saml request(authnrequest) is signed or not
                sign-request: false
```


## 트러블슈팅
- SLO [spring-security-saml2-service-provider - opensaml 버전 문제](https://github.com/spring-projects/spring-security/issues/10539)
```yaml
implementation 'org.opensaml:opensaml-saml-impl:4.1.1'
```