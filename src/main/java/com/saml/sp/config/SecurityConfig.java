package com.saml.sp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;

import javax.servlet.http.HttpServletRequest;

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
                        "/saml2/service-provider-metadata/**",      // metadata url
                        "/login/**", "/login",                      // login urzjal
                        "/logout", "/logout/saml2/**",              // logout url
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
