package com.saml.sp.config;

import org.opensaml.saml.saml2.core.LogoutRequest;
import org.springframework.context.annotation.Bean;
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
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;

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
        configureSaml2Logout(http);
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

    private void configureSaml2Logout(HttpSecurity http) throws Exception {
        http.saml2Logout(saml2 ->
                saml2.logoutRequest(request ->
                                request.logoutRequestResolver(openSaml4LogoutRequestResolver())
                        )
                        .logoutResponse(response ->
                                response.logoutResponseResolver(openSaml4LogoutResponseResolver())
                        )
        );
    }

    @Bean
    public Saml2LogoutRequestResolver openSaml4LogoutRequestResolver() {
        return new OpenSaml4LogoutRequestResolver(new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository));
    }

    @Bean
    public OpenSaml4LogoutResponseResolver openSaml4LogoutResponseResolver() {
        return new OpenSaml4LogoutResponseResolver(new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository));
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
