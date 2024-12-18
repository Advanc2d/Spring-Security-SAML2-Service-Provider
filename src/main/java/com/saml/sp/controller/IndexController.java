package com.saml.sp.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;
import java.util.Map;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        String message = "Not Login Yet";

        if (principal != null) {
            Map<String, List<Object>> s = principal.getAttributes();
            String emailAddress = principal.getFirstAttribute("email_address");
            message = emailAddress;
            model.addAttribute("message", message);
        }

        return "index";
    }

    @GetMapping("/saml/login")
    public String samlLogin(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        String message = "Not Login Yet";

        if (principal != null) {
            Map<String, List<Object>> s = principal.getAttributes();
            String emailAddress = principal.getFirstAttribute("email_address");
            message = emailAddress;
            model.addAttribute("message", message);
        }

        return "index";
    }

    @GetMapping("/error")
    public String error(Model model) {
        String error = "Error Message";
        model.addAttribute("message", error);
        return "index";
    }
}
