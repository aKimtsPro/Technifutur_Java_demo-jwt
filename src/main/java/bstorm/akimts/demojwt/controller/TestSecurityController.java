package bstorm.akimts.demojwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/security")
public class TestSecurityController {

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/authenticated")
    public String getConnected(){
        return "connecté";
    }

}
